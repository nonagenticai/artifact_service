"""Render a stored artifact as a readable document (HTML, or PDF from that HTML).

DOC-1 (~/.claude/plans/program/20-designs/FR-PROJECT-HOME-REDESIGN-2026-10-26.md §7).

Three source shapes are understood:

* ``document.json`` — ``{"title", "sections": [{"heading", "body_md", "sources"}]}``
  as the conveyor's document card types write it;
* markdown (``text/markdown`` / ``*.md``) and plain text;
* any other JSON (the conveyor's ``report.json``: structured findings, no prose),
  rendered as a definition list / table of its top-level keys.

⛔ SANITISATION is two layers, and both are load-bearing:

1. markdown-it runs with ``html=False``, so raw HTML in the markdown is emitted
   as escaped TEXT, never as markup;
2. every markdown fragment then goes through ``nh3`` with an explicit allowlist
   (no ``script``/``style``/``iframe``/``img``, no ``style``/``on*`` attributes,
   link schemes http/https/mailto only).

Everything this module builds around those fragments (titles, headings, JSON
keys and values, footnotes) is ``html.escape``-d at the point it is written.

⛔ The PDF path must NEVER fetch a URL. WeasyPrint will otherwise dereference
``<img src>``, stylesheet links and ``url()`` in CSS — an SSRF from a document
body into the cluster network. ``_NoFetch`` refuses every fetch, and ``img`` is
not in the allowlist in the first place.

The report renderer must NEVER fail: any JSON value renders as something, and
an unexpected exception falls back to a ``<pre>`` dump of the source.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import nh3
from markdown_it import MarkdownIt

logger = logging.getLogger(__name__)

#: Part of every cache key. Bump it whenever the bytes this module produces for
#: the same input change (template, CSS, sanitiser policy, library pins), or
#: cached renders from the previous version keep being served.
RENDER_VERSION = "r1"

FORMATS = ("html", "pdf")

_MARKDOWN_TYPES = {"text/markdown", "text/x-markdown"}
_JSON_TYPES = {"application/json"}
_TEXT_TYPES = {"text/plain"}

_ALLOWED_TAGS = {
    "a",
    "abbr",
    "b",
    "blockquote",
    "br",
    "code",
    "del",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}
_ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "h1": {"id"},
    "h2": {"id"},
    "h3": {"id"},
    "h4": {"id"},
    "h5": {"id"},
    "h6": {"id"},
    "td": {"align"},
    "th": {"align"},
    "ol": {"start"},
}
_URL_SCHEMES = {"http", "https", "mailto"}

#: Report rendering bounds — a pathological report must still render quickly.
_MAX_DEPTH = 4
_MAX_ITEMS = 200
_MAX_TABLE_COLUMNS = 12

_CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "Liberation Sans", "DejaVu Sans", Arial, sans-serif; font-size: 11pt;
  line-height: 1.5; color: #1f2328; max-width: 52rem; margin: 0 auto; padding: 1rem; }
h1 { font-size: 1.8em; margin: 0 0 .3em; }
h2 { font-size: 1.35em; margin: 1.4em 0 .4em; border-bottom: 1px solid #d0d7de; }
h3 { font-size: 1.12em; margin: 1.2em 0 .3em; }
.doc-meta { color: #57606a; font-size: .9em; margin: 0 0 1em; }
.doc-summary { font-size: 1.05em; margin: 0 0 1.4em; }
nav.toc { border: 1px solid #d0d7de; border-radius: 6px; padding: .6em 1em; margin: 0 0 1.6em; }
nav.toc ol { margin: .2em 0; padding-left: 1.4em; }
pre { background: #f6f8fa; padding: .7em; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; font-size: .9em; }
code { font-family: "Liberation Mono", "DejaVu Sans Mono", monospace; }
table { border-collapse: collapse; margin: .6em 0; width: 100%; }
th, td { border: 1px solid #d0d7de; padding: .3em .5em; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
dl { margin: .4em 0; }
dt { font-weight: bold; margin-top: .6em; }
dd { margin: .1em 0 0 1.2em; }
.src-refs { font-size: .85em; color: #57606a; }
section.footnotes { border-top: 1px solid #d0d7de; margin-top: 2em; font-size: .9em; }
blockquote { border-left: 3px solid #d0d7de; margin: .6em 0; padding: 0 .9em; color: #57606a; }
"""


class NotRenderableError(ValueError):
    """The artifact's content type has no document rendering (e.g. an image)."""


@dataclass
class DocumentMeta:
    """Row metadata shown in the document header. Any field may be absent.

    Review ``status`` is deliberately NOT rendered: it changes on every review,
    and the reader shows it live in its own banner. Putting it in the bytes would
    invalidate the render cache on each decision for no reader benefit.
    """

    title: str | None = None
    doc_type: str | None = None
    phase: str | None = None
    summary: str | None = None
    version: int | None = None
    filename: str = ""

    def fingerprint_parts(self) -> list[str]:
        """Every value that reaches the rendered bytes, for the cache key."""
        return [
            str(v)
            for v in (
                self.title,
                self.doc_type,
                self.phase,
                self.summary,
                self.version,
                self.filename,
            )
        ]


@dataclass
class _Toc:
    entries: list[tuple[int, str, str]] = field(default_factory=list)
    _used: set[str] = field(default_factory=set)

    def add(self, level: int, text: str) -> str:
        base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "section"
        slug, n = base, 2
        while slug in self._used:
            slug, n = f"{base}-{n}", n + 1
        self._used.add(slug)
        self.entries.append((level, text, slug))
        return slug


def _md() -> MarkdownIt:
    # html=False: raw HTML in the source becomes escaped text. linkify off (no
    # extra dependency). Tables + strikethrough on — reports use both.
    return MarkdownIt("commonmark", {"html": False}).enable(["table", "strikethrough"])


def _sanitise(fragment: str) -> str:
    return nh3.clean(
        fragment,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        url_schemes=_URL_SCHEMES,
        link_rel="noopener noreferrer nofollow",
    )


def markdown_to_html(text: str, toc: _Toc | None = None, *, heading_offset: int = 0) -> str:
    """Markdown → sanitised HTML. Headings get ids and, if given, TOC entries.

    ``heading_offset`` demotes headings (a section body under an ``h2`` uses 1,
    so its ``#`` becomes ``h3``), capped at ``h6``.
    """
    md = _md()
    tokens = md.parse(text or "")
    for i, tok in enumerate(tokens):
        if tok.type in ("heading_open", "heading_close"):
            level = min(int(tok.tag[1]) + heading_offset, 6)
            tok.tag = f"h{level}"
            if tok.type == "heading_open" and toc is not None:
                inline = tokens[i + 1] if i + 1 < len(tokens) else None
                label = inline.content if inline is not None else ""
                if level <= 3:
                    tok.attrSet("id", toc.add(level, label))
    rendered = md.renderer.render(tokens, md.options, {})
    return _sanitise(rendered)


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _safe_href(url: str) -> str | None:
    if re.match(r"^(https?://|mailto:)", url.strip(), re.IGNORECASE):
        return url.strip()
    return None


# ---------------------------------------------------------------------------
# Source shapes
# ---------------------------------------------------------------------------


def is_document_json(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("sections"), list)


def _source_label(src: Any) -> tuple[str, str | None]:
    """(visible label, href or None) for one entry of a section's ``sources``."""
    if isinstance(src, str):
        return src, _safe_href(src)
    if isinstance(src, dict):
        url = next((src[k] for k in ("url", "href", "link") if isinstance(src.get(k), str)), None)
        label = next(
            (src[k] for k in ("title", "label", "name", "text") if isinstance(src.get(k), str)),
            None,
        )
        href = _safe_href(url) if url else None
        if label and url:
            return f"{label} — {url}", href
        if label or url:
            return str(label or url), href
    return json.dumps(src, ensure_ascii=False, default=str), None


def _render_document_json(data: dict[str, Any], toc: _Toc) -> tuple[str | None, str]:
    title = data.get("title") if isinstance(data.get("title"), str) else None
    parts: list[str] = []
    footnotes: list[tuple[str, str | None]] = []
    for idx, section in enumerate(data.get("sections") or [], start=1):
        if not isinstance(section, dict):
            parts.append(f"<section>{_render_value(section, 0)}</section>")
            continue
        heading = section.get("heading")
        heading_text = heading if isinstance(heading, str) and heading.strip() else f"Section {idx}"
        slug = toc.add(2, heading_text)
        body = section.get("body_md")
        body_html = markdown_to_html(body if isinstance(body, str) else "", None, heading_offset=2)
        refs = ""
        sources = section.get("sources")
        if isinstance(sources, list) and sources:
            links = []
            for src in sources:
                footnotes.append(_source_label(src))
                n = len(footnotes)
                links.append(f'<a href="#fn-{n}" id="fnref-{n}">[{n}]</a>')
            refs = f'<p class="src-refs">Sources: {" ".join(links)}</p>'
        parts.append(
            f'<section><h2 id="{slug}">{_esc(heading_text)}</h2>{body_html}{refs}</section>'
        )
    if footnotes:
        items = []
        for n, (label, href) in enumerate(footnotes, start=1):
            text = (
                f'<a href="{_esc(href)}" rel="noopener noreferrer nofollow">{_esc(label)}</a>'
                if href
                else _esc(label)
            )
            items.append(f'<li id="fn-{n}">{text} <a href="#fnref-{n}">&#8617;</a></li>')
        parts.append(
            '<section class="footnotes"><h2>Sources</h2><ol>' + "".join(items) + "</ol></section>"
        )
    return title, "".join(parts)


def _humanise_key(key: Any) -> str:
    text = str(key).replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else str(key)


def _scalar(value: Any) -> str:
    if value is None:
        return "<em>none</em>"
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    if "\n" in text:
        return f"<pre>{_esc(text)}</pre>"
    href = _safe_href(text)
    if href and len(text) < 2000:
        return f'<a href="{_esc(href)}" rel="noopener noreferrer nofollow">{_esc(text)}</a>'
    return _esc(text)


def _render_table(rows: list[dict[str, Any]], depth: int) -> str:
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    columns = columns[:_MAX_TABLE_COLUMNS]
    head = "".join(f"<th>{_esc(_humanise_key(c))}</th>" for c in columns)
    body = "".join(
        "<tr>"
        + "".join(f"<td>{_render_value(r.get(c), depth + 1)}</td>" for c in columns)
        + "</tr>"
        for r in rows[:_MAX_ITEMS]
    )
    more = _more(len(rows))
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}"


def _more(n: int) -> str:
    return f"<p><em>… {n - _MAX_ITEMS} more not shown</em></p>" if n > _MAX_ITEMS else ""


def _render_value(value: Any, depth: int) -> str:
    if depth >= _MAX_DEPTH and isinstance(value, dict | list):
        return f"<pre>{_esc(json.dumps(value, indent=2, ensure_ascii=False, default=str))}</pre>"
    if isinstance(value, dict):
        if not value:
            return "<em>empty</em>"
        items = list(value.items())
        body = "".join(
            f"<dt>{_esc(_humanise_key(k))}</dt><dd>{_render_value(v, depth + 1)}</dd>"
            for k, v in items[:_MAX_ITEMS]
        )
        return f"<dl>{body}</dl>{_more(len(items))}"
    if isinstance(value, list):
        if not value:
            return "<em>none</em>"
        if all(isinstance(v, dict) for v in value):
            return _render_table(value, depth)
        body = "".join(f"<li>{_render_value(v, depth + 1)}</li>" for v in value[:_MAX_ITEMS])
        return f"<ul>{body}</ul>{_more(len(value))}"
    return _scalar(value)


def _render_report(data: Any, toc: _Toc) -> tuple[str | None, str]:
    """A JSON report with no prose: one section per top-level key."""
    if not isinstance(data, dict):
        return None, _render_value(data, 0)
    title = data.get("title") if isinstance(data.get("title"), str) else None
    parts = []
    for key, value in list(data.items())[:_MAX_ITEMS]:
        if key == "title" and value == title:
            continue
        label = _humanise_key(key)
        slug = toc.add(2, label)
        parts.append(
            f'<section><h2 id="{slug}">{_esc(label)}</h2>{_render_value(value, 1)}</section>'
        )
    return title, "".join(parts) + _more(len(data))


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def classify(content_type: str, filename: str) -> str:
    """'markdown' | 'json' | 'text'; NotRenderableError for anything else."""
    ct = (content_type or "").split(";")[0].strip().lower()
    name = (filename or "").lower()
    if ct in _MARKDOWN_TYPES or name.endswith((".md", ".markdown")):
        return "markdown"
    if ct in _JSON_TYPES or name.endswith(".json"):
        return "json"
    if ct in _TEXT_TYPES or name.endswith(".txt"):
        return "text"
    raise NotRenderableError(f"content type '{content_type}' cannot be rendered as a document")


def render_html(content: bytes, *, content_type: str, meta: DocumentMeta) -> str:
    """Render ``content`` to a complete, self-contained, sanitised HTML page."""
    kind = classify(content_type, meta.filename)
    text = content.decode("utf-8", errors="replace")
    toc = _Toc()
    body_title: str | None = None
    try:
        if kind == "markdown":
            body = markdown_to_html(text, toc)
        elif kind == "text":
            body = f"<pre>{_esc(text)}</pre>"
        else:
            try:
                data = json.loads(text)
            except ValueError:
                body = f"<pre>{_esc(text)}</pre>"
            else:
                if is_document_json(data):
                    body_title, body = _render_document_json(data, toc)
                else:
                    body_title, body = _render_report(data, toc)
    except Exception:  # noqa: BLE001 - a render must never fail on content
        logger.exception("document render fell back to a plain dump (%s)", meta.filename)
        toc = _Toc()
        body = f"<pre>{_esc(text)}</pre>"

    title = meta.title or body_title or meta.filename or "Document"
    meta_bits = [
        b
        for b in (
            meta.doc_type,
            f"Phase: {meta.phase}" if meta.phase else None,
            f"Version {meta.version}" if meta.version is not None else None,
        )
        if b
    ]
    header = f"<h1>{_esc(title)}</h1>"
    if meta_bits:
        header += f'<p class="doc-meta">{" · ".join(_esc(b) for b in meta_bits)}</p>'
    if meta.summary:
        header += f'<p class="doc-summary">{_esc(meta.summary)}</p>'
    toc_html = ""
    if len(toc.entries) > 1:
        items = "".join(
            f'<li class="toc-l{level}"><a href="#{slug}">{_esc(label)}</a></li>'
            for level, label, slug in toc.entries
        )
        toc_html = f'<nav class="toc"><strong>Contents</strong><ol>{items}</ol></nav>'
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head>"
        f"<body><article>{header}{toc_html}{body}</article></body></html>"
    )


def html_to_pdf(page: str) -> bytes:
    """PDF bytes from ``render_html`` output. Never fetches any URL.

    Same approach as w2v analysis_service ``domains/critique/services/pdf_generator.py``
    (``weasyprint.HTML(string=...).write_pdf()``), plus a fetcher that refuses
    everything. Imported lazily: weasyprint dlopens pango at import, and only the
    PDF path needs it.
    """
    from weasyprint import HTML  # noqa: PLC0415
    from weasyprint.urls import URLFetcher  # noqa: PLC0415

    class _NoFetch(URLFetcher):
        def fetch(self, url: str, headers: Any = None) -> Any:  # noqa: ARG002
            raise ValueError(f"external resource fetching is disabled: {url[:80]}")

    pdf = HTML(string=page, base_url=None, url_fetcher=_NoFetch()).write_pdf()
    if not pdf:  # pragma: no cover - write_pdf() without a target always returns bytes
        raise RuntimeError("weasyprint returned no PDF bytes")
    return bytes(pdf)
