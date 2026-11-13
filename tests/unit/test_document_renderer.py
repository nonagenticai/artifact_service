"""Unit tests for services.document_renderer (no database, no storage)."""

import json
import urllib.request

import pytest

from services import document_renderer as dr

META = dr.DocumentMeta(filename="document.json")


def _page(payload, content_type="application/json", meta=META) -> str:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return dr.render_html(raw, content_type=content_type, meta=meta)


class TestSanitisation:
    @pytest.mark.parametrize(
        "body",
        [
            "<script>alert(1)</script>",
            '<a href="javascript:alert(1)">x</a>',
            "[x](javascript:alert(1))",
            '<iframe src="https://evil"></iframe>',
            '<p style="background:url(http://10.0.0.1/)">x</p>',
            "![x](http://10.0.0.1/track.png)",
            '<img src=x onerror="alert(1)">',
        ],
    )
    def test_markdown_never_emits_active_markup(self, body):
        page = _page(body.encode(), "text/markdown", dr.DocumentMeta(filename="d.md"))
        lowered = page.lower()
        for bad in ("<script", "<iframe", "<img", '<a href="javascript', "<p style"):
            assert bad not in lowered, (bad, page)

    def test_second_layer_strips_markup_even_if_markdown_let_it_through(self):
        """nh3 alone, on raw markup: the defence if html=False were ever flipped."""
        out = dr._sanitise(
            '<script>x</script><img src="http://a/b"><p style="color:red" onclick="y">t</p>'
            '<a href="javascript:z">l</a><h2 id="ok">h</h2>'
        )
        assert "<script" not in out and "<img" not in out
        assert "style=" not in out and "onclick" not in out and "javascript" not in out
        assert '<h2 id="ok">h</h2>' in out

    def test_title_and_headings_are_escaped(self):
        doc = {"title": "<b>t</b>", "sections": [{"heading": "<script>h</script>", "body_md": ""}]}
        page = _page(doc)
        assert "<script>h" not in page
        assert "&lt;script&gt;h&lt;/script&gt;" in page
        assert "<h1>&lt;b&gt;t&lt;/b&gt;</h1>" in page

    def test_only_http_sources_become_links(self):
        doc = {"sections": [{"heading": "S", "body_md": "", "sources": ["javascript:alert(1)"]}]}
        page = _page(doc)
        assert 'href="javascript' not in page
        assert "javascript:alert(1)" in page  # shown as text


class TestShapes:
    def test_document_json_toc_and_footnotes(self):
        doc = {
            "title": "T",
            "sections": [
                {
                    "heading": "A",
                    "body_md": "# inner",
                    "sources": [{"title": "S", "url": "https://s"}],
                },
                {"heading": "A", "body_md": "x"},
            ],
        }
        page = _page(doc)
        assert 'href="#a"' in page and 'href="#a-2"' in page  # de-duplicated slugs
        assert "<h3>inner</h3>" in page  # body headings demoted under the section h2
        assert '<li id="fn-1"><a href="https://s"' in page

    def test_row_title_overrides_document_title(self):
        page = _page(
            {"title": "Doc", "sections": []}, meta=dr.DocumentMeta(title="Row", filename="d")
        )
        assert "<h1>Row</h1>" in page

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            [],
            [1, "a", None],
            [{"a": 1}, {"b": [1, {"c": {"d": {"e": {"f": 1}}}}]}],
            {"k": {"nested": [[[[[1]]]]]}},
            {"big": list(range(1000))},
            {"multi": "line1\nline2", "flag": True, "none": None, "n": 1.5},
            "just a string",
            12,
        ],
    )
    def test_report_never_fails(self, payload):
        page = _page(payload, meta=dr.DocumentMeta(filename="report.json"))
        assert page.startswith("<!DOCTYPE html>") and page.endswith("</html>")

    def test_report_table_and_definition_list(self):
        page = _page({"items": [{"id": 1, "sev": "high"}], "ok": False})
        assert "<th>Sev</th>" in page and "<td>high</td>" in page
        assert '<h2 id="ok">Ok</h2>no' in page

    def test_large_list_is_truncated_visibly(self):
        page = _page({"big": list(range(250))})
        assert "50 more not shown" in page

    def test_plain_text_is_preformatted(self):
        page = dr.render_html(
            b"a <b>", content_type="text/plain", meta=dr.DocumentMeta(filename="a.txt")
        )
        assert "<pre>a &lt;b&gt;</pre>" in page

    @pytest.mark.parametrize(
        ("ct", "name", "kind"),
        [
            ("text/markdown", "x", "markdown"),
            ("application/octet-stream", "doc.md", "markdown"),
            ("application/json; charset=utf-8", "x", "json"),
            ("text/plain", "x", "text"),
        ],
    )
    def test_classify(self, ct, name, kind):
        assert dr.classify(ct, name) == kind

    @pytest.mark.parametrize("ct", ["image/png", "application/pdf", "application/zip"])
    def test_classify_refuses_binaries(self, ct):
        with pytest.raises(dr.NotRenderableError):
            dr.classify(ct, "file.bin")


@pytest.mark.needs_pdf_backend
class TestPdf:
    def test_pdf_bytes(self):
        pdf = dr.html_to_pdf(_page({"title": "T", "sections": [{"heading": "H", "body_md": "b"}]}))
        assert pdf.startswith(b"%PDF-")

    def test_pdf_never_fetches_a_url(self, monkeypatch):
        """Even hand-written HTML with remote resources must not reach the network.

        The patched ``open`` RECORDS rather than raises, because WeasyPrint
        swallows fetcher exceptions: an assertion raised in there would be
        silently eaten and the test would pass with the fetch having happened.
        """
        opened: list[object] = []

        def _record(self, req, *a, **kw):
            opened.append(req)
            raise OSError("blocked by test")

        monkeypatch.setattr(urllib.request.OpenerDirector, "open", _record)
        page = (
            "<html><head><link rel=stylesheet href='http://127.0.0.1:9/x.css'>"
            "<style>body{background:url(http://127.0.0.1:9/bg.png)}</style></head>"
            "<body><img src='file:///etc/passwd'><img src='http://169.254.169.254/'>x</body></html>"
        )
        assert dr.html_to_pdf(page).startswith(b"%PDF-")
        assert opened == []

    def test_default_allowed_mimes_include_markdown(self):
        from core.config import get_settings

        mimes = get_settings().allowed_mimes
        assert "text/markdown" in mimes and "text/x-markdown" in mimes
