"""DOC-1: document metadata, markdown uploads and the render route — real Postgres.

Same engine + FakeTenantMiddleware shape as ``tests/test_visibility.py`` (headers
``X-Test-Tenant`` / ``X-Subject-Id``), with a dict-backed fake storage so the
render cache is observable: a render writes a derived object, and the second
render must be served from it without rendering again.
"""

import io
import json
import secrets
import uuid
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from tests.conftest import TEST_TENANT_A, TEST_TENANT_B
from tests.test_visibility import PROJECT_ID, _make_client

TENANT = TEST_TENANT_A
OTHER = TEST_TENANT_B
USER = "user-doc-author"

DOCUMENT = {
    "title": "Gap analysis",
    "sections": [
        {
            "heading": "Findings",
            "body_md": "Four problems **confirmed**.\n\n<script>alert('x')</script>\n\n"
            "| id | severity |\n|----|----------|\n| 1 | high |",
            "sources": ["https://example.com/evidence", {"title": "RM", "url": "https://rm/x"}],
        },
        {"heading": "Next steps", "body_md": "- fix\n- verify"},
    ],
}
REPORT = {"findings": [{"id": 1, "severity": "high"}], "passed": False, "notes": None}


class FakeStorage:
    """In-memory stand-in for storage_service. download of a missing key is a 404."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.downloads: list[str] = []

    def generate_storage_key(self, **kw: Any) -> str:
        return f"test/storage/{secrets.token_hex(8)}/v1/{kw.get('filename', 'file')}"

    def upload_file(self, storage_key: str, file_data: Any, size: int, content_type: str) -> None:
        self.objects[storage_key] = file_data.read()

    def download_file(self, storage_key: str) -> bytes:
        self.downloads.append(storage_key)
        if storage_key not in self.objects:
            req = httpx.Request("GET", f"http://storage/{storage_key}")
            raise httpx.HTTPStatusError(
                "not found", request=req, response=httpx.Response(404, request=req)
            )
        return self.objects[storage_key]

    def delete_file(self, storage_key: str) -> None:
        self.objects.pop(storage_key, None)


@pytest.fixture(scope="class")
def doc_client():
    from routes.artifacts import cross_project_router, get_storage_service

    client, _mock = _make_client()
    client.app.include_router(cross_project_router)
    storage = FakeStorage()
    client.app.dependency_overrides[get_storage_service] = lambda: storage
    client.storage = storage  # type: ignore[attr-defined]
    with client:
        yield client


def _h(tenant: str = TENANT, subject: str = USER) -> dict[str, str]:
    return {"X-Test-Tenant": tenant, "X-Subject-Id": subject}


def _upload(
    client,
    content: bytes,
    *,
    filename: str,
    content_type: str,
    tenant: str = TENANT,
    expect: int = 200,
    **fields: str,
) -> dict[str, Any]:
    data = {
        "filename": filename,
        "content_type": content_type,
        "kind": "doc",
        "sensitivity": "internal",
        **fields,
    }
    # The REAL allowed-mimes list (not a patched one) — so text/markdown being
    # accepted here proves the shipped default, not a test override.
    from core.config import get_settings

    with patch("routes.artifacts.settings") as mock_settings:
        mock_settings.allowed_mimes = get_settings().allowed_mimes
        mock_settings.max_file_size_bytes = 10 * 1024 * 1024
        mock_settings.enable_virus_scanning = False
        resp = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data=data,
            files={"file": (filename, io.BytesIO(content), content_type)},
            headers=_h(tenant),
        )
    assert resp.status_code == expect, resp.text
    return resp.json()


def _doc(client, **fields: str) -> dict[str, Any]:
    return _upload(
        client,
        json.dumps(DOCUMENT).encode(),
        filename="document.json",
        content_type="application/json",
        **fields,
    )


class TestMetadata:
    def test_upload_persists_and_echoes_the_four_fields(self, doc_client):
        up = _doc(
            doc_client,
            title="Gap analysis",
            doc_type="analysis_report",
            phase="analysis",
            summary="4 problems confirmed",
        )
        for k, v in {
            "title": "Gap analysis",
            "doc_type": "analysis_report",
            "phase": "analysis",
            "summary": "4 problems confirmed",
        }.items():
            assert up[k] == v
        got = doc_client.get(f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}", headers=_h())
        assert got.status_code == 200
        body = got.json()
        assert (body["title"], body["doc_type"], body["phase"], body["summary"]) == (
            "Gap analysis",
            "analysis_report",
            "analysis",
            "4 problems confirmed",
        )
        cross = doc_client.get(f"/api/artifacts/{up['artifact_id']}", headers=_h()).json()
        assert cross["phase"] == "analysis"

    def test_metadata_is_null_when_not_supplied(self, doc_client):
        up = _upload(doc_client, b"x", filename="a.txt", content_type="text/plain")
        assert (up["title"], up["doc_type"], up["phase"], up["summary"]) == (None,) * 4

    def test_over_long_doc_type_is_422_not_500(self, doc_client):
        body = _doc(doc_client, doc_type="x" * 101, expect=422)
        assert [e["loc"][-1] for e in body["detail"]] == ["doc_type"]

    def test_markdown_upload_is_accepted(self, doc_client):
        up = _upload(doc_client, b"# Hi", filename="document.md", content_type="text/markdown")
        assert up["artifact_id"]

    def test_card_id_filled_from_planka_card_tag(self, doc_client):
        card = str(uuid.uuid4())
        up = _doc(doc_client, tags=f"run:7,planka_card:{card}")
        assert up["card_id"] == card
        listed = doc_client.get(f"/api/artifacts/by-card/{card}", headers=_h()).json()
        assert [r["id"] for r in listed] == [up["artifact_id"]]

    def test_explicit_card_id_wins_over_tag(self, doc_client):
        explicit, tagged = str(uuid.uuid4()), str(uuid.uuid4())
        up = _doc(doc_client, card_id=explicit, tags=f"planka_card:{tagged}")
        assert up["card_id"] == explicit

    def test_non_uuid_planka_tag_leaves_card_id_null(self, doc_client):
        # Planka's own ids are 19-digit snowflakes; card_id is a uuid column.
        up = _doc(doc_client, tags="planka_card:1885787636753237021")
        assert up["card_id"] is None

    def test_patch_metadata_is_partial_and_null_clears(self, doc_client):
        up = _doc(doc_client, title="Old", phase="analysis", summary="s")
        url = f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/metadata"
        card = str(uuid.uuid4())
        r = doc_client.patch(
            url, json={"title": "New", "summary": None, "card_id": card}, headers=_h()
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["title"] == "New"
        assert body["summary"] is None
        assert body["phase"] == "analysis"  # untouched: not in the body
        assert body["card_id"] == card

    def test_patch_unknown_field_is_422(self, doc_client):
        up = _doc(doc_client)
        r = doc_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/metadata",
            json={"status": "approved"},
            headers=_h(),
        )
        assert r.status_code == 422

    def test_patch_cross_tenant_is_404(self, doc_client):
        up = _doc(doc_client, title="Mine")
        r = doc_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/metadata",
            json={"title": "Stolen"},
            headers=_h(OTHER),
        )
        assert r.status_code == 404
        got = doc_client.get(f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}", headers=_h())
        assert got.json()["title"] == "Mine"

    def test_list_filters_by_phase_and_doc_type(self, doc_client):
        phase = f"ph-{secrets.token_hex(4)}"
        a = _doc(doc_client, phase=phase, doc_type="analysis_report")
        b = _doc(doc_client, phase=phase, doc_type="adr")
        _doc(doc_client, phase="other", doc_type="adr")
        for base in (f"/projects/{PROJECT_ID}/artifacts", "/api/artifacts"):
            ids = {r["id"] for r in doc_client.get(f"{base}?phase={phase}", headers=_h()).json()}
            assert ids == {a["artifact_id"], b["artifact_id"]}
            ids = {
                r["id"]
                for r in doc_client.get(f"{base}?phase={phase}&doc_type=adr", headers=_h()).json()
            }
            assert ids == {b["artifact_id"]}


class TestRender:
    def test_document_json_html(self, doc_client):
        up = _doc(doc_client, doc_type="Analysis report", phase="analysis", summary="Four.")
        r = doc_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/render", headers=_h()
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/html")
        page = r.text
        assert "<h1>Gap analysis</h1>" in page
        assert '<nav class="toc">' in page and 'href="#findings"' in page
        assert '<h2 id="findings">Findings</h2>' in page
        assert "<strong>confirmed</strong>" in page
        assert "<script>" not in page and "&lt;script&gt;" in page
        assert 'id="fn-1"' in page and "https://example.com/evidence" in page
        assert "Phase: analysis" in page and "Four." in page

    def test_markdown_html(self, doc_client):
        up = _upload(
            doc_client,
            b"# Title\n\n## Part one\n\ntext <img src=x onerror=alert(1)>\n\n## Part two\n",
            filename="document.md",
            content_type="text/markdown",
        )
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert r.status_code == 200, r.text
        assert 'href="#part-one"' in r.text and 'href="#part-two"' in r.text
        # Raw HTML in markdown is TEXT, never markup.
        assert "<img" not in r.text and "&lt;img src=x onerror=alert(1)&gt;" in r.text

    def test_report_json_renders_as_definition_list(self, doc_client):
        up = _upload(
            doc_client,
            json.dumps(REPORT).encode(),
            filename="report.json",
            content_type="application/json",
        )
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert r.status_code == 200, r.text
        assert "<th>Severity</th>" in r.text and "<td>high</td>" in r.text
        assert '<h2 id="passed">Passed</h2>no' in r.text

    def test_invalid_json_still_renders(self, doc_client):
        up = _upload(
            doc_client, b"{not json", filename="report.json", content_type="application/json"
        )
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert r.status_code == 200
        assert "<pre>{not json</pre>" in r.text

    @pytest.mark.needs_pdf_backend
    def test_pdf_render(self, doc_client):
        up = _doc(doc_client)
        r = doc_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/render?format=pdf",
            headers=_h(),
        )
        assert r.status_code == 200, r.text
        assert r.headers["content-type"] == "application/pdf"
        assert r.content.startswith(b"%PDF-")
        assert r.headers["content-disposition"] == 'attachment; filename="document.pdf"'

    @pytest.mark.needs_pdf_backend
    def test_second_render_is_served_from_cache(self, doc_client):
        import routes.artifacts as routes_mod

        up = _doc(doc_client)
        url = f"/api/artifacts/{up['artifact_id']}/render?format=pdf"
        with patch.object(routes_mod, "_render_bytes", wraps=routes_mod._render_bytes) as spy:
            first = doc_client.get(url, headers=_h())
            second = doc_client.get(url, headers=_h())
        assert first.status_code == second.status_code == 200
        assert first.headers["x-render-cache"] == "miss"
        assert second.headers["x-render-cache"] == "hit"
        assert spy.call_count == 1
        assert first.content == second.content
        derived = [k for k in doc_client.storage.objects if k.startswith("derived/")]
        assert any(k.startswith(f"derived/{up['artifact_id']}/v1/render-pdf-") for k in derived)

    def test_metadata_change_misses_the_cache(self, doc_client):
        up = _doc(doc_client, title="Before")
        url = f"/api/artifacts/{up['artifact_id']}/render"
        assert "Before" in doc_client.get(url, headers=_h()).text
        doc_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/metadata",
            json={"title": "After"},
            headers=_h(),
        )
        r = doc_client.get(url, headers=_h())
        assert r.headers["x-render-cache"] == "miss"
        assert "<h1>After</h1>" in r.text

    def test_cross_tenant_render_is_404_on_both_routes(self, doc_client):
        up = _doc(doc_client)
        for url in (
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/render",
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/render?format=pdf",
            f"/api/artifacts/{up['artifact_id']}/render",
            f"/api/artifacts/{up['artifact_id']}/render?format=pdf",
        ):
            r = doc_client.get(url, headers=_h(OTHER))
            assert r.status_code == 404, (url, r.status_code)
            assert r.json()["detail"] == "Artifact not found"

    def test_user_private_render_is_404_for_other_user(self, doc_client):
        from core.config import get_settings

        with patch("routes.artifacts.settings") as mock_settings:
            mock_settings.allowed_mimes = get_settings().allowed_mimes
            mock_settings.max_file_size_bytes = 10 * 1024 * 1024
            mock_settings.enable_virus_scanning = False
            resp = doc_client.post(
                f"/projects/{PROJECT_ID}/artifacts/upload",
                data={
                    "filename": "document.md",
                    "content_type": "text/markdown",
                    "kind": "doc",
                    "sensitivity": "internal",
                },
                files={"file": ("document.md", io.BytesIO(b"# private"), "text/markdown")},
                headers={**_h(), "X-Visibility": "user"},
            )
        art = resp.json()["artifact_id"]
        assert doc_client.get(f"/api/artifacts/{art}/render", headers=_h()).status_code == 200
        r = doc_client.get(f"/api/artifacts/{art}/render", headers=_h(subject="someone-else"))
        assert r.status_code == 404

    def test_random_id_is_404(self, doc_client):
        r = doc_client.get(f"/api/artifacts/{uuid.uuid4()}/render", headers=_h())
        assert r.status_code == 404

    def test_image_is_415(self, doc_client):
        up = _upload(doc_client, b"\x89PNG....", filename="x.png", content_type="image/png")
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert r.status_code == 415

    def test_bad_format_is_422(self, doc_client):
        up = _doc(doc_client)
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render?format=docx", headers=_h())
        assert r.status_code == 422


class TestDeleteRemovesRenders:
    @pytest.mark.needs_pdf_backend
    def test_delete_removes_the_current_derived_render(self, doc_client):
        up = _doc(doc_client)
        art = up["artifact_id"]
        for fmt in ("html", "pdf"):
            assert (
                doc_client.get(
                    f"/api/artifacts/{art}/render?format={fmt}", headers=_h()
                ).status_code
                == 200
            )
        derived = [k for k in doc_client.storage.objects if k.startswith(f"derived/{art}/")]
        assert len(derived) == 2
        r = doc_client.delete(f"/projects/{PROJECT_ID}/artifacts/{art}", headers=_h())
        assert r.status_code == 204
        assert [k for k in doc_client.storage.objects if k.startswith(f"derived/{art}/")] == []


class TestPlankaCardId:
    SNOWFLAKE = "1885787636753237021"

    def test_filled_from_tag_with_any_format(self, doc_client):
        up = _doc(doc_client, tags=f"run:7,planka_card:{self.SNOWFLAKE}")
        assert up["planka_card_id"] == self.SNOWFLAKE
        assert up["card_id"] is None  # the uuid column is untouched by a snowflake
        got = doc_client.get(f"/api/artifacts/{up['artifact_id']}", headers=_h()).json()
        assert got["planka_card_id"] == self.SNOWFLAKE

    def test_explicit_value_wins_over_tag(self, doc_client):
        up = _doc(doc_client, planka_card_id="explicit-1", tags=f"planka_card:{self.SNOWFLAKE}")
        assert up["planka_card_id"] == "explicit-1"

    def test_no_tag_leaves_it_null(self, doc_client):
        assert _doc(doc_client, tags="run:7")["planka_card_id"] is None

    def test_over_long_value_is_422(self, doc_client):
        body = _doc(doc_client, planka_card_id="x" * 65, expect=422)
        assert [e["loc"][-1] for e in body["detail"]] == ["planka_card_id"]

    def test_patch_sets_and_clears(self, doc_client):
        up = _doc(doc_client)
        url = f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/metadata"
        r = doc_client.patch(url, json={"planka_card_id": "123"}, headers=_h())
        assert r.status_code == 200 and r.json()["planka_card_id"] == "123"
        r = doc_client.patch(url, json={"planka_card_id": None}, headers=_h())
        assert r.json()["planka_card_id"] is None
        r = doc_client.patch(url, json={"planka_card_id": "y" * 65}, headers=_h())
        assert r.status_code == 422

    def test_list_filter_on_both_routes_and_tenant_scoped(self, doc_client):
        card = secrets.token_hex(8)
        mine = _doc(doc_client, tags=f"planka_card:{card}")
        _doc(doc_client, tags=f"planka_card:{card}-other")
        _upload(
            doc_client,
            json.dumps(DOCUMENT).encode(),
            filename="document.json",
            content_type="application/json",
            tenant=OTHER,
            tags=f"planka_card:{card}",
        )
        for base in (f"/projects/{PROJECT_ID}/artifacts", "/api/artifacts"):
            rows = doc_client.get(f"{base}?planka_card_id={card}", headers=_h()).json()
            assert [r["id"] for r in rows] == [mine["artifact_id"]]


def _big_markdown(sections: int) -> bytes:
    """A markdown document whose HTML render takes real CPU time (~0.3-3s)."""
    return "".join(
        f"## Section {i}\n\nSome **bold** text and a [link](https://e.x/{i}).\n\n- a\n- b\n\n"
        for i in range(sections)
    ).encode()


RENDER_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)


class TestRenderSecurityHeaders:
    """Real requests through the app against real Postgres."""

    def _assert_headers(self, r: httpx.Response) -> None:
        assert r.status_code == 200, r.text
        assert r.headers["content-security-policy"] == RENDER_CSP
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "SAMEORIGIN"

    def test_html_render_on_both_routes_miss_and_hit(self, doc_client):
        up = _doc(doc_client)
        for url in (
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/render",
            f"/api/artifacts/{up['artifact_id']}/render",
        ):
            self._assert_headers(doc_client.get(url, headers=_h()))
        last = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert last.headers["x-render-cache"] == "hit"
        self._assert_headers(last)

    def test_the_policy_admits_what_the_page_uses(self, doc_client):
        """The page needs exactly one inline <style> and nothing external."""
        up = _doc(doc_client)
        page = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h()).text
        assert "<style>" in page
        for forbidden in ("<script", "<link", "<img", "<iframe", "src=", "@import", "url("):
            assert forbidden not in page, forbidden

    @pytest.mark.needs_pdf_backend
    def test_pdf_render(self, doc_client):
        up = _doc(doc_client)
        r = doc_client.get(f"/api/artifacts/{up['artifact_id']}/render?format=pdf", headers=_h())
        self._assert_headers(r)
        assert r.content.startswith(b"%PDF-")


class TestRenderConcurrency:
    """The render slots are bounded and the event loop keeps serving meanwhile."""

    def test_saturation_is_503_with_retry_after_and_slots_are_released(self, doc_client):
        from concurrent.futures import ThreadPoolExecutor

        from core.config import get_settings
        from routes.artifacts import RENDER_RETRY_AFTER_SECONDS

        limit = get_settings().render_max_concurrency
        n = limit * 3
        content = _big_markdown(8000)
        ids = [
            _upload(doc_client, content, filename=f"big{i}.md", content_type="text/markdown")[
                "artifact_id"
            ]
            for i in range(n)
        ]
        with ThreadPoolExecutor(max_workers=n) as pool:
            responses = list(
                pool.map(lambda a: doc_client.get(f"/api/artifacts/{a}/render", headers=_h()), ids)
            )
        codes = [r.status_code for r in responses]
        assert set(codes) <= {200, 503}, codes
        assert codes.count(200) >= 1, codes
        busy = [r for r in responses if r.status_code == 503]
        assert busy, f"{n} concurrent renders with {limit} slots never saturated: {codes}"
        for r in busy:
            assert r.headers["retry-after"] == str(RENDER_RETRY_AFTER_SECONDS)
        # Every slot came back: each rejected document now renders.
        for a, r in zip(ids, responses, strict=True):
            if r.status_code == 503:
                again = doc_client.get(f"/api/artifacts/{a}/render", headers=_h())
                assert again.status_code == 200, again.text

    def test_a_render_does_not_block_other_requests(self, doc_client):
        import time
        from concurrent.futures import ThreadPoolExecutor

        up = _upload(
            doc_client, _big_markdown(20000), filename="huge.md", content_type="text/markdown"
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            started = time.monotonic()
            render = pool.submit(
                doc_client.get, f"/api/artifacts/{up['artifact_id']}/render", headers=_h()
            )
            time.sleep(0.2)
            health = doc_client.get("/health/live")
            answered_while_rendering = not render.done()
            render_resp = render.result()
        assert health.status_code == 200
        assert render_resp.status_code == 200
        assert answered_while_rendering, (
            f"render finished in {time.monotonic() - started:.2f}s before the health probe "
            "answered — the document is too small to prove anything"
        )
