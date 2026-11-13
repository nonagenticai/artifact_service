"""RM model exports (ArchiMate exchange .archimate.xml, UML .xmi) as application/xml.

Real Postgres and the REAL upload/download/render routes, with the real
``SecurityHeadersMiddleware`` mounted, so the headers asserted are the ones a
browser gets. Only storage_service (a separate service) is the in-memory
``FakeStorage``. The allowed-mimes list is the shipped default, not a patch.

Serving safety: tenant XML can carry XHTML + script (the SVG class), so it must
never be served as something a browser renders in place — download is
``attachment`` + ``nosniff`` + a script-denying CSP, and render refuses it.
"""

import pytest

from tests.test_document_render import FakeStorage, _h, _upload
from tests.test_visibility import PROJECT_ID, _make_client

ARCHIMATE = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<model xmlns="http://www.opengroup.org/xsd/archimate/3.0/" identifier="id-1">'
    b'<name xml:lang="en">RM export</name>'
    b'<html:script xmlns:html="http://www.w3.org/1999/xhtml">alert(1)</html:script>'
    b"</model>\n"
)
XMI = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<xmi:XMI xmlns:xmi="http://www.omg.org/spec/XMI/20131001" '
    b'xmlns:uml="http://www.omg.org/spec/UML/20131001">'
    b'<uml:Model xmi:id="m1" name="RM"/></xmi:XMI>\n'
)


@pytest.fixture(scope="class")
def xml_client():
    from middleware.security_headers import SecurityHeadersMiddleware
    from routes.artifacts import cross_project_router, get_storage_service

    client, _mock = _make_client()
    client.app.include_router(cross_project_router)
    client.app.add_middleware(SecurityHeadersMiddleware)
    storage = FakeStorage()
    client.app.dependency_overrides[get_storage_service] = lambda: storage
    with client:
        yield client


class TestXmlModelExports:
    @pytest.mark.parametrize(
        ("filename", "body"),
        [("rm-model.archimate.xml", ARCHIMATE), ("rm-model.xmi", XMI)],
    )
    def test_upload_then_download_is_byte_exact_and_never_inline(self, xml_client, filename, body):
        up = _upload(xml_client, body, filename=filename, content_type="application/xml")
        assert up["size"] == len(body)

        r = xml_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{up['artifact_id']}/download", headers=_h()
        )
        assert r.status_code == 200, r.text
        assert r.content == body
        assert r.headers["content-type"].startswith("application/xml")
        assert r.headers["content-disposition"] == f'attachment; filename="{filename}"'
        assert r.headers["x-content-type-options"] == "nosniff"
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]

    def test_render_refuses_xml(self, xml_client):
        up = _upload(
            xml_client, ARCHIMATE, filename="m.archimate.xml", content_type="application/xml"
        )
        r = xml_client.get(f"/api/artifacts/{up['artifact_id']}/render", headers=_h())
        assert r.status_code == 415
