"""GET /api/artifacts/{artifact_id} — tenant-scoped get-by-id without a project.

fr's asset bindings store only the artifact id, so it cannot use the
per-project ``/projects/{p}/artifacts/{id}`` route. This route must resolve
visibility exactly like ``/api/artifacts`` (own tenant + PLATFORM inheritance of
SYSTEM's published rows) and answer 404 — never 403 — for anything not visible.

Reuses the real-Postgres client and the system-tenant patching of
``tests/test_system_inheritance.py`` (same engine, same headers).
"""

import uuid

from tests.test_system_inheritance import (  # noqa: F401 — fixtures are used by name
    CUSTOMER,
    PLATFORM,
    SYSTEM,
    TENANT_B,
    USER,
    USER_B,
    _h,
    _system_tenant_is_the_test_uuid,
    _upload,
    sys_client,
)


class TestCrossProjectGetById:
    def test_own_tenant_artifact_is_200(self, sys_client):  # noqa: F811
        art = _upload(sys_client, tenant=TENANT_B, subject=USER_B)
        r = sys_client.get(f"/api/artifacts/{art['id']}", headers=_h(TENANT_B))
        assert r.status_code == 200, r.text
        body = r.json()
        assert str(body["id"]) == art["id"]
        assert body["is_system"] is False

    def test_other_tenants_artifact_is_404(self, sys_client):  # noqa: F811
        art = _upload(sys_client, tenant=TENANT_B, subject=USER_B, publish_status="published")
        r = sys_client.get(f"/api/artifacts/{art['id']}", headers=_h(CUSTOMER))
        assert r.status_code == 404, r.text
        assert r.json()["detail"] == "Artifact not found"

    def test_same_tenant_user_private_artifact_is_404_for_other_user(self, sys_client):  # noqa: F811
        art = _upload(sys_client, tenant=TENANT_B, subject=USER_B, visibility="user")
        assert (
            sys_client.get(f"/api/artifacts/{art['id']}", headers=_h(TENANT_B, USER_B)).status_code
            == 200
        )
        r = sys_client.get(f"/api/artifacts/{art['id']}", headers=_h(TENANT_B, "someone-else"))
        assert r.status_code == 404

    def test_published_system_artifact_is_200_for_platform_tenant(self, sys_client):  # noqa: F811
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        r = sys_client.get(f"/api/artifacts/{pub['id']}", headers=_h(PLATFORM))
        assert r.status_code == 200, r.text
        assert str(r.json()["id"]) == pub["id"]
        assert r.json()["is_system"] is True

    def test_system_artifact_is_404_for_customer_and_draft_for_platform(self, sys_client):  # noqa: F811
        """Owner's ruling 2026-09-30: customers never inherit SYSTEM rows; drafts
        never leave the system tenant."""
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        draft = _upload(sys_client, tenant=SYSTEM, publish_status="draft")
        assert (
            sys_client.get(f"/api/artifacts/{pub['id']}", headers=_h(TENANT_B)).status_code == 404
        )
        assert (
            sys_client.get(f"/api/artifacts/{draft['id']}", headers=_h(PLATFORM)).status_code == 404
        )
        # Owner still reads its own draft.
        assert (
            sys_client.get(f"/api/artifacts/{draft['id']}", headers=_h(SYSTEM, USER)).status_code
            == 200
        )

    def test_random_uuid_is_404(self, sys_client):  # noqa: F811
        r = sys_client.get(f"/api/artifacts/{uuid.uuid4()}", headers=_h(TENANT_B))
        assert r.status_code == 404
        assert r.json()["detail"] == "Artifact not found"

    def test_non_uuid_is_422(self, sys_client):  # noqa: F811
        r = sys_client.get("/api/artifacts/not-a-uuid", headers=_h(TENANT_B))
        assert r.status_code == 422

    def test_by_card_route_is_not_shadowed(self, sys_client):  # noqa: F811
        card = str(uuid.uuid4())
        art = _upload(sys_client, tenant=TENANT_B, subject=USER_B, card_id=card)
        r = sys_client.get(f"/api/artifacts/by-card/{card}", headers=_h(TENANT_B))
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body, list)
        assert [str(row["id"]) for row in body] == [art["id"]]
        assert r.headers["X-Total-Count"] == "1"
