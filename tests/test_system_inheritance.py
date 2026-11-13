"""System-tenant read inheritance for artifacts.

Owner design: the SYSTEM+IMPROVEMENT tenant holds shared assets. Every other
tenant READS its own rows plus the system tenant's PUBLISHED, tenant-visible
rows (``is_system: true`` on the wire); writes are always own-tenant; system
DRAFTS never leave the system tenant.

Real Postgres (same engine/fixture shape as ``tests/test_visibility.py``); the
system tenant is a TEST uuid patched onto ``routes.artifacts.settings`` so no
test ever reads or writes under the production system tenant's id.

Headers:
    X-Test-Tenant: controls tenant_id in FakeTenantMiddleware
    X-Subject-Id:  controls subject_id
"""

import io
import secrets
import uuid
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from tests.conftest import TEST_TENANT_A, TEST_TENANT_B
from tests.test_visibility import PROJECT_ID, _make_client

#: Stand-in for the SYSTEM+IMPROVEMENT tenant. A test uuid, never the prod one.
SYSTEM = "0198c2d4-7a10-7a00-9c00-5157e1a00001"
TENANT_B = TEST_TENANT_B
USER = "user-sys-author"
USER_B = "user-bob"

#: A PLATFORM tenant (owner's ruling 2026-09-30: only platform tenants inherit
#: SYSTEM's published rows). A test uuid, never one of the real 6 platform ids
#: and never TENANT_B — TENANT_B is deliberately kept a CUSTOMER throughout
#: this file so every other test here keeps exercising the customer (deny)
#: path. Made platform-only for the duration of each test by the autouse
#: fixture below.
PLATFORM = "0198c2d4-7a10-7a00-9c00-5157e1a00005"

#: A REAL customer tenant id (not a platform tenant, never the system tenant):
#: used by the keep-out tests so they exercise a production-shaped customer.
CUSTOMER = "0195f48b-d000-7000-8000-000000000100"

#: How a Uuid column renders the literal in compiled SQL (hyphens stripped).
SYSTEM_HEX = SYSTEM.replace("-", "")

assert SYSTEM not in (TEST_TENANT_A, TEST_TENANT_B)
assert PLATFORM not in (SYSTEM, TEST_TENANT_A, TEST_TENANT_B)
assert CUSTOMER not in (SYSTEM, PLATFORM, TEST_TENANT_A, TEST_TENANT_B)


class _FakeFallbackTagMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request.state.tenant_from_fallback = request.headers.get("X-Test-Fallback") == "1"
        return await call_next(request)


@pytest.fixture(scope="class")
def sys_client():
    from routes.artifacts import cross_project_router

    client, _mock = _make_client()
    # _make_client mounts only the project router; the cross-project READ
    # paths (/api/artifacts, /by-card) are flipped too, so mount them.
    client.app.include_router(cross_project_router)
    # Stand-in for AuthMiddleware's source tag: X-Test-Fallback: 1 marks the
    # tenant as resolved via the absent-header fallback. Added last, so it is
    # the OUTER middleware and runs before FakeTenantMiddleware sets the tenant.
    client.app.add_middleware(_FakeFallbackTagMiddleware)
    with client:
        yield client


@pytest.fixture(autouse=True)
def _system_tenant_is_the_test_uuid():
    """Point the routes' system tenant at SYSTEM for the duration of each test.

    Also makes PLATFORM a platform tenant (owner's ruling 2026-09-30) so tests
    that prove inheritance still works have a reader who legitimately gets it.
    TENANT_B is deliberately NOT added here — every test in this file that
    reads as TENANT_B must keep exercising the customer (deny) path.
    """
    import routes.artifacts as routes_mod
    from core.config import get_settings

    # visibility.may_inherit_system() reads get_settings() at call time. Another
    # module (the tenant_id-uuid migration test) calls get_settings.cache_clear(),
    # after which get_settings() is no longer routes_mod.settings — patch both.
    live = get_settings()
    platform = [*routes_mod.settings.artifacts_platform_tenant_ids, PLATFORM]
    with (
        patch.object(routes_mod.settings, "system_tenant_id", SYSTEM),
        patch.object(routes_mod.settings, "artifacts_platform_tenant_ids", platform),
        patch.object(live, "artifacts_platform_tenant_ids", platform),
    ):
        yield


def _upload(
    client,
    *,
    tenant: str,
    subject: str = USER,
    publish_status: str | None = None,
    visibility: str = "tenant",
    card_id: str | None = None,
    fallback: bool = False,
    expect: int = 200,
) -> dict[str, Any]:
    filename = f"sys-{secrets.token_hex(6)}.txt"
    data = {
        "filename": filename,
        "content_type": "text/plain",
        "kind": "doc",
        "sensitivity": "internal",
        "tags": "",
    }
    if publish_status is not None:
        data["publish_status"] = publish_status
    if card_id is not None:
        data["card_id"] = card_id
    with patch("routes.artifacts.settings") as mock_settings:
        mock_settings.allowed_mimes = ["text/plain"]
        mock_settings.max_file_size_bytes = 10 * 1024 * 1024
        mock_settings.enable_virus_scanning = False
        resp = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data=data,
            files={"file": (filename, io.BytesIO(b"hello system"), "text/plain")},
            headers={
                "X-Test-Tenant": tenant,
                "X-Subject-Id": subject,
                "X-Visibility": visibility,
                **({"X-Test-Fallback": "1"} if fallback else {}),
            },
        )
    assert resp.status_code == expect, f"upload: {resp.status_code} {resp.text}"
    if expect != 200:
        return {"status": resp.status_code, "detail": resp.json().get("detail")}
    body = resp.json()
    return {"id": str(body["artifact_id"]), "publish_status": body["publish_status"]}


def _h(tenant: str, subject: str = USER_B) -> dict[str, str]:
    return {"X-Test-Tenant": tenant, "X-Subject-Id": subject}


def _by_id(rows: list[dict]) -> dict[str, dict]:
    return {str(r["id"]): r for r in rows}


class TestSystemInheritance:
    def test_upload_defaults_to_draft(self, sys_client):
        art = _upload(sys_client, tenant=SYSTEM)
        assert art["publish_status"] == "draft"
        r = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{art['id']}", headers=_h(SYSTEM))
        assert r.status_code == 200
        assert r.json()["publish_status"] == "draft"

    def test_platform_tenant_sees_own_plus_published_system(self, sys_client):
        """Owner's ruling 2026-09-30: only a PLATFORM tenant inherits SYSTEM's
        published rows — this used to be exercised with TENANT_B (a customer),
        which no longer inherits (see test_customer_cannot_read_system_published)."""
        card = str(uuid.uuid4())
        own = _upload(sys_client, tenant=PLATFORM, subject=USER_B, card_id=card)
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published", card_id=card)

        # Every flipped READ path: project list, get, download, manifest,
        # cross-project list, by-card list.
        listed = _by_id(
            sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(PLATFORM)).json()
        )
        assert own["id"] in listed and pub["id"] in listed
        assert listed[pub["id"]]["is_system"] is True
        assert listed[pub["id"]]["publish_status"] == "published"
        assert listed[own["id"]]["is_system"] is False

        got = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{pub['id']}", headers=_h(PLATFORM))
        assert got.status_code == 200 and got.json()["is_system"] is True

        dl = sys_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{pub['id']}/download", headers=_h(PLATFORM)
        )
        assert dl.status_code == 200

        manifest = sys_client.get(
            f"/projects/{PROJECT_ID}/artifacts/manifests/project", headers=_h(PLATFORM)
        ).json()
        assert pub["id"] in _by_id(manifest["artifacts"])

        cross = _by_id(sys_client.get("/api/artifacts", headers=_h(PLATFORM)).json())
        assert cross[pub["id"]]["is_system"] is True

        by_card = _by_id(
            sys_client.get(f"/api/artifacts/by-card/{card}", headers=_h(PLATFORM)).json()
        )
        assert set(by_card) == {own["id"], pub["id"]}

    def test_tenant_b_does_not_see_draft_system(self, sys_client):
        draft = _upload(sys_client, tenant=SYSTEM, publish_status="draft")

        listed = _by_id(
            sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(TENANT_B)).json()
        )
        assert draft["id"] not in listed
        cross = _by_id(sys_client.get("/api/artifacts", headers=_h(TENANT_B)).json())
        assert draft["id"] not in cross
        for suffix in ("", "/download"):
            r = sys_client.get(
                f"/projects/{PROJECT_ID}/artifacts/{draft['id']}{suffix}", headers=_h(TENANT_B)
            )
            assert r.status_code == 404, (
                f"system DRAFT leaked via GET{suffix or ' '}: {r.status_code}"
            )

    def test_tenant_b_does_not_see_user_private_published_system(self, sys_client):
        priv = _upload(sys_client, tenant=SYSTEM, publish_status="published", visibility="user")
        r = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{priv['id']}", headers=_h(TENANT_B))
        assert r.status_code == 404

    def test_tenant_b_cannot_mutate_system_artifact(self, sys_client):
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        base = f"/projects/{PROJECT_ID}/artifacts/{pub['id']}"

        assert sys_client.delete(base, headers=_h(TENANT_B)).status_code == 404
        assert (
            sys_client.patch(
                f"{base}/publish-status", json={"publish_status": "draft"}, headers=_h(TENANT_B)
            ).status_code
            == 404
        )
        assert (
            sys_client.post(
                f"{base}/review", json={"decision": "approve"}, headers=_h(TENANT_B)
            ).status_code
            == 404
        )

        # Untouched, as seen by its owner.
        after = sys_client.get(base, headers=_h(SYSTEM, USER))
        assert after.status_code == 200
        assert after.json()["publish_status"] == "published"
        assert after.json()["status"] == "pending"

    def test_system_caller_sees_only_its_own_rows_unflagged(self, sys_client):
        """Owner's ruling 2026-10-02 (G-B cancelled): the system tenant reads its
        OWN rows (draft and published, ``is_system`` False) and NEVER another
        tenant's, even with include_system=True on every read path."""
        draft = _upload(sys_client, tenant=SYSTEM, publish_status="draft")
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        other = _upload(sys_client, tenant=TENANT_B, subject=USER_B)
        other_pub = _upload(sys_client, tenant=TENANT_B, subject=USER_B, publish_status="published")

        listed = _by_id(
            sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(SYSTEM, USER)).json()
        )
        assert draft["id"] in listed and pub["id"] in listed
        assert other["id"] not in listed and other_pub["id"] not in listed
        assert listed[draft["id"]]["is_system"] is False
        assert listed[pub["id"]]["is_system"] is False

    def test_owner_can_unpublish_and_it_disappears_for_others(self, sys_client):
        """'Others' here means a PLATFORM reader — the only kind that can ever
        see the row in the first place (owner's ruling 2026-09-30)."""
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        url = f"/projects/{PROJECT_ID}/artifacts/{pub['id']}"
        assert sys_client.get(url, headers=_h(PLATFORM)).status_code == 200

        r = sys_client.patch(
            f"{url}/publish-status", json={"publish_status": "draft"}, headers=_h(SYSTEM, USER)
        )
        assert r.status_code == 200 and r.json()["publish_status"] == "draft"
        assert sys_client.get(url, headers=_h(PLATFORM)).status_code == 404

        r = sys_client.patch(
            f"{url}/publish-status", json={"publish_status": "published"}, headers=_h(SYSTEM, USER)
        )
        assert r.status_code == 200
        assert sys_client.get(url, headers=_h(PLATFORM)).status_code == 200

    def test_system_never_reads_another_tenants_artifact(self, sys_client):
        """KEEP-OUT (owner's ruling 2026-10-02): a customer row, draft or
        published, is a 404 for the system tenant on every read path, and the
        cross-project listings contain only system-tenant rows."""
        draft = _upload(sys_client, tenant=CUSTOMER, subject=USER_B)
        pub = _upload(sys_client, tenant=CUSTOMER, subject=USER_B, publish_status="published")
        card = str(uuid.uuid4())
        carded = _upload(sys_client, tenant=CUSTOMER, subject=USER_B, card_id=card)
        mine = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        for art in (draft, pub, carded):
            for suffix in ("", "/download"):
                r = sys_client.get(
                    f"/projects/{PROJECT_ID}/artifacts/{art['id']}{suffix}",
                    headers=_h(SYSTEM, USER),
                )
                assert r.status_code == 404, f"system read customer row via GET{suffix}"
        for url in (f"/projects/{PROJECT_ID}/artifacts", "/api/artifacts"):
            rows = sys_client.get(url, headers=_h(SYSTEM, USER)).json()
            ids = set(_by_id(rows))
            assert mine["id"] in ids
            assert not ids & {draft["id"], pub["id"], carded["id"]}, f"leak via {url}"
            assert all(str(r["tenant_id"]) == SYSTEM for r in rows if "tenant_id" in r)
        by_card = _by_id(
            sys_client.get(f"/api/artifacts/by-card/{card}", headers=_h(SYSTEM, USER)).json()
        )
        assert carded["id"] not in by_card

    def test_trusted_network_system_header_or_no_header_gets_own_rows_only(self, sys_client):
        """A trusted-network caller with no token resolves to the system tenant
        (explicit ``X-Tenant-Id: <system>`` or the absent-header fallback). That
        grants the system tenant's OWN scope and nothing wider.

        Route-level only (FakeTenantMiddleware + the X-Test-Fallback stand-in),
        so AUTH_TENANT_FALLBACK_MODE does not apply here: the fallback-tagged
        case models the observe break-glass. Under enforce the real middleware
        refuses the header-less request before any route runs — pinned by
        ``TestMiddlewareFallbackTag.test_absent_header_is_refused_under_enforce``."""
        other = _upload(sys_client, tenant=CUSTOMER, subject=USER_B, publish_status="published")
        mine = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        for headers in (_h(SYSTEM, USER), {**_h(SYSTEM, USER), "X-Test-Fallback": "1"}):
            ids = set(
                _by_id(sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=headers).json())
            )
            assert mine["id"] in ids and other["id"] not in ids

    def test_real_customer_reads_only_its_own_rows(self, sys_client):
        """A real customer tenant sees its own rows only: no system rows (even
        published) and no other tenant's rows."""
        mine = _upload(sys_client, tenant=CUSTOMER, subject=USER_B, publish_status="published")
        sys_pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        sys_draft = _upload(sys_client, tenant=SYSTEM, publish_status="draft")
        other = _upload(sys_client, tenant=TENANT_B, subject=USER_B, publish_status="published")
        for url in (f"/projects/{PROJECT_ID}/artifacts", "/api/artifacts"):
            ids = set(_by_id(sys_client.get(url, headers=_h(CUSTOMER)).json()))
            assert mine["id"] in ids
            assert not ids & {sys_pub["id"], sys_draft["id"], other["id"]}, f"leak via {url}"
        for art in (sys_pub, sys_draft, other):
            r = sys_client.get(
                f"/projects/{PROJECT_ID}/artifacts/{art['id']}", headers=_h(CUSTOMER)
            )
            assert r.status_code == 404

    def test_customer_cannot_read_system_published(self, sys_client):
        """Owner's ruling 2026-09-30: system and improvement data are NEVER
        visible to a customer tenant — not even once published. Only a
        PLATFORM tenant inherits (test_platform_tenant_reads_system_published)."""
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        r = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{pub['id']}", headers=_h(TENANT_B))
        assert r.status_code == 404
        listed = _by_id(
            sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(TENANT_B)).json()
        )
        assert pub["id"] not in listed

    def test_platform_tenant_reads_system_published(self, sys_client):
        """A PLATFORM tenant still inherits SYSTEM's published rows."""
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        r = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{pub['id']}", headers=_h(PLATFORM))
        assert r.status_code == 200
        assert r.json()["is_system"] is True
        listed = _by_id(
            sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(PLATFORM)).json()
        )
        assert pub["id"] in listed

    def test_customer_cannot_read_another_customers_artifact(self, sys_client):
        from tests.conftest import TEST_TENANT_A

        other_customer = _upload(sys_client, tenant=TENANT_B, subject=USER_B)
        r = sys_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{other_customer['id']}", headers=_h(TEST_TENANT_A)
        )
        assert r.status_code == 404

    def test_customer_cannot_read_system_unpublished(self, sys_client):
        draft = _upload(sys_client, tenant=SYSTEM, publish_status="draft")
        r = sys_client.get(f"/projects/{PROJECT_ID}/artifacts/{draft['id']}", headers=_h(TENANT_B))
        assert r.status_code == 404

    def test_publish_status_rejects_unknown_value(self, sys_client):
        art = _upload(sys_client, tenant=SYSTEM)
        r = sys_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{art['id']}/publish-status",
            json={"publish_status": "public"},
            headers=_h(SYSTEM, USER),
        )
        assert r.status_code == 422


class TestPublishRequiresExplicitTenant:
    """A header-less (fallback-resolved) caller lands in the SYSTEM tenant, so
    letting it publish would share an artifact with every tenant. 403 instead."""

    def test_fallback_upload_published_is_403(self, sys_client):
        def inherited() -> int:
            rows = sys_client.get(f"/projects/{PROJECT_ID}/artifacts", headers=_h(TENANT_B))
            return sum(1 for row in rows.json() if row["is_system"])

        before = inherited()
        r = _upload(
            sys_client, tenant=SYSTEM, publish_status="published", fallback=True, expect=403
        )
        assert "explicit tenant" in str(r["detail"])
        assert inherited() == before, "refused upload must not reach other tenants"

    def test_fallback_patch_to_published_is_403(self, sys_client):
        art = _upload(sys_client, tenant=SYSTEM, publish_status="draft")
        url = f"/projects/{PROJECT_ID}/artifacts/{art['id']}"
        r = sys_client.patch(
            f"{url}/publish-status",
            json={"publish_status": "published"},
            headers={**_h(SYSTEM, USER), "X-Test-Fallback": "1"},
        )
        assert r.status_code == 403, r.text
        assert "explicit tenant" in r.json()["detail"]
        assert sys_client.get(url, headers=_h(SYSTEM, USER)).json()["publish_status"] == "draft"
        assert sys_client.get(url, headers=_h(TENANT_B)).status_code == 404

    def test_fallback_draft_upload_still_allowed(self, sys_client):
        for ps in (None, "draft"):
            art = _upload(sys_client, tenant=SYSTEM, publish_status=ps, fallback=True)
            assert art["publish_status"] == "draft"

    def test_fallback_patch_to_draft_still_allowed(self, sys_client):
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        r = sys_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{pub['id']}/publish-status",
            json={"publish_status": "draft"},
            headers={**_h(SYSTEM, USER), "X-Test-Fallback": "1"},
        )
        assert r.status_code == 200 and r.json()["publish_status"] == "draft"

    def test_explicit_system_caller_can_publish(self, sys_client):
        pub = _upload(sys_client, tenant=SYSTEM, publish_status="published")
        assert pub["publish_status"] == "published"
        draft = _upload(sys_client, tenant=SYSTEM)
        r = sys_client.patch(
            f"/projects/{PROJECT_ID}/artifacts/{draft['id']}/publish-status",
            json={"publish_status": "published"},
            headers=_h(SYSTEM, USER),
        )
        assert r.status_code == 200 and r.json()["publish_status"] == "published"
        got = sys_client.get(
            f"/projects/{PROJECT_ID}/artifacts/{draft['id']}", headers=_h(PLATFORM)
        )
        assert got.status_code == 200 and got.json()["is_system"] is True


class TestMiddlewareFallbackTag:
    """The REAL AuthMiddleware sets the source tag the routes rely on."""

    @staticmethod
    def _app() -> FastAPI:
        from auth.middleware import AuthMiddleware

        app = FastAPI()
        app.add_middleware(AuthMiddleware)

        @app.get("/artifacts/echo")
        async def _echo(request: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "tenant_id": request.state.tenant_id,
                    "fallback": getattr(request.state, "tenant_from_fallback", "UNSET"),
                }
            )

        return app

    async def _get(self, headers: dict[str, str]) -> dict:
        transport = httpx.ASGITransport(app=self._app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/artifacts/echo", headers=headers)
        assert resp.status_code == 200, resp.text
        return resp.json()

    async def test_absent_header_is_tagged_fallback(self, tenant_fallback_mode):
        """observe break-glass only: the absent header still falls back, tagged."""
        from auth.middleware import DEFAULT_TENANT_ID

        tenant_fallback_mode("observe")
        body = await self._get({})
        assert body == {"tenant_id": DEFAULT_TENANT_ID, "fallback": True}

    async def test_absent_header_is_refused_under_enforce(self):
        """Default mode: no header never reaches a route, so no fallback tag exists."""
        transport = httpx.ASGITransport(app=self._app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/artifacts/echo")
        assert resp.status_code == 401, resp.text
        assert resp.json()["error"]["code"] == "TENANT_REQUIRED"

    async def test_explicit_header_is_not_fallback(self):
        from auth.middleware import DEFAULT_TENANT_ID

        # Even when the explicit header NAMES the default tenant.
        body = await self._get({"X-Tenant-Id": DEFAULT_TENANT_ID})
        assert body == {"tenant_id": DEFAULT_TENANT_ID, "fallback": False}


class TestScopeUnit:
    """Pure SQL-shape checks on repositories.visibility — no database."""

    def _sql(self, *, tenant_id: str = TENANT_B, **kw) -> str:
        from sqlalchemy import select

        from models.artifact import Artifact
        from repositories.visibility import scope

        stmt = scope(select(Artifact.id), Artifact, tenant_id=tenant_id, subject_id="s", **kw)
        return str(stmt.compile(compile_kwargs={"literal_binds": True}))

    def test_default_is_own_tenant_only(self):
        sql = self._sql(system_tenant_id=SYSTEM)
        assert SYSTEM_HEX not in sql and "publish_status" not in sql

    def test_include_system_adds_published_gate_for_a_platform_tenant(self):
        """PLATFORM is added to artifacts_platform_tenant_ids by the module's
        autouse fixture, so it is a legitimate widen — see
        may_inherit_system()."""
        sql = self._sql(tenant_id=PLATFORM, include_system=True, system_tenant_id=SYSTEM)
        assert SYSTEM_HEX in sql and "'published'" in sql

    def test_include_system_is_a_no_op_for_a_non_platform_tenant(self):
        """Owner's ruling 2026-09-30: TENANT_B is not in
        artifacts_platform_tenant_ids, so include_system=True must not widen
        the WHERE at all — the SELECT stays own-tenant-only."""
        sql = self._sql(include_system=True, system_tenant_id=SYSTEM)
        assert SYSTEM_HEX not in sql and "publish_status" not in sql

    def test_system_tenant_is_always_scoped_to_its_own_tenant(self):
        """Owner's ruling 2026-10-02: scope() for the system tenant ALWAYS carries
        a tenant_id predicate, with or without include_system."""
        for include_system in (True, False):
            sql = self._sql(
                tenant_id=SYSTEM, include_system=include_system, system_tenant_id=SYSTEM
            )
            assert "WHERE" in sql.upper()
            assert f"tenant_id = '{SYSTEM_HEX}'" in sql
            assert "publish_status" not in sql

    def test_system_tenant_without_include_system_stays_own_tenant_only(self):
        """Mutation lookups call `scope()` with `include_system` left at its
        default (False): own-tenant only."""
        from sqlalchemy import select

        from models.artifact import Artifact
        from repositories.visibility import scope

        stmt = scope(
            select(Artifact.id),
            Artifact,
            tenant_id=SYSTEM,
            subject_id="s",
        )
        sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "WHERE" in sql.upper()

    def test_can_mutate_refuses_foreign_tenant_row(self):
        from types import SimpleNamespace

        from repositories.visibility import can_mutate

        row = SimpleNamespace(tenant_id=SYSTEM, visibility="tenant", subject_id="x")
        assert can_mutate(row, subject_id="x", tenant_id=TENANT_B) is False
        assert can_mutate(row, subject_id="x", tenant_id=SYSTEM) is True


class TestTrustedNetworkSystemHeaderIsOwnScope:
    """REAL AuthMiddleware -> scope(): a token-less trusted-network caller that
    names the system tenant (or sends no header, landing there by fallback) gets
    a tenant_id-pinned statement — never an unfiltered one."""

    @staticmethod
    def _app() -> FastAPI:
        from sqlalchemy import select

        from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware
        from models.artifact import Artifact
        from repositories.visibility import scope

        app = FastAPI()
        app.add_middleware(AuthMiddleware)

        @app.get("/artifacts/sql")
        async def _sql(request: Request) -> JSONResponse:
            stmt = scope(
                select(Artifact.id),
                Artifact,
                tenant_id=request.state.tenant_id,
                subject_id="s",
                include_system=True,
                system_tenant_id=DEFAULT_TENANT_ID,
            )
            return JSONResponse(
                {
                    "tenant_id": request.state.tenant_id,
                    "sql": str(stmt.compile(compile_kwargs={"literal_binds": True})),
                }
            )

        return app

    @pytest.mark.parametrize("with_header", [True, False])
    async def test_system_tenant_without_a_token_is_own_tenant_scoped(
        self, with_header, tenant_fallback_mode
    ):
        """``with_header=False`` exercises the absent-header fallback, which only
        exists under the observe break-glass — hence the explicit mode."""
        from auth.middleware import DEFAULT_TENANT_ID

        tenant_fallback_mode("observe")
        headers = {"X-Tenant-Id": DEFAULT_TENANT_ID} if with_header else {}
        transport = httpx.ASGITransport(app=self._app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/artifacts/sql", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["tenant_id"] == DEFAULT_TENANT_ID
        assert "WHERE" in body["sql"].upper()
        assert f"tenant_id = '{DEFAULT_TENANT_ID.replace('-', '')}'" in body["sql"]

    async def test_no_header_never_reaches_scope_under_enforce(self):
        """Default mode: a token-less, header-less caller gets NO scope at all —
        not even the system tenant's own — because it is refused before the route."""
        transport = httpx.ASGITransport(app=self._app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/artifacts/sql")
        assert resp.status_code == 401, resp.text
        assert resp.json()["error"]["code"] == "TENANT_REQUIRED"
        assert "sql" not in resp.json()
