"""Per-user-within-tenant visibility tests for artifact_service.

6-test matrix for the artifacts entity:
    1. tenant-visible artifact seen by other user in same tenant
    2. user-visible artifact HIDDEN from other user in same tenant
    3. user-visible artifact visible to creator
    4. cross-tenant isolation holds for both visibilities
    5. creator can delete their own user-visible artifact
    6. other user CANNOT delete creator's user-visible artifact (404, not 403)

Headers:
    X-Test-Tenant: controls tenant_id in FakeTenantMiddleware
    X-Subject-Id:  controls subject_id
    X-Visibility:  'tenant' (default) | 'user' — stored on upload
"""

import io
import os
import secrets
from typing import Any
from unittest.mock import MagicMock, patch

import conftest as _root_conftest
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from starlette.middleware.base import BaseHTTPMiddleware

from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

TENANT = TEST_TENANT_A
TENANT_B = TEST_TENANT_B
USER_A = "user-alice"
USER_B = "user-bob"
PROJECT_ID = "11111111-1111-1111-1111-111111111111"

# ⛔ THE DSN COMES FROM conftest, IT IS NOT RE-DERIVED HERE.
#
# This module used to carry its OWN copy of
# ``os.getenv("TEST_DATABASE_URL", "…localhost:5442…")``. That variable is set by
# nothing — it appears zero times in the shared CI archetype — so these six
# tests skipped on every CI run. They kept skipping even after ``conftest.pg_engine``
# was taught the archetype's names, because the second copy did not change: this
# file never touches ``pg_engine``, it builds its own engine. A duplicated
# resolution is how the first hole survived its own fix.
#
# ``import conftest``, NOT ``from tests.conftest import …``: measured,
# ``conftest is tests.conftest`` -> ``False``. pytest loads the root conftest as
# ``conftest`` and that is the module object whose counter
# ``pytest_sessionfinish`` reads; the ``tests.conftest`` spelling is a separate
# module with its own globals, so ``note_database_reached()`` called through it
# would increment a counter nothing looks at.
TEST_DATABASE_URL = _root_conftest.TEST_DATABASE_URL


# ---------------------------------------------------------------------------
# Client fixture: creates schema + app per test class (shared within class)
# ---------------------------------------------------------------------------


def _make_client() -> tuple[TestClient, MagicMock]:
    """Build a FastAPI app with real DB and mocked storage for visibility testing.

    Creates (or recreates) the schema synchronously using the app's own event loop
    (via TestClient lifespan / asyncio.run). Returns (client, mock_storage).
    """
    import asyncio
    import sys

    src_path = os.path.join(os.path.dirname(__file__), "..", "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from sqlalchemy import text  # noqa: PLC0415

    from core.database import Base, get_db  # noqa: PLC0415
    from routes.artifacts import get_storage_service, router  # noqa: PLC0415
    from routes.health import router as health_router  # noqa: PLC0415

    # Create schema synchronously BEFORE building the app
    async def _create_schema():
        engine = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as e:
            await engine.dispose()
            # Same decision as pg_engine: an unreachable database is a FAILURE.
            _root_conftest.database_unreachable(e)
        _root_conftest.note_database_reached()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())

    # Dedicated engine for the app (uses regular pool)
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    app = FastAPI()
    app.include_router(router)
    app.include_router(health_router)

    async def override_get_db():
        async with factory() as session:
            yield session

    mock_storage = MagicMock()
    mock_storage.generate_storage_key.side_effect = lambda **kw: (
        f"test/storage/{secrets.token_hex(8)}/v1/{kw.get('filename', 'file.txt')}"
    )
    mock_storage.upload_file.return_value = None
    mock_storage.download_file.return_value = b"test file content"
    mock_storage.delete_file.return_value = None

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_service] = lambda: mock_storage

    class FakeTenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            tenant = request.headers.get("X-Test-Tenant", TEST_TENANT_A)
            request.state.tenant_id = tenant
            request.state.user = {"user_id": tenant, "tenant_id": tenant}
            request.state.subject_id = request.headers.get("X-Subject-Id", "")
            return await call_next(request)

    app.add_middleware(FakeTenantMiddleware)
    return TestClient(app, raise_server_exceptions=True), mock_storage


@pytest.fixture(scope="class")
def vis_client():
    """Class-scoped client: one schema creation per test class."""
    client, _mock = _make_client()
    with client:
        yield client


# ---------------------------------------------------------------------------
# Upload/query helpers
# ---------------------------------------------------------------------------


def _upload(client, *, tenant: str, subject: str, visibility: str = "tenant") -> dict[str, Any]:
    """Upload a minimal artifact and return upload response."""
    filename = f"vis-{secrets.token_hex(6)}.txt"
    with patch("routes.artifacts.settings") as mock_settings:
        mock_settings.allowed_mimes = ["text/plain"]
        mock_settings.max_file_size_bytes = 10 * 1024 * 1024
        mock_settings.enable_virus_scanning = False
        resp = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": filename,
                "content_type": "text/plain",
                "kind": "doc",
                "sensitivity": "internal",
                "tags": "",
            },
            files={"file": (filename, io.BytesIO(b"hello visibility"), "text/plain")},
            headers={
                "X-Test-Tenant": tenant,
                "X-Subject-Id": subject,
                "X-Visibility": visibility,
            },
        )
    assert resp.status_code == 200, f"upload failed: {resp.status_code} {resp.text}"
    data = resp.json()
    return {"artifact_id": str(data["artifact_id"]), "filename": filename}


def _list_ids(client, *, tenant: str, subject: str) -> set[str]:
    resp = client.get(
        f"/projects/{PROJECT_ID}/artifacts",
        headers={"X-Test-Tenant": tenant, "X-Subject-Id": subject},
    )
    assert resp.status_code == 200, f"list failed: {resp.status_code} {resp.text}"
    return {str(a["id"]) for a in resp.json()}


def _get(client, artifact_id: str, *, tenant: str, subject: str) -> int:
    resp = client.get(
        f"/projects/{PROJECT_ID}/artifacts/{artifact_id}",
        headers={"X-Test-Tenant": tenant, "X-Subject-Id": subject},
    )
    return resp.status_code


def _delete(client, artifact_id: str, *, tenant: str, subject: str) -> int:
    resp = client.delete(
        f"/projects/{PROJECT_ID}/artifacts/{artifact_id}",
        headers={"X-Test-Tenant": tenant, "X-Subject-Id": subject},
    )
    return resp.status_code


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestVisibility:
    """Six visibility tests for the artifacts entity."""

    # 1. tenant-visible artifact seen by another user in same tenant
    def test_tenant_visible_seen_by_other_user(self, vis_client):
        art = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="tenant")

        status_code = _get(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_B)
        assert status_code == 200, "tenant-visible artifact must be readable by other tenant member"

        ids = _list_ids(vis_client, tenant=TENANT, subject=USER_B)
        assert art["artifact_id"] in ids

    # 2. user-visible artifact HIDDEN from other user in same tenant
    def test_user_visible_hidden_from_other_user(self, vis_client):
        art = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="user")

        status_code = _get(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_B)
        assert status_code == 404, "user-visible artifact must be hidden from non-creator"

        ids = _list_ids(vis_client, tenant=TENANT, subject=USER_B)
        assert art["artifact_id"] not in ids, (
            "user-visible artifact must not appear in list for other user"
        )

    # 3. user-visible artifact visible to its creator
    def test_user_visible_visible_to_creator(self, vis_client):
        art = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="user")

        status_code = _get(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_A)
        assert status_code == 200, "user-visible artifact must be visible to its creator"

        ids = _list_ids(vis_client, tenant=TENANT, subject=USER_A)
        assert art["artifact_id"] in ids

    # 4. cross-tenant isolation: neither visibility leaks to other tenant
    def test_cross_tenant_isolation(self, vis_client):
        art_t = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="tenant")
        art_u = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="user")

        for art in (art_t, art_u):
            sc = _get(vis_client, art["artifact_id"], tenant=TENANT_B, subject=USER_A)
            assert sc == 404, (
                f"cross-tenant leak: artifact {art['artifact_id']} visible in TENANT_B"
            )

        ids_b = _list_ids(vis_client, tenant=TENANT_B, subject=USER_A)
        assert art_t["artifact_id"] not in ids_b
        assert art_u["artifact_id"] not in ids_b

    # 5. creator can delete their own user-visible artifact
    def test_creator_can_delete_own_user_artifact(self, vis_client):
        art = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="user")

        sc = _delete(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_A)
        assert sc == 204, f"creator should be able to delete own user-visible artifact, got {sc}"

        sc2 = _get(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_A)
        assert sc2 == 404

    # 6. other user CANNOT delete creator's user-visible artifact (404, not 403)
    def test_other_user_cannot_delete_user_artifact(self, vis_client):
        art = _upload(vis_client, tenant=TENANT, subject=USER_A, visibility="user")

        sc = _delete(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_B)
        assert sc == 404, f"BOLA: non-creator delete should return 404, got {sc}"

        # Alice's artifact must still be intact
        sc2 = _get(vis_client, art["artifact_id"], tenant=TENANT, subject=USER_A)
        assert sc2 == 200, "artifact should still exist for creator after failed delete"
