"""Tests for Phase 3: tenant_name column capture and auto-fill.

Two cases:
1. Middleware captures X-Tenant-Name header into request.state.tenant_name.
2. The before_insert listener auto-fills tenant_name := tenant_id when the
   caller did not supply a tenant_name (e.g. trusted-network call without
   the X-Tenant-Name header).
"""

from unittest.mock import MagicMock
from uuid import UUID

import pytest
from fastapi import Request

from tests.conftest import TEST_TENANT_A

# ---------------------------------------------------------------------------
# Test 1: Middleware captures X-Tenant-Name into request.state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_captures_tenant_name() -> None:
    """AuthMiddleware stashes X-Tenant-Name on request.state.tenant_name in bypass mode."""
    import os

    os.environ["AUTH_ENABLED"] = "false"
    try:
        from auth.middleware import AuthMiddleware

        # Build a minimal ASGI request with the header present
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/artifacts/",
            "query_string": b"",
            "headers": [
                # A uuid, not the old ``b"acme-corp"``: the bypass branch gates
                # X-Tenant-Id through canonical_tenant_id, so a NAME here is a
                # 400 and the middleware never reaches call_next — this test
                # would have failed on a KeyError, blaming the wrong thing.
                # The human-readable name travels in X-Tenant-Name, which is
                # exactly what this test is about.
                (b"x-tenant-id", TEST_TENANT_A.encode()),
                (b"x-tenant-name", b"Acme Corporation"),
            ],
        }
        request = Request(scope)

        captured: dict = {}

        async def call_next(req: Request):
            captured["tenant_name"] = getattr(req.state, "tenant_name", "__MISSING__")
            from starlette.responses import Response

            return Response("ok")

        mw = AuthMiddleware(app=MagicMock(), bypass_auth=True)
        await mw.dispatch(request, call_next)

        assert captured["tenant_name"] == "Acme Corporation", (
            f"Expected 'Acme Corporation', got {captured['tenant_name']!r}"
        )
    finally:
        os.environ.pop("AUTH_ENABLED", None)


# ---------------------------------------------------------------------------
# Test 2: before_insert listener auto-fills tenant_name := tenant_id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_listener_autofills_tenant_name(pg_engine) -> None:
    """When tenant_name is not set, the before_insert listener sets it to tenant_id."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from models.artifact import Artifact

    factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as session:
        artifact = Artifact(
            tenant_id=TEST_TENANT_A,
            # tenant_name deliberately NOT set — listener should fill it
            project_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            filename="auto-fill-test.txt",
            content_type="text/plain",
            kind="doc",
            sensitivity="internal",
            size=42,
            sha256="deadbeef" * 8,
            storage_key="projects/auto-fill-test/v1/auto-fill-test.txt",
            created_by=TEST_TENANT_A,
            visibility="tenant",
        )

        session.add(artifact)
        await session.commit()
        await session.refresh(artifact)

        assert artifact.tenant_name == TEST_TENANT_A, (
            f"Expected tenant_name='test-tenant-uuid-001', got {artifact.tenant_name!r}"
        )
