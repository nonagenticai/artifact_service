"""AUTH_TENANT_FALLBACK_MODE=enforce on the REAL routes (owner: strict tenant separation).

A token-less request that sends no ``X-Tenant-Id`` used to be served as
``DEFAULT_TENANT_ID`` — the SYSTEM tenant. Under ``enforce`` (the default) it
is 401 ``TENANT_REQUIRED`` on every protected route, counted as
``artifact_service_tenant_resolution_total{source="refused_missing_tenant"}``.

The app here is the real artifact routers behind the real ``AuthMiddleware``.
``get_db`` is overridden to raise 418, so "the request reached the route" is
observable WITHOUT a database: 418 means the middleware admitted it, 401 means
it did not. A bare ``!= 401`` would also pass on a 500 from an unreachable DB,
which is why the positive control asserts the 418 exactly.

Transport: ``httpx.ASGITransport`` reports the peer as ``127.0.0.1``, which is
inside the default ``TRUSTED_CIDRS`` — so the trusted-network branch is the one
genuinely exercised.
"""

from __future__ import annotations

import io
import uuid
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from prometheus_client import REGISTRY

from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware, _license_cache
from tests.conftest import TEST_TENANT_A

METRIC = "artifact_service_tenant_resolution_total"
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
REACHED = 418


def _value(source: str) -> float:
    v = REGISTRY.get_sample_value(METRIC, {"source": source})
    assert v is not None, f"{METRIC}{{source={source!r}}} is not registered"
    return v


def _make_app() -> FastAPI:
    from core.database import get_db
    from routes.artifacts import cross_project_router, get_storage_service, router
    from routes.health import router as health_router

    app = FastAPI()
    app.include_router(router)
    app.include_router(cross_project_router)
    app.include_router(health_router)

    async def _db_reached() -> None:
        raise HTTPException(status_code=REACHED, detail="route reached")

    app.dependency_overrides[get_db] = _db_reached
    app.dependency_overrides[get_storage_service] = lambda: MagicMock()
    app.add_middleware(AuthMiddleware)
    return app


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    _license_cache.clear()
    monkeypatch.delenv("AUTH_ENABLED", raising=False)


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _upload_kwargs(headers: dict[str, str]) -> dict:
    return {
        "data": {"filename": "a.txt", "content_type": "text/plain", "kind": "doc"},
        "files": {"file": ("a.txt", io.BytesIO(b"hello"), "text/plain")},
        "headers": headers,
    }


async def _call(client: httpx.AsyncClient, op: str, headers: dict[str, str]) -> httpx.Response:
    if op == "list":
        return await client.get("/api/artifacts", headers=headers)
    if op == "by-id":
        return await client.get(f"/api/artifacts/{uuid.uuid4()}", headers=headers)
    if op == "project-list":
        return await client.get(f"/projects/{PROJECT_ID}/artifacts", headers=headers)
    if op == "upload":
        return await client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload", **_upload_kwargs(headers)
        )
    raise AssertionError(op)


OPS = ["list", "by-id", "project-list", "upload"]


@pytest.mark.parametrize("op", OPS)
async def test_no_tenant_header_is_401_tenant_required(client: httpx.AsyncClient, op: str) -> None:
    """Default mode: no header => 401 TENANT_REQUIRED, and the route never runs."""
    resp = await _call(client, op, {})
    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert body["error"]["code"] == "TENANT_REQUIRED"
    assert "tenant_required" in body["error"]["message"]
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert DEFAULT_TENANT_ID not in resp.text


@pytest.mark.parametrize("op", OPS)
async def test_a_uuid_tenant_header_is_admitted(client: httpx.AsyncClient, op: str) -> None:
    """Control: the same request WITH a uuid header reaches the route (418 = the
    stubbed get_db ran), so what is refused above is the missing tenant only."""
    resp = await _call(client, op, {"X-Tenant-Id": TEST_TENANT_A})
    assert resp.status_code == REACHED, resp.text


@pytest.mark.parametrize("path", ["/health/live", "/health", "/healthz", "/metrics", "/docs"])
async def test_auth_exempt_paths_never_need_a_tenant(client: httpx.AsyncClient, path: str) -> None:
    """Exempt paths are decided before the tenant check: never TENANT_REQUIRED."""
    resp = await client.get(path)
    assert resp.status_code != 401, resp.text
    assert "TENANT_REQUIRED" not in resp.text


async def test_health_live_is_200_without_a_tenant(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/live")
    assert resp.status_code == 200, resp.text


async def test_refusal_increments_refused_missing_tenant(client: httpx.AsyncClient) -> None:
    before = {s: _value(s) for s in ("refused_missing_tenant", "fallback_default")}
    resp = await client.get("/api/artifacts")
    assert resp.status_code == 401
    assert _value("refused_missing_tenant") - before["refused_missing_tenant"] == 1.0
    assert _value("fallback_default") == before["fallback_default"]


async def test_refusal_logs_one_warning_with_path_and_peer(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING", logger="auth.middleware"):
        resp = await client.get("/api/artifacts")
    assert resp.status_code == 401
    hits = [r for r in caplog.records if "tenant_required" in r.getMessage()]
    assert len(hits) == 1, caplog.text
    assert "/api/artifacts" in hits[0].getMessage()
    assert "127.0.0.1" in hits[0].getMessage()


async def test_observe_mode_keeps_the_old_fallback(
    client: httpx.AsyncClient, tenant_fallback_mode
) -> None:
    """observe break-glass: the header-less request reaches the route again, counted
    as fallback_default and NOT as a refusal."""
    tenant_fallback_mode("observe")
    before = {s: _value(s) for s in ("refused_missing_tenant", "fallback_default")}
    resp = await client.get("/api/artifacts")
    assert resp.status_code == REACHED, resp.text
    assert _value("fallback_default") - before["fallback_default"] == 1.0
    assert _value("refused_missing_tenant") == before["refused_missing_tenant"]


def test_the_default_mode_is_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh Settings with no env var and no .env file defaults to enforce."""
    from core.config import Settings

    monkeypatch.delenv("AUTH_TENANT_FALLBACK_MODE", raising=False)
    assert Settings(_env_file=None).auth_tenant_fallback_mode == "enforce"


@pytest.mark.parametrize("raw", ["observe", "OBSERVE", "enforce"])
def test_the_mode_reads_the_env(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    from core.config import Settings

    monkeypatch.setenv("AUTH_TENANT_FALLBACK_MODE", raw)
    assert Settings(_env_file=None).auth_tenant_fallback_mode == raw.lower()


def test_an_unknown_mode_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError

    from core.config import Settings

    monkeypatch.setenv("AUTH_TENANT_FALLBACK_MODE", "off")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
