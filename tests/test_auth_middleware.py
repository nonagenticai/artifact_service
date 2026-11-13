"""Unit tests for the license-token AuthMiddleware.

The middleware is exercised against a small ASGI app constructed inside each
test so the assertions stay tight and we avoid fighting the global ENABLE_AUTH
override in tests/conftest.py.

Coverage:
- public endpoints (root, health, docs) bypass auth
- /artifacts/* from a "trusted network" peer (testclient hostname) bypasses
  with the default tenant
- /artifacts/* with a valid Bearer token in X-Tenant-Id is admitted and the
  introspection response populates request.state
- /artifacts/* with an invalid Bearer token → 401
- Introspection results are cached: second call does not re-hit the licenses
  service.
- a bare NAME in X-Tenant-Id is 400, from the same trusted peer that used to
  have it accepted.

TENANT IDS ARE UUIDS (2026-08-26). Every tenant literal in this file used to be
a name — ``n8n-dev``, ``tenant-uuid-1``, ``subject-uuid-9``. Those spellings
were not incidental fixture noise: they were the suite agreeing with the defect,
which is why replacing them was part of the change rather than cleanup after it.
The license branch gates the INTROSPECTED payload too, so a name there is a 401.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import auth.middleware as auth_middleware
from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware, _license_cache
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

#: On the license branch the tenant is resolved as ``subject_id or tenant_id``
#: and BOTH are now uuid-gated — the introspected payload is decoded JSON, so a
#: name there is refused exactly like a name on the wire. These two must stay
#: DISTINCT so the `subject_id`-wins precedence below is actually observable.
LICENSE_TENANT = TEST_TENANT_A
LICENSE_SUBJECT = TEST_TENANT_B


def _make_app() -> FastAPI:
    """Build a minimal app with one public + one protected route."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": getattr(request.state, "tenant_id", None),
                "subject_id": getattr(request.state, "subject_id", None),
            }
        )

    return app


@pytest.fixture(autouse=True)
def _clear_license_cache() -> None:
    """Each test starts with a fresh introspection cache."""
    _license_cache.clear()


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Public-endpoint bypass
# ---------------------------------------------------------------------------


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Protected paths
# ---------------------------------------------------------------------------


async def test_protected_route_from_trusted_network_bypasses_auth(
    client: httpx.AsyncClient,
    tenant_fallback_mode,
) -> None:
    """ASGI peer (127.0.0.1) is a trusted network — under the observe break-glass.

    ``AUTH_TENANT_FALLBACK_MODE=observe`` is set explicitly: this pins the OLD
    absent-header fallback, which ``enforce`` (the default) now refuses — see
    ``test_protected_route_from_trusted_network_without_tenant_is_401``.
    """
    tenant_fallback_mode("observe")
    resp = await client.get("/artifacts/echo")
    assert resp.status_code == 200
    body = resp.json()
    # No X-Tenant-Id at all -> the CONFIGURED default, which is a uuid. This used
    # to assert the literal 'n8n-dev'; that string is a tenant NAME and is no
    # longer a tenant id anywhere in this service.
    assert body["tenant_id"] == DEFAULT_TENANT_ID


async def test_protected_route_from_trusted_network_without_tenant_is_401(
    client: httpx.AsyncClient,
) -> None:
    """Default mode (enforce): same peer, same header-less request -> 401.

    No mode is set here on purpose — this asserts the DEFAULT. The body must not
    carry the default tenant: refusing and then leaking its id would be half a fix.
    """
    resp = await client.get("/artifacts/echo")
    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert body["error"]["code"] == "TENANT_REQUIRED"
    assert body["error"]["status"] == 401
    assert "tenant_required" in body["error"]["message"]
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert DEFAULT_TENANT_ID not in resp.text

    # Control: the same peer WITH a uuid header is admitted, so what was refused
    # is the missing tenant, not the peer.
    ok = await client.get("/artifacts/echo", headers={"X-Tenant-Id": TEST_TENANT_A})
    assert ok.status_code == 200, ok.text
    assert ok.json()["tenant_id"] == TEST_TENANT_A


async def test_health_stays_public_without_a_tenant_under_enforce(
    client: httpx.AsyncClient,
) -> None:
    """Auth-exempt paths never reach the tenant decision."""
    resp = await client.get("/health")
    assert resp.status_code == 200


async def test_protected_route_with_valid_license_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid Bearer token in X-Tenant-Id is introspected and admitted.

    The TENANT is the payload's ``tenant_id``; ``subject_id`` is the licence
    holder's subject row id and is carried ONLY as the subject. This used to pin
    the opposite (subject-first "single-tenant-per-subject" precedence, a
    leftover from when licences had tenant_id == subject_id). Every active
    licence now has a distinct subject, so that precedence scoped each licence
    caller into a tenant named after its subject (procedure_management's pm#78
    defect) and made the ingress-injected tenant a mismatch.
    """
    introspect_payload: dict[str, Any] = {
        "active": True,
        "tenant_id": LICENSE_TENANT,
        "subject_id": LICENSE_SUBJECT,
        "license_id": "lic-77",
        "roles": ["user"],
        "tenant_name": "acme",
    }

    async def _fake(token: str) -> dict[str, Any]:
        assert token == "abc.def.ghi"
        return introspect_payload

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/artifacts/echo",
            headers={"X-Tenant-Id": "Bearer abc.def.ghi"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == LICENSE_TENANT
    assert body["subject_id"] == LICENSE_SUBJECT
    assert LICENSE_TENANT != LICENSE_SUBJECT, "the two must differ or this proves nothing"


async def test_protected_route_with_invalid_license_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inactive introspection result returns 401 with the envelope shape."""

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": False}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/artifacts/echo",
            headers={"X-Tenant-Id": "Bearer dud-token"},
        )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert body["error"]["status"] == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_license_subject_ignores_client_supplied_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Within-tenant BOLA: X-Subject-Id must NOT override the introspected subject.

    The license branch used to resolve the subject as
    ``request.headers.get("X-Subject-Id") or license_result.get("subject_id")``,
    so a client-supplied header BEAT the license-authz-validated Subject UUID.
    Any holder of any valid license could send another user's subject and both
    read and mutate their ``visibility='user'`` artifacts (see
    ``repositories/visibility.py``: ``scope()`` matches on ``subject_id`` and
    ``can_mutate()`` gates on it).

    The attacker header here is deliberately DIFFERENT from the introspected
    subject, so the assertion fails on the pre-fix expression.
    """
    introspect_payload: dict[str, Any] = {
        "active": True,
        "tenant_id": LICENSE_TENANT,
        "subject_id": LICENSE_SUBJECT,
        "license_id": "lic-77",
    }

    async def _fake(_token: str) -> dict[str, Any]:
        return introspect_payload

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/artifacts/echo",
            headers={
                "X-Tenant-Id": "Bearer abc.def.ghi",
                "X-Subject-Id": "attacker-chosen-subject",
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["subject_id"] == LICENSE_SUBJECT
    assert body["subject_id"] != "attacker-chosen-subject"


async def test_license_subject_empty_when_introspection_carries_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tenant-only license yields an EMPTY subject, not the header's value.

    Without this the fix could regress to "fall back to the header when the
    payload has no subject", which is the same BOLA with an extra step. Empty
    means tenant-only downstream: ``scope()`` returns visibility='tenant' rows
    only, and ``Artifact._autofill_subject_id`` (before_insert) still fills
    ``subject_id := tenant_id`` so row creation keeps working.
    """

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": True, "tenant_id": LICENSE_TENANT}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/artifacts/echo",
            headers={
                "X-Tenant-Id": "Bearer abc.def.ghi",
                "X-Subject-Id": "attacker-chosen-subject",
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["subject_id"] == ""


async def test_trusted_network_still_accepts_propagated_subject_header(
    client: httpx.AsyncClient,
) -> None:
    """Scope pin: the trusted-network branch DOES still trust X-Subject-Id.

    That branch has no license to introspect — the peer is already inside the
    trusted CIDR set and X-Subject-Id is the in-mesh propagated identity, the
    only source of one. Inverting it there breaks real in-cluster callers
    (discovery-engine did exactly that). This test fails if the fix leaks past
    the license branch.
    """
    resp = await client.get(
        "/artifacts/echo",
        headers={"X-Tenant-Id": TEST_TENANT_A, "X-Subject-Id": "propagated-subject-7"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == TEST_TENANT_A
    # The TENANT is uuid-gated; the SUBJECT deliberately is not — it is an opaque
    # in-mesh identity, which is why a non-uuid subject is still honoured here.
    assert body["subject_id"] == "propagated-subject-7"


async def test_a_bare_tenant_name_from_a_trusted_peer_is_now_400(
    client: httpx.AsyncClient,
) -> None:
    """The inversion, recorded where the old expectation used to live.

    The test above this one used to send ``X-Tenant-Id: n8n-dev`` and assert
    200 with ``tenant_id == "n8n-dev"``. Same peer, same header, opposite
    outcome — a trusted in-mesh caller can no longer bring a tenant into
    existence by naming it. Kept as an assertion rather than deleted so the file
    still says what changed.
    """
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": "n8n-dev"})

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"]["code"] == "INVALID_TENANT_ID"
    # The rejected value is never echoed back into the response body.
    assert "n8n-dev" not in resp.text


async def test_license_payload_carrying_a_tenant_name_is_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name in the INTROSPECTED payload is 401, not 400 — and not accepted.

    401 rather than 400 because the fault is in what the authz service returned,
    not in anything the client sent: the client's remedy is a different token,
    so a re-auth challenge is the right signal here and the wrong one on the
    header path.
    """

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": True, "subject_id": "n8n-dev", "tenant_id": "n8n-dev"}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/artifacts/echo", headers={"X-Tenant-Id": "Bearer abc.def.ghi"})

    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert "uuid" in resp.json()["error"]["message"].lower()


async def test_protected_route_missing_tenant_in_introspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Active token with neither subject_id nor tenant_id → 401 (must be tenant-bound).

    artifact_service resolves tenant context as ``subject_id or tenant_id``;
    both must be missing to exercise the "no tenant context" 401 branch.
    """

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": True, "roles": ["user"]}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/artifacts/echo",
            headers={"X-Tenant-Id": "Bearer no-tenant"},
        )

    assert resp.status_code == 401
    assert "tenant" in resp.json()["error"]["message"].lower()
