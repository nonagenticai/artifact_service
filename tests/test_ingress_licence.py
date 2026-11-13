"""Licence-only callers arriving through a public ingress.

What the pod receives for such a request (measured 2026-10-11):

* the client sent ``Authorization: Bearer <licence>`` (and possibly
  ``X-Tenant-Id: Bearer <licence>``);
* the ingress Lua STRIPPED the client ``X-Tenant-Id``, introspected the licence
  and injected the licence's tenant as a bare uuid ``X-Tenant-Id``, leaving
  ``Authorization`` intact;
* the peer address is ztunnel's link-local ``169.254.7.127`` — outside
  ``TRUSTED_CIDRS``.

Before the fix that landed on "Not trusted, no token" -> 401. Now it is admitted
iff the ``Authorization`` licence introspects ACTIVE to EXACTLY the uuid tenant
(equality, never substitution). Since the RM #222 port, ``Authorization`` is a
licence carrier in its own right: a live licence for ANOTHER tenant is a 403
(not the old 401), and a live licence with no ``X-Tenant-Id`` is its own
tenant's principal. Every no-licence negative must stay the old 401.

``_introspect_license`` is monkeypatched. The peer is ``169.254.7.127`` (and a
public address for the forged-header negatives), neither in the default
``TRUSTED_CIDRS``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import REGISTRY

import auth.middleware as auth_middleware
from auth.middleware import (
    AuthMiddleware,
    _is_trusted_network,
    _license_cache,
    _proof_negative_cache,
    _proof_not_found_cache,
)
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

INGRESS_PEER = ("169.254.7.127", 44964)
PUBLIC_PEER = ("203.0.113.9", 40000)
LICENCE = "lic.abc.def"
SUBJECT = "0198c2d4-7a10-7aaa-8bbb-000000000123"
SOURCE_METRIC = "artifact_service_tenant_resolution_total"

# Exactly what the gateway forwards for a licence-only client.
INGRESS_HEADERS = {"X-Tenant-Id": TEST_TENANT_A, "Authorization": f"Bearer {LICENCE}"}

# Stands in for the Keycloak access token FR forwards in Authorization.
KEYCLOAK_JWT = "keycloak-access-token-stand-in"  # value irrelevant: introspection is mocked


def _source(source: str) -> float:
    v = REGISTRY.get_sample_value(SOURCE_METRIC, {"source": source})
    return v or 0.0


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": request.state.tenant_id,
                "subject_id": request.state.subject_id,
                "from_fallback": request.state.tenant_from_fallback,
            }
        )

    return app


async def _get(headers: dict[str, str], peer: tuple[str, int] = INGRESS_PEER) -> httpx.Response:
    transport = httpx.ASGITransport(app=_make_app(), client=peer)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        return await ac.get("/artifacts/echo", headers=headers)


class _introspects_to:  # noqa: N801 - reads as a verb at the call site
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: list[str] = []

    async def __call__(self, token: str) -> Any:
        self.calls.append(token)
        return self.payload


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    _license_cache.clear()
    _proof_negative_cache.clear()
    _proof_not_found_cache.clear()
    monkeypatch.delenv("AUTH_ENABLED", raising=False)


def _assert_old_401(resp: httpx.Response) -> None:
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert resp.json()["error"]["message"] == "Missing authentication token"
    assert TEST_TENANT_A not in resp.text and TEST_TENANT_B not in resp.text


def test_the_ingress_peer_is_not_a_trusted_network() -> None:
    """Precondition: the fix must not depend on (or widen) TRUSTED_CIDRS."""
    assert not _is_trusted_network(INGRESS_PEER[0])
    assert not _is_trusted_network(PUBLIC_PEER[0])


# --- the positive: what the gateway forwards ---------------------------------


@pytest.mark.parametrize("proof_mode", ["observe", "enforce"])
async def test_a_gateway_forwarded_licence_request_is_admitted(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, proof_mode: str
) -> None:
    tenant_proof_mode(proof_mode)
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A, "subject_id": SUBJECT})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    before = _source("licence")

    resp = await _get(INGRESS_HEADERS)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "tenant_id": TEST_TENANT_A,
        "subject_id": SUBJECT,
        "from_fallback": False,
    }
    assert fake.calls == [LICENCE]
    assert _source("licence") - before == 1.0


async def test_the_subject_comes_from_introspection_never_the_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wire ``X-Subject-Id`` must not beat the introspected subject (BOLA)."""
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": True, "tenant_id": TEST_TENANT_A}),
    )
    resp = await _get({**INGRESS_HEADERS, "X-Subject-Id": "victim-subject"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["subject_id"] == ""


# --- security negatives: all stay the old 401 ---------------------------------


async def test_a_forged_tenant_header_without_a_licence_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    for peer in (INGRESS_PEER, PUBLIC_PEER):
        _assert_old_401(await _get({"X-Tenant-Id": TEST_TENANT_A}, peer))
    assert fake.calls == [], "no Authorization => nothing introspected"


async def test_a_licence_for_another_tenant_is_refused_not_substituted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid ACTIVE licence for B, header names A: neither A nor B is served — 403."""
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": True, "tenant_id": TEST_TENANT_B}),
    )
    resp = await _get(INGRESS_HEADERS, PUBLIC_PEER)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_MISMATCH"
    assert TEST_TENANT_A not in resp.text and TEST_TENANT_B not in resp.text


async def test_a_keycloak_jwt_is_not_treated_as_a_licence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FR's Keycloak bearer introspects token_not_found: refused, and cached briefly."""
    fake = _introspects_to({"active": False, "reason": "token_not_found"})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    headers = {"X-Tenant-Id": TEST_TENANT_A, "Authorization": f"Bearer {KEYCLOAK_JWT}"}

    _assert_old_401(await _get(headers))
    _assert_old_401(await _get(headers))
    assert fake.calls == [KEYCLOAK_JWT], "token_not_found must hit the short cache"


async def test_an_inactive_licence_naming_the_header_tenant_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inactive payload names the MATCHING tenant, so dropping the ``active``
    check would admit it."""
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": False, "reason": "revoked", "tenant_id": TEST_TENANT_A}),
    )
    _assert_old_401(await _get(INGRESS_HEADERS))


async def test_an_authorization_licence_alone_is_its_own_tenants_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RM #222: no X-Tenant-Id => the Authorization licence's OWN tenant (never a
    header-chosen one). Before the port this was 401 — the licence was not read."""
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A, "subject_id": SUBJECT})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    resp = await _get({"Authorization": f"Bearer {LICENCE}"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_A
    assert resp.json()["subject_id"] == SUBJECT


async def test_a_non_uuid_tenant_header_beside_a_licence_is_400(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    resp = await _get({"X-Tenant-Id": "n8n-dev", "Authorization": f"Bearer {LICENCE}"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"


@pytest.mark.parametrize("payload", [None, ["x"]])
async def test_an_introspection_outage_or_junk_answer_is_refused_not_500(
    monkeypatch: pytest.MonkeyPatch, payload: Any
) -> None:
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(payload))
    _assert_old_401(await _get(INGRESS_HEADERS))


async def test_an_introspection_exception_is_refused_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(_token: str) -> None:
        raise httpx.ConnectError("license-authz unreachable")

    monkeypatch.setattr(auth_middleware, "_introspect_license", _boom)
    _assert_old_401(await _get(INGRESS_HEADERS))


async def test_a_licence_with_a_non_uuid_tenant_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": True, "tenant_id": "n8n-dev"}),
    )
    resp = await _get(INGRESS_HEADERS)
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["message"] == "License token tenant context is not a uuid"


async def test_a_licence_whose_subject_names_the_header_tenant_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tenant is the licence's ``tenant_id``, never its ``subject_id``: a
    licence of tenant B whose SUBJECT uuid happens to equal the header must not
    prove tenant A (the old ``subject_id or tenant_id`` precedence would)."""
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": True, "tenant_id": TEST_TENANT_B, "subject_id": TEST_TENANT_A}),
    )
    resp = await _get(INGRESS_HEADERS)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_MISMATCH"
