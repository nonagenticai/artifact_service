"""artifact_service#53 — a trusted peer's uuid ``X-Tenant-Id`` must be PROVEN.

Proof = a licence in ``Authorization: Bearer <licence>`` whose tenant (the
licence branch's own derivation, ``_licence_tenant``) equals the header.

* proven                       -> admitted, ``tenant_proof=explicit_header_proven``
* unproven, observe (default)  -> admitted exactly as before, counted unproven
* unproven, enforce            -> 401 ``TENANT_PROOF_REQUIRED``
* licence for ANOTHER tenant   -> 403 ``TENANT_PROOF_MISMATCH`` in BOTH modes since the
                                  RM #222 port (was: observe admitted it; measured 0
                                  such requests in production before the change)
* introspection error          -> unproven, never a 500

``_introspect_license`` is monkeypatched; the peer is ``10.42.7.9`` (inside the
default ``TRUSTED_CIDRS``), so the trusted-network branch is the one exercised.
Every negative case is built so it would turn GREEN-for-the-wrong-reason into a
visible failure if its guard were removed: the mismatch payload is ACTIVE (so
dropping the mismatch check admits it), the inactive payload carries the
MATCHING tenant (so dropping the ``active`` check proves it), and the raising
introspector would hit the outer handler's 500 without the local catch.
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
    _license_cache,
    _proof_negative_cache,
    _proof_not_found_cache,
)
from metrics import TENANT_PROOFS
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

PROOF_METRIC = "artifact_service_tenant_proof_total"
SOURCE_METRIC = "artifact_service_tenant_resolution_total"
TRUSTED_PEER = ("10.42.7.9", 40000)
LICENCE = "lic.abc.def"


def _proof(outcome: str) -> float:
    v = REGISTRY.get_sample_value(PROOF_METRIC, {"outcome": outcome})
    assert v is not None, f"{PROOF_METRIC}{{outcome={outcome!r}}} is not registered"
    return v


def _source(source: str) -> float:
    v = REGISTRY.get_sample_value(SOURCE_METRIC, {"source": source})
    assert v is not None, f"{SOURCE_METRIC}{{source={source!r}}} is not registered"
    return v


def _proof_snapshot() -> dict[str, float]:
    return {o: _proof(o) for o in TENANT_PROOFS}


def _proof_delta(before: dict[str, float]) -> dict[str, float]:
    after = _proof_snapshot()
    return {o: after[o] - before[o] for o in TENANT_PROOFS}


def _only(outcome: str) -> dict[str, float]:
    return {o: (1.0 if o == outcome else 0.0) for o in TENANT_PROOFS}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": request.state.tenant_id,
                "tenant_proof": getattr(request.state, "tenant_proof", None),
                "from_fallback": request.state.tenant_from_fallback,
            }
        )

    return app


async def _get(headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=_make_app(), client=TRUSTED_PEER)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        return await ac.get("/artifacts/echo", headers=headers)


class _introspects_to:  # noqa: N801 - reads as a verb at the call site
    """Stand-in for ``_introspect_license`` returning a fixed payload; records calls."""

    def __init__(self, payload: dict[str, Any] | None) -> None:
        self.payload = payload
        self.calls: list[str] = []

    async def __call__(self, token: str) -> dict[str, Any] | None:
        self.calls.append(token)
        return self.payload


HEADER_ONLY = {"X-Tenant-Id": TEST_TENANT_A}
WITH_LICENCE = {"X-Tenant-Id": TEST_TENANT_A, "Authorization": f"Bearer {LICENCE}"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    _license_cache.clear()
    _proof_negative_cache.clear()
    _proof_not_found_cache.clear()
    monkeypatch.delenv("AUTH_ENABLED", raising=False)


# --- a. proven ---------------------------------------------------------------


@pytest.mark.parametrize("mode", ["observe", "enforce"])
async def test_a_matching_licence_proves_the_header(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, mode: str
) -> None:
    """Proven => admitted in BOTH modes, tagged proven. Since the RM #222 port an
    active Authorization licence is a LICENCE principal, so the source is
    ``licence`` (was ``explicit_header``; measured 0 proven requests live)."""
    tenant_proof_mode(mode)
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    before, src_before = _proof_snapshot(), _source("licence")

    resp = await _get(WITH_LICENCE)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "tenant_id": TEST_TENANT_A,
        "tenant_proof": "explicit_header_proven",
        "from_fallback": False,
    }
    assert fake.calls == [LICENCE]
    assert _proof_delta(before) == _only("explicit_header_proven")
    assert _source("licence") - src_before == 1.0


# --- b. unproven, observe ----------------------------------------------------


async def test_no_authorization_in_observe_is_admitted_unproven(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    tenant_proof_mode("observe")
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    before, src_before = _proof_snapshot(), _source("explicit_header")

    resp = await _get(HEADER_ONLY)

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_A
    assert resp.json()["tenant_proof"] == "explicit_header_unproven"
    assert resp.json()["from_fallback"] is False
    assert fake.calls == [], "no Authorization => nothing to introspect"
    assert _proof_delta(before) == _only("explicit_header_unproven")
    assert _source("explicit_header") - src_before == 1.0


def test_the_default_proof_mode_is_observe(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.config import Settings

    monkeypatch.delenv("AUTH_TENANT_PROOF_MODE", raising=False)
    assert Settings(_env_file=None).auth_tenant_proof_mode == "observe"


# --- c. unproven, enforce ----------------------------------------------------


async def test_no_authorization_in_enforce_is_401_tenant_proof_required(
    tenant_proof_mode,
) -> None:
    tenant_proof_mode("enforce")
    before = _proof_snapshot()

    resp = await _get(HEADER_ONLY)

    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"
    assert resp.json()["error"]["status"] == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert TEST_TENANT_A not in resp.text
    assert _proof_delta(before) == _only("refused_unproven_tenant")


@pytest.mark.parametrize("auth", ["Basic dXNlcjpwYXNz", "Bearer ", "Bearer"])
async def test_a_non_licence_authorization_is_unproven_in_enforce(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, auth: str
) -> None:
    tenant_proof_mode("enforce")
    fake = _introspects_to({"active": True, "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    resp = await _get({"X-Tenant-Id": TEST_TENANT_A, "Authorization": auth})

    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"
    assert fake.calls == []


# --- d. mismatch -------------------------------------------------------------


@pytest.mark.parametrize("mode", ["observe", "enforce"])
async def test_a_licence_for_another_tenant_is_403_in_both_modes(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, mode: str
) -> None:
    """ACTIVE licence for B, header names A. Without the mismatch check this would
    be admitted (the licence is active, so it is not 'unproven')."""
    tenant_proof_mode(mode)
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": True, "tenant_id": TEST_TENANT_B}),
    )
    before = _proof_snapshot()

    resp = await _get(WITH_LICENCE)

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_MISMATCH"
    assert "WWW-Authenticate" not in resp.headers
    assert TEST_TENANT_A not in resp.text and TEST_TENANT_B not in resp.text
    assert _proof_delta(before) == _only("refused_tenant_mismatch")
    assert "explicit_header_mismatch" in TENANT_PROOFS, "retired label stays pre-created"


async def test_an_inactive_bearer_is_introspected_once_then_cached(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    """A revoked/expired licence answers inactive (not token_not_found): the
    second request with the same bearer must not call license-authz again."""
    tenant_proof_mode("observe")
    fake = _introspects_to({"active": False, "reason": "revoked", "tenant_id": TEST_TENANT_A})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    first = await _get(WITH_LICENCE)
    second = await _get(WITH_LICENCE)

    assert first.status_code == 200 and second.status_code == 200
    assert second.json()["tenant_proof"] == "explicit_header_unproven"
    assert fake.calls == [LICENCE], "the inactive answer must be cached"


async def test_an_introspection_outage_is_not_cached(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    """``None`` (license-authz unreachable) must be retried, not remembered as inactive."""
    tenant_proof_mode("observe")
    fake = _introspects_to(None)
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    await _get(WITH_LICENCE)
    await _get(WITH_LICENCE)

    assert fake.calls == [LICENCE, LICENCE]


# --- e. inactive licence -----------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "status", "proof"),
    [("enforce", 401, None), ("observe", 200, "explicit_header_unproven")],
)
async def test_an_inactive_licence_is_unproven(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, mode: str, status: int, proof: str | None
) -> None:
    """The inactive payload names the MATCHING tenant, so dropping the ``active``
    check would turn it into a proof and both cases would fail."""
    tenant_proof_mode(mode)
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": False, "tenant_id": TEST_TENANT_A}),
    )

    resp = await _get(WITH_LICENCE)

    assert resp.status_code == status, resp.text
    if status == 401:
        assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"
    else:
        assert resp.json()["tenant_proof"] == proof


async def test_a_none_introspection_result_is_unproven_in_enforce(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    tenant_proof_mode("enforce")
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(None))
    resp = await _get(WITH_LICENCE)
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"


# --- f. introspection raises -------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "status"),
    [("observe", 200), ("enforce", 401)],
)
async def test_an_introspection_error_is_unproven_never_500(
    monkeypatch: pytest.MonkeyPatch,
    tenant_proof_mode,
    caplog: pytest.LogCaptureFixture,
    mode: str,
    status: int,
) -> None:
    tenant_proof_mode(mode)

    async def _boom(_token: str) -> dict[str, Any] | None:
        raise httpx.ConnectError("license-authz unreachable")

    monkeypatch.setattr(auth_middleware, "_introspect_license", _boom)

    with caplog.at_level("WARNING", logger="auth.middleware"):
        resp = await _get(WITH_LICENCE)

    assert resp.status_code == status, resp.text
    if status == 200:
        assert resp.json()["tenant_proof"] == "explicit_header_unproven"
    else:
        assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"
    assert any("introspection failed" in r.getMessage() for r in caplog.records), caplog.text
    assert LICENCE not in caplog.text, "the licence token must never be logged"


# --- settings ------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["observe", "ENFORCE", " enforce "])
def test_the_proof_mode_reads_the_env(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    from core.config import Settings

    monkeypatch.setenv("AUTH_TENANT_PROOF_MODE", raw)
    assert Settings(_env_file=None).auth_tenant_proof_mode == raw.strip().lower()


def test_an_unknown_proof_mode_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError

    from core.config import Settings

    monkeypatch.setenv("AUTH_TENANT_PROOF_MODE", "off")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("exc", [ValueError("not json"), AttributeError("list has no get")])
async def test_a_malformed_introspection_answer_is_unproven_not_500(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, exc: Exception
) -> None:
    """license-authz answering 200 with a non-JSON / non-object body raises inside
    ``_introspect_license``; under observe that must stay a 200, never a 500."""
    tenant_proof_mode("observe")

    async def _raises(token: str) -> None:
        raise exc

    monkeypatch.setattr(auth_middleware, "_introspect_license", _raises)
    resp = await _get(WITH_LICENCE)

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_proof"] == "explicit_header_unproven"


async def test_token_not_found_is_cached_only_briefly(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    """FR's Keycloak JWT introspects ``token_not_found``: the same bearer must not
    cost a round trip per request, but it lands in the SHORT (10 s) cache, never
    the 60 s one, because a freshly rotated licence briefly answers the same."""
    tenant_proof_mode("observe")
    fake = _introspects_to({"active": False, "reason": "token_not_found"})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)

    await _get(WITH_LICENCE)
    await _get(WITH_LICENCE)
    assert fake.calls == [LICENCE], "token_not_found must be cached (FR cost)"
    assert len(_proof_negative_cache) == 0, "token_not_found must not use the 60 s cache"
    assert _proof_not_found_cache.ttl == 10

    _proof_not_found_cache.clear()  # TTL expiry
    await _get(WITH_LICENCE)
    assert fake.calls == [LICENCE, LICENCE]


async def test_a_non_object_introspection_answer_is_unproven(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    tenant_proof_mode("enforce")
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(["x"]))  # type: ignore[arg-type]
    resp = await _get(WITH_LICENCE)
    assert resp.status_code == 401, resp.text
