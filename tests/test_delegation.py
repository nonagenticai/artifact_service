"""Effective-tenant delegation + the ``Authorization`` licence carrier (RM #222/#223 port).

* ``AUTH_DELEGATING_SUBJECTS`` (empty default): an introspected licence SUBJECT on
  it may name the tenant it acts for in ``X-Effective-Tenant-Id`` (fr's
  ``tenantBearerEnvVar`` shape: ``X-Tenant-Id: Bearer <svc licence>``), or in a
  plain ``X-Tenant-Id`` beside an ``Authorization`` licence.
* Anyone else naming a DIFFERENT tenant there: 403, never served as its own tenant.
* The licence's own tenant is ``tenant_id``, never ``subject_id``.
* fr's ``streamArtifact`` (``Authorization: Bearer <Keycloak JWT>`` + bare uuid
  ``X-Tenant-Id`` from a trusted peer) is byte-identical under observe and a hard
  401 only under ``AUTH_TENANT_PROOF_MODE=enforce``.

``_introspect_license`` is monkeypatched. Every positive asserts the tenant AND the
RLS ContextVar, so a mutant that binds one but not the other fails.
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
from metrics import EFFECTIVE_TENANT_OUTCOMES
from tenant_guc import current_tenant_var
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

TRUSTED_PEER = ("10.42.7.9", 40000)
INGRESS_PEER = ("169.254.7.127", 44964)
SVC_LICENCE = "svc.fr.licence"
KEYCLOAK_JWT = "keycloak-user-jwt"  # value irrelevant: introspection is mocked
FR_SUBJECT = "019ffe9f-31fd-70da-b3c5-f921f7290b01"  # svc-fr-backend
OTHER_SUBJECT = "0198c2d4-7a10-7aaa-8bbb-000000000999"
# fr's service tenant: neither of the customer tenants used below.
FR_TENANT = "0198c2d4-7a10-7c3e-8b91-00000000f0f0"
TENANT_C = "0198c2d4-7a10-7c3e-8b91-00000000c0c0"
END_USER = "kc-user-sub-1234"

EFF_METRIC = "artifact_service_effective_tenant_total"
SOURCE_METRIC = "artifact_service_tenant_resolution_total"
PROOF_METRIC = "artifact_service_tenant_proof_total"

FR_LICENCE = {"active": True, "tenant_id": FR_TENANT, "subject_id": FR_SUBJECT}


def _eff(outcome: str) -> float:
    v = REGISTRY.get_sample_value(EFF_METRIC, {"outcome": outcome})
    assert v is not None, f"{EFF_METRIC}{{outcome={outcome!r}}} is not registered"
    return v


def _source(source: str) -> float:
    v = REGISTRY.get_sample_value(SOURCE_METRIC, {"source": source})
    assert v is not None, f"{SOURCE_METRIC}{{source={source!r}}} is not registered"
    return v


def _proof(outcome: str) -> float:
    v = REGISTRY.get_sample_value(PROOF_METRIC, {"outcome": outcome})
    assert v is not None, f"{PROOF_METRIC}{{outcome={outcome!r}}} is not registered"
    return v


def _eff_snapshot() -> dict[str, float]:
    return {o: _eff(o) for o in EFFECTIVE_TENANT_OUTCOMES}


def _eff_delta(before: dict[str, float]) -> dict[str, float]:
    after = _eff_snapshot()
    return {o: after[o] - before[o] for o in EFFECTIVE_TENANT_OUTCOMES}


def _only(outcome: str | None) -> dict[str, float]:
    return {o: (1.0 if o == outcome else 0.0) for o in EFFECTIVE_TENANT_OUTCOMES}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": request.state.tenant_id,
                "guc_tenant": current_tenant_var.get(),
                "subject_id": request.state.subject_id,
                "delegated": getattr(request.state, "tenant_delegated", None),
                "delegating_subject": getattr(request.state, "delegating_subject", None),
                "tenant_proof": getattr(request.state, "tenant_proof", None),
                "from_fallback": request.state.tenant_from_fallback,
            }
        )

    return app


async def _get(headers: dict[str, str], peer: tuple[str, int] = TRUSTED_PEER) -> httpx.Response:
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


@pytest.fixture
def delegating(monkeypatch: pytest.MonkeyPatch):
    """Set ``AUTH_DELEGATING_SUBJECTS`` on the live Settings for ONE test."""
    from core.config import get_settings

    def _set(*subjects: str) -> None:
        monkeypatch.setattr(get_settings(), "auth_delegating_subjects", list(subjects))

    return _set


def _fr_delegated_headers(effective: str) -> dict[str, str]:
    """Exactly what fr's ``tenantBearerEnvVar`` sends."""
    return {
        "X-Tenant-Id": f"Bearer {SVC_LICENCE}",
        "X-Effective-Tenant-Id": effective,
        "X-Subject-Id": END_USER,
    }


# --- 1. delegation via X-Tenant-Id: Bearer + X-Effective-Tenant-Id -------------


@pytest.mark.parametrize("mode", ["observe", "enforce"])
@pytest.mark.parametrize("peer", [TRUSTED_PEER, INGRESS_PEER])
async def test_a_delegating_subject_is_scoped_to_the_effective_tenant(
    monkeypatch: pytest.MonkeyPatch, delegating, tenant_proof_mode, mode: str, peer
) -> None:
    tenant_proof_mode(mode)
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))
    before, src_before = _eff_snapshot(), _source("licence_delegated")

    resp = await _get(_fr_delegated_headers(TEST_TENANT_B), peer)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "tenant_id": TEST_TENANT_B,
        "guc_tenant": TEST_TENANT_B,
        "subject_id": END_USER,
        "delegated": True,
        "delegating_subject": FR_SUBJECT,
        "tenant_proof": None,
        "from_fallback": False,
    }
    assert _eff_delta(before) == _only("delegated")
    assert _source("licence_delegated") - src_before == 1.0


async def test_an_effective_tenant_is_normalised(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get(_fr_delegated_headers(f"  {TEST_TENANT_B.upper()} "))

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_B


async def test_the_allowlist_is_keyed_on_the_introspected_subject_uppercase_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Settings canonicalises entries; an uppercase subject from the wire config
    still matches the introspected (lowercase) subject."""
    from core.config import Settings, get_settings

    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", FR_SUBJECT.upper())
    subjects = Settings(_env_file=None).auth_delegating_subjects
    monkeypatch.setattr(get_settings(), "auth_delegating_subjects", subjects)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get(_fr_delegated_headers(TEST_TENANT_B))

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_B


# --- 2. non-delegating caller naming another tenant -> 403 ---------------------


@pytest.mark.parametrize("allowlist", [(), (OTHER_SUBJECT,)])
@pytest.mark.parametrize("mode", ["observe", "enforce"])
async def test_a_non_delegating_subject_naming_another_tenant_is_403(
    monkeypatch: pytest.MonkeyPatch, delegating, tenant_proof_mode, allowlist, mode: str
) -> None:
    """Empty allowlist (the shipped default) and an allowlist naming someone else
    both refuse — and never serve fr's OWN tenant instead (silent downgrade)."""
    tenant_proof_mode(mode)
    delegating(*allowlist)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))
    before = _eff_snapshot()

    resp = await _get(_fr_delegated_headers(TEST_TENANT_B))

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "EFFECTIVE_TENANT_FORBIDDEN"
    assert TEST_TENANT_B not in resp.text and FR_TENANT not in resp.text
    assert _eff_delta(before) == _only("refused_not_delegating")


async def test_the_allowlist_is_never_matched_on_a_wire_subject(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    """``X-Subject-Id`` naming the delegator does not make a caller one."""
    delegating(FR_SUBJECT)
    customer = {"active": True, "tenant_id": TEST_TENANT_A, "subject_id": OTHER_SUBJECT}
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(customer))

    resp = await _get({**_fr_delegated_headers(TEST_TENANT_B), "X-Subject-Id": FR_SUBJECT})

    assert resp.status_code == 403, resp.text


async def test_an_effective_tenant_equal_to_the_licence_is_a_no_op(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-delegating caller stamping its OWN tenant is admitted, uncounted."""
    customer = {"active": True, "tenant_id": TEST_TENANT_A, "subject_id": OTHER_SUBJECT}
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(customer))
    before, lic_before = _eff_snapshot(), _source("licence")

    resp = await _get(_fr_delegated_headers(TEST_TENANT_A))

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_A
    assert resp.json()["delegated"] is False
    assert resp.json()["subject_id"] == OTHER_SUBJECT, "licence subject, never the wire's"
    assert _eff_delta(before) == _only(None)
    assert _source("licence") - lic_before == 1.0


@pytest.mark.parametrize("bad", ["n8n-dev", "Bearer x", "00000000-0000"])
async def test_a_malformed_effective_tenant_is_400_even_for_a_delegator(
    monkeypatch: pytest.MonkeyPatch, delegating, bad: str
) -> None:
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))
    before = _eff_snapshot()

    resp = await _get(_fr_delegated_headers(bad))

    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"
    assert bad not in resp.text
    assert _eff_delta(before) == _only("refused_malformed")


# --- 3. the tenant comes from tenant_id, never subject_id ----------------------


async def test_a_delegator_without_an_effective_tenant_is_its_own_tenant_not_its_subject(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get({"X-Tenant-Id": f"Bearer {SVC_LICENCE}"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == FR_TENANT
    assert resp.json()["tenant_id"] != FR_SUBJECT
    assert resp.json()["delegated"] is False


# --- 4. Authorization carrier (RM #222) ----------------------------------------


async def test_authorization_licence_plus_plain_header_delegates_for_an_allowlisted_subject(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    delegating(FR_SUBJECT)
    fake = _introspects_to(FR_LICENCE)
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    proof_before = _proof("explicit_header_delegated")

    resp = await _get(
        {
            "Authorization": f"Bearer {SVC_LICENCE}",
            "X-Tenant-Id": TEST_TENANT_B,
            "X-Subject-Id": END_USER,
        }
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["tenant_id"], body["guc_tenant"], body["delegated"]) == (
        TEST_TENANT_B,
        TEST_TENANT_B,
        True,
    )
    assert body["tenant_proof"] == "explicit_header_delegated"
    assert _proof("explicit_header_delegated") - proof_before == 1.0
    assert fake.calls == [SVC_LICENCE]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
async def test_authorization_licence_plus_plain_header_for_another_tenant_is_403(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, mode: str
) -> None:
    """Not delegating: the plain header must be the licence tenant. Refused in
    BOTH modes, and never answered as the licence's own tenant."""
    tenant_proof_mode(mode)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get({"Authorization": f"Bearer {SVC_LICENCE}", "X-Tenant-Id": TEST_TENANT_B})

    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_MISMATCH"


async def test_a_delegator_naming_a_third_tenant_in_the_plain_header_is_403(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    """Plain X-Tenant-Id = C, X-Effective-Tenant-Id = B, licence = fr: contradictory."""
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get(
        {
            "Authorization": f"Bearer {SVC_LICENCE}",
            "X-Tenant-Id": TENANT_C,
            "X-Effective-Tenant-Id": TEST_TENANT_B,
        }
    )

    assert resp.status_code == 403, resp.text


async def test_a_delegator_behind_the_gateway_uses_the_effective_tenant(
    monkeypatch: pytest.MonkeyPatch, delegating
) -> None:
    """Gateway injects the licence's own tenant as the plain header; the effective
    header still selects the customer."""
    delegating(FR_SUBJECT)
    monkeypatch.setattr(auth_middleware, "_introspect_license", _introspects_to(FR_LICENCE))

    resp = await _get(
        {
            "Authorization": f"Bearer {SVC_LICENCE}",
            "X-Tenant-Id": FR_TENANT,
            "X-Effective-Tenant-Id": TEST_TENANT_B,
        },
        INGRESS_PEER,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_B


# --- 5. fr streamArtifact: Keycloak JWT in Authorization + bare X-Tenant-Id -----


STREAM_HEADERS = {
    "Authorization": f"Bearer {KEYCLOAK_JWT}",
    "X-Tenant-Id": TEST_TENANT_A,
    "X-Subject-Id": END_USER,
}


async def test_stream_artifact_shape_is_unchanged_under_observe(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, delegating
) -> None:
    """Exactly what it was before the port: admitted under the header tenant,
    subject from X-Subject-Id, counted unproven — even with delegation armed."""
    tenant_proof_mode("observe")
    delegating(FR_SUBJECT)
    fake = _introspects_to({"active": False, "reason": "token_not_found"})
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    unproven_before, hdr_before = _proof("explicit_header_unproven"), _source("explicit_header")

    first = await _get(STREAM_HEADERS)
    second = await _get(STREAM_HEADERS)

    for resp in (first, second):
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "tenant_id": TEST_TENANT_A,
            "guc_tenant": TEST_TENANT_A,
            "subject_id": END_USER,
            "delegated": None,
            "delegating_subject": None,
            "tenant_proof": "explicit_header_unproven",
            "from_fallback": False,
        }
    assert _proof("explicit_header_unproven") - unproven_before == 2.0
    assert _source("explicit_header") - hdr_before == 2.0
    assert fake.calls == [KEYCLOAK_JWT], "token_not_found stays on the short cache"


async def test_stream_artifact_shape_is_a_hard_401_under_enforce(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode
) -> None:
    tenant_proof_mode("enforce")
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": False, "reason": "token_not_found"}),
    )

    resp = await _get(STREAM_HEADERS)

    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "TENANT_PROOF_REQUIRED"


async def test_a_jwt_without_a_tenant_header_is_401_under_enforce_not_the_default_tenant(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, tenant_fallback_mode
) -> None:
    """With the absent-header fallback in observe (break-glass), a JWT carrier
    must still not land in DEFAULT_TENANT_ID under proof enforce."""
    tenant_proof_mode("enforce")
    tenant_fallback_mode("observe")
    monkeypatch.setattr(
        auth_middleware,
        "_introspect_license",
        _introspects_to({"active": False, "reason": "token_not_found"}),
    )

    resp = await _get({"Authorization": f"Bearer {KEYCLOAK_JWT}"})

    assert resp.status_code == 401, resp.text


# --- 6. bare-tenant callers: identity unchanged in observe ---------------------


async def test_a_bare_tenant_caller_ignores_effective_tenant_and_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tenant_proof_mode, delegating
) -> None:
    """Today's 121/day: no credential at all. Delegation needs an introspected
    subject, so X-Effective-Tenant-Id is not read and nothing is introspected."""
    tenant_proof_mode("observe")
    delegating(FR_SUBJECT)
    fake = _introspects_to(FR_LICENCE)
    monkeypatch.setattr(auth_middleware, "_introspect_license", fake)
    before = _eff_snapshot()

    resp = await _get(
        {"X-Tenant-Id": TEST_TENANT_A, "X-Effective-Tenant-Id": TEST_TENANT_B, "X-Subject-Id": "u"}
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant_id"] == TEST_TENANT_A
    assert resp.json()["subject_id"] == "u"
    assert resp.json()["tenant_proof"] == "explicit_header_unproven"
    assert fake.calls == []
    assert _eff_delta(before) == _only(None)


# --- 7. settings -----------------------------------------------------------------


def test_delegation_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.config import Settings

    monkeypatch.delenv("AUTH_DELEGATING_SUBJECTS", raising=False)
    assert Settings(_env_file=None).auth_delegating_subjects == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        (f" {FR_SUBJECT} , {OTHER_SUBJECT.upper()} ", [FR_SUBJECT, OTHER_SUBJECT]),
        (f'["{FR_SUBJECT}"]', [FR_SUBJECT]),
    ],
)
def test_delegating_subjects_parse(monkeypatch: pytest.MonkeyPatch, raw: str, expected) -> None:
    from core.config import Settings

    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", raw)
    assert Settings(_env_file=None).auth_delegating_subjects == expected


@pytest.mark.parametrize("raw", ["svc-fr-backend", f"{FR_SUBJECT},nope"])
def test_a_non_uuid_delegating_subject_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    from pydantic import ValidationError

    from core.config import Settings

    monkeypatch.setenv("AUTH_DELEGATING_SUBJECTS", raw)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
