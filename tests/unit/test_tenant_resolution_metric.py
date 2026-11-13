"""``artifact_service_tenant_resolution_total{source}`` — where each tenant came from.

D3 gate 1 (TENANCY_AND_IMPROVEMENT.md §4.3): the no-header fallback to
``DEFAULT_TENANT_ID`` may only be closed once Prometheus can show how often it
fires. These tests pin that:

* every admitted request increments EXACTLY one ``source`` child, once;
* the ``request.state.tenant_from_fallback`` tag and the metric agree;
* rejected requests (400 / 401) count nothing — EXCEPT the header-less 401
  under ``AUTH_TENANT_FALLBACK_MODE=enforce``, counted as
  ``refused_missing_tenant``;
* the per-source check is RED when the increment is removed (mutation control).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import REGISTRY

import auth.middleware as auth_middleware
from auth.middleware import AuthMiddleware, _license_cache
from metrics import TENANT_SOURCES
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

METRIC = "artifact_service_tenant_resolution_total"
#: Outside every TRUSTED_CIDRS default (TEST-NET-3), so auth is really exercised.
UNTRUSTED_PEER = ("203.0.113.7", 40000)
TRUSTED_PEER = ("10.42.7.9", 40000)


def _value(source: str) -> float:
    v = REGISTRY.get_sample_value(METRIC, {"source": source})
    assert v is not None, f"{METRIC}{{source={source!r}}} is not registered"
    return v


def _snapshot() -> dict[str, float]:
    return {s: _value(s) for s in TENANT_SOURCES}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": request.state.tenant_id,
                "from_fallback": request.state.tenant_from_fallback,
            }
        )

    return app


async def _get(
    headers: dict[str, str] | None = None,
    peer: tuple[str, int] = TRUSTED_PEER,
) -> httpx.Response:
    transport = httpx.ASGITransport(app=_make_app(), client=peer)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        return await ac.get("/artifacts/echo", headers=headers or {})


async def _fake_introspect(_token: str) -> dict[str, Any]:
    return {"active": True, "tenant_id": TEST_TENANT_A, "subject_id": TEST_TENANT_B}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch, tenant_fallback_mode) -> None:
    _license_cache.clear()
    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake_introspect)
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    # This file pins the `fallback_default` source, which only exists under the
    # observe break-glass. The enforce (default) outcome is pinned separately
    # below, each test setting "enforce" explicitly.
    tenant_fallback_mode("observe")


#: (case id, AUTH_ENABLED value or None, request headers, expected source)
CASES: list[tuple[str, str | None, dict[str, str], str]] = [
    ("trusted-no-header", None, {}, "fallback_default"),
    ("trusted-explicit-header", None, {"X-Tenant-Id": TEST_TENANT_A}, "explicit_header"),
    ("licence-token", None, {"X-Tenant-Id": "Bearer abc.def.ghi"}, "licence"),
    ("bypass-no-header", "false", {}, "fallback_default"),
    ("bypass-explicit-header", "false", {"X-Tenant-Id": TEST_TENANT_A}, "explicit_header"),
]


async def _assert_one_increment(
    monkeypatch: pytest.MonkeyPatch,
    auth_enabled: str | None,
    headers: dict[str, str],
    expected: str,
) -> None:
    """One admitted request => +1 on ``expected``, +0 on every other source."""
    if auth_enabled is not None:
        monkeypatch.setenv("AUTH_ENABLED", auth_enabled)
    before = _snapshot()
    resp = await _get(headers)
    assert resp.status_code == 200, resp.text
    after = _snapshot()
    delta = {s: after[s] - before[s] for s in TENANT_SOURCES}
    assert delta == {s: (1.0 if s == expected else 0.0) for s in TENANT_SOURCES}, delta
    # The route-facing source tag and the metric are derived from one value.
    assert resp.json()["from_fallback"] is (expected == "fallback_default")


@pytest.mark.parametrize(
    ("auth_enabled", "headers", "expected"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
async def test_each_source_increments_its_label_once_per_request(
    monkeypatch: pytest.MonkeyPatch,
    auth_enabled: str | None,
    headers: dict[str, str],
    expected: str,
) -> None:
    await _assert_one_increment(monkeypatch, auth_enabled, headers, expected)


async def test_two_requests_count_two() -> None:
    before = _value("fallback_default")
    await _get()
    await _get()
    assert _value("fallback_default") - before == 2.0


@pytest.mark.parametrize(
    ("headers", "peer"),
    [
        ({"X-Tenant-Id": "n8n-dev"}, TRUSTED_PEER),  # 400: a name is not a tenant id
        ({"X-Tenant-Id": ""}, TRUSTED_PEER),  # 400: empty is not "absent"
        ({}, UNTRUSTED_PEER),  # 401: no token, untrusted peer
    ],
    ids=["bad-header-400", "empty-header-400", "untrusted-no-token-401"],
)
async def test_rejected_requests_count_nothing(
    headers: dict[str, str], peer: tuple[str, int]
) -> None:
    before = _snapshot()
    resp = await _get(headers, peer)
    assert resp.status_code in (400, 401), resp.text
    assert _snapshot() == before


@pytest.mark.parametrize("auth_enabled", [None, "false"], ids=["trusted", "bypass"])
async def test_enforce_counts_a_header_less_request_as_refused_missing_tenant(
    monkeypatch: pytest.MonkeyPatch,
    tenant_fallback_mode,
    auth_enabled: str | None,
) -> None:
    """Default mode: no header => 401 TENANT_REQUIRED and EXACTLY +1 on
    ``refused_missing_tenant`` — +0 on ``fallback_default`` and everything else."""
    tenant_fallback_mode("enforce")
    if auth_enabled is not None:
        monkeypatch.setenv("AUTH_ENABLED", auth_enabled)
    before = _snapshot()
    resp = await _get({})
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"]["code"] == "TENANT_REQUIRED"
    after = _snapshot()
    delta = {s: after[s] - before[s] for s in TENANT_SOURCES}
    assert delta == {s: (1.0 if s == "refused_missing_tenant" else 0.0) for s in TENANT_SOURCES}


async def test_enforce_still_admits_an_explicit_header(tenant_fallback_mode) -> None:
    """Control: enforce refuses the ABSENT header only — a uuid header is admitted
    and counted as explicit_header, not as a refusal."""
    tenant_fallback_mode("enforce")
    before = _value("refused_missing_tenant")
    resp = await _get({"X-Tenant-Id": TEST_TENANT_A})
    assert resp.status_code == 200, resp.text
    assert _value("refused_missing_tenant") == before


async def test_enforce_refusal_count_goes_red_without_the_increment(
    monkeypatch: pytest.MonkeyPatch, tenant_fallback_mode
) -> None:
    """MUTATION CONTROL for the refusal counter, same shape as the one below."""
    tenant_fallback_mode("enforce")
    noop: Callable[[str], None] = lambda _source: None  # noqa: E731
    monkeypatch.setattr(auth_middleware, "record_tenant_source", noop)
    before = _value("refused_missing_tenant")
    resp = await _get({})
    assert resp.status_code == 401
    assert _value("refused_missing_tenant") == before


@pytest.mark.parametrize(("case_id", "auth_enabled", "headers", "expected"), CASES)
async def test_removing_the_increment_turns_the_per_source_check_red(
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
    auth_enabled: str | None,
    headers: dict[str, str],
    expected: str,
) -> None:
    """MUTATION CONTROL: with ``record_tenant_source`` stubbed out of the
    middleware, the exact check the real test uses must FAIL for every case —
    otherwise that test could pass with no counting at all."""
    noop: Callable[[str], None] = lambda _source: None  # noqa: E731
    monkeypatch.setattr(auth_middleware, "record_tenant_source", noop)
    with pytest.raises(AssertionError):
        await _assert_one_increment(monkeypatch, auth_enabled, headers, expected)
