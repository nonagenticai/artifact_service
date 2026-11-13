"""art#49: the transaction-local ``app.current_tenant`` GUC (``src/tenant_guc.py``).

Copied from procedure_management ``tests/test_tenant_guc.py`` (pm#94 PR-1).

Pins:

* ``TENANT_RLS_MODE=enforce`` + a bound tenant ⇒ every transaction starts with
  ``app.current_tenant`` = that tenant;
* it is TRANSACTION-local: after COMMIT the same connection reads NULL/'' (a
  session-level set would leak to the next pgbouncer client);
* a mid-request commit re-binds the NEXT transaction (per-transaction, not
  per-session), from the ContextVar as it is NOW;
* mode ``off`` (the default) and "no tenant" set nothing;
* the mode is a validated Settings field: whitespace/case are normalised and an
  unknown value refuses to start (it used to mean ``off`` — a typo disabled
  RLS); the prod value ``enforce`` still binds the GUC;
* the application engine (``core.database.engine``) carries the listener;
* through the real ``AuthMiddleware`` the ContextVar equals
  ``request.state.tenant_id`` on every branch (bypass, licence, trusted header,
  trusted fallback) and is empty again afterwards;
* the startup check classifies the four RLS postures.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

import tenant_guc
from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware
from core.config import Settings, get_settings
from tenant_guc import (
    RLS_FAIL_CLOSED_MODE_OFF,
    RLS_INERT_FOR_THIS_ROLE,
    RLS_NOT_INSTALLED,
    RLS_OK,
    classify_rls_state,
    current_tenant_var,
    register_tenant_guc,
    rls_startup_check,
)
from tests.conftest import TEST_DATABASE_URL, TEST_TENANT_A, TEST_TENANT_B

pytestmark = pytest.mark.unit

GUC_SQL = text("SELECT current_setting('app.current_tenant', true)")


def _set_mode(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    """``tenant_rls_mode()`` reads the cached Settings per call; patch it there."""
    monkeypatch.setattr(get_settings(), "tenant_rls_mode", mode)


@pytest.fixture
def enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_mode(monkeypatch, "enforce")


@pytest.fixture
def bound() -> Iterator[Any]:
    def _bind(tenant: str | None) -> None:
        current_tenant_var.set(tenant)

    yield _bind
    current_tenant_var.set(None)


@pytest.fixture
async def guc_engine(pg_engine) -> AsyncIterator[AsyncEngine]:
    """A real engine on the test database with the listener registered.

    ``pg_engine`` is requested only so the suite's DB-reachability guard counts
    this module; the instrument is its OWN engine, built like the app's.
    """
    eng = create_async_engine(TEST_DATABASE_URL, pool_size=1, max_overflow=0)
    register_tenant_guc(eng)
    try:
        yield eng
    finally:
        await eng.dispose()


async def _guc(conn: Any) -> str | None:
    return (await conn.execute(GUC_SQL)).scalar_one()


def test_the_application_engine_carries_the_listener() -> None:
    from core.database import engine

    assert event.contains(engine.sync_engine, "begin", tenant_guc._bind_tenant_guc)


def test_register_is_idempotent(guc_engine) -> None:
    register_tenant_guc(guc_engine)
    assert event.contains(guc_engine.sync_engine, "begin", tenant_guc._bind_tenant_guc)


def test_the_default_mode_is_off(monkeypatch) -> None:
    monkeypatch.delenv("TENANT_RLS_MODE", raising=False)
    assert Settings(_env_file=None).tenant_rls_mode == "off"


@pytest.mark.parametrize("raw", ["", "  "])
def test_an_empty_or_blank_mode_means_off(monkeypatch, raw) -> None:
    """Same as unset (consistent with RM / tool_registry / PM); never a crash."""
    monkeypatch.setenv("TENANT_RLS_MODE", raw)
    assert Settings(_env_file=None).tenant_rls_mode == "off"


@pytest.mark.parametrize(
    ("raw", "mode"),
    [
        ("off", "off"),
        (" OFF ", "off"),
        ("enforce", "enforce"),
        (" Enforce ", "enforce"),
        ("ENFORCE\n", "enforce"),
    ],
)
def test_whitespace_and_case_are_normalised(monkeypatch, raw, mode) -> None:
    monkeypatch.setenv("TENANT_RLS_MODE", raw)
    assert Settings(_env_file=None).tenant_rls_mode == mode


@pytest.mark.parametrize("raw", ["enforced", "enfroce", "observe", "on", "true", "1"])
def test_an_unknown_mode_refuses_to_start(monkeypatch, raw) -> None:
    """Was: unknown ⇒ ``off``, so a typo silently disabled tenant RLS."""
    monkeypatch.setenv("TENANT_RLS_MODE", raw)
    with pytest.raises(ValidationError, match="tenant_rls_mode"):
        Settings(_env_file=None)


@pytest.mark.parametrize("mode", ["off", "enforce"])
def test_mode_is_read_from_settings_at_call_time(monkeypatch, mode) -> None:
    _set_mode(monkeypatch, mode)
    assert tenant_guc.tenant_rls_mode() == mode


def test_the_app_entrypoint_refuses_to_start_on_a_typo(tmp_path) -> None:
    """The Dockerfile CMD imports ``main:app``; ``main`` builds Settings at import."""
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    env = {**os.environ, "PYTHONPATH": src, "TENANT_RLS_MODE": "enforced"}
    proc = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-c", "import main"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode != 0
    assert "tenant_rls_mode" in proc.stderr, proc.stderr[-2000:]


# --------------------------------------------------------------------------
# The listener on a real engine
# --------------------------------------------------------------------------


async def test_guc_inside_a_transaction_is_the_request_tenant(guc_engine, enforce, bound) -> None:
    bound(TEST_TENANT_A)
    async with guc_engine.begin() as conn:
        assert await _guc(conn) == TEST_TENANT_A


async def test_guc_does_not_survive_commit_on_the_pooled_connection(
    guc_engine, enforce, bound
) -> None:
    """Transaction-local: a session-level set would still read the tenant here —
    which, through a transaction pgbouncer, is the NEXT client's transaction."""
    bound(TEST_TENANT_A)
    async with guc_engine.connect() as conn:
        async with conn.begin():
            assert await _guc(conn) == TEST_TENANT_A
            pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        bound(None)
        async with conn.begin():
            assert (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one() == pid
            assert await _guc(conn) in (None, "")


async def test_a_mid_request_commit_rebinds_the_next_transaction(
    guc_engine, enforce, bound
) -> None:
    bound(TEST_TENANT_A)
    async with AsyncSession(guc_engine) as session:
        first = (await session.execute(text("SELECT txid_current()"))).scalar_one()
        assert await _guc(session) == TEST_TENANT_A
        await session.commit()

        assert await _guc(session) == TEST_TENANT_A
        second = (await session.execute(text("SELECT txid_current()"))).scalar_one()
        assert second != first
        await session.commit()

        bound(TEST_TENANT_B)
        assert await _guc(session) == TEST_TENANT_B
        await session.commit()


async def test_the_prod_value_enforce_from_the_env_binds_the_guc(
    guc_engine, monkeypatch, bound
) -> None:
    """Prod runs ``TENANT_RLS_MODE=enforce``: it must still mean enforce end to end."""
    monkeypatch.setenv("TENANT_RLS_MODE", "enforce")
    _set_mode(monkeypatch, Settings(_env_file=None).tenant_rls_mode)
    bound(TEST_TENANT_A)
    async with guc_engine.begin() as conn:
        assert await _guc(conn) == TEST_TENANT_A


async def test_mode_off_sets_nothing(guc_engine, monkeypatch, bound) -> None:
    _set_mode(monkeypatch, "off")
    bound(TEST_TENANT_A)
    async with guc_engine.begin() as conn:
        assert await _guc(conn) in (None, "")


async def test_no_tenant_sets_nothing(guc_engine, enforce, bound) -> None:
    """Never a default tenant: unbound ⇒ unset ⇒ RLS fails closed."""
    bound(None)
    async with guc_engine.begin() as conn:
        assert await _guc(conn) in (None, "")


# --------------------------------------------------------------------------
# AuthMiddleware binds the ContextVar in lock-step with request.state.tenant_id
# --------------------------------------------------------------------------


def _request(path: str, headers: dict[str, str], client_host: str) -> MagicMock:
    req = MagicMock()
    req.url.path = path
    req.headers = headers
    req.client.host = client_host
    req.state = MagicMock(spec=[])
    return req


def _capturing_call_next(seen: dict[str, Any]) -> AsyncMock:
    async def _call_next(request: Any) -> MagicMock:
        seen["var"] = current_tenant_var.get()
        seen["state"] = request.state.tenant_id
        return MagicMock()

    return AsyncMock(side_effect=_call_next)


@pytest.mark.parametrize(
    ("bypass", "headers", "host", "licence", "expected"),
    [
        (True, {"X-Tenant-Id": TEST_TENANT_A}, "8.8.8.8", None, TEST_TENANT_A),
        (True, {}, "8.8.8.8", None, DEFAULT_TENANT_ID),
        (False, {"X-Tenant-Id": "Bearer tok"}, "8.8.8.8", TEST_TENANT_B, TEST_TENANT_B),
        (False, {"X-Tenant-Id": TEST_TENANT_A}, "10.42.0.9", None, TEST_TENANT_A),
        (False, {}, "10.42.0.9", None, DEFAULT_TENANT_ID),
    ],
    ids=["bypass-header", "bypass-default", "licence", "trusted-header", "trusted-fallback"],
)
async def test_the_contextvar_equals_request_state_on_every_branch(
    monkeypatch, tenant_fallback_mode, bypass, headers, host, licence, expected
) -> None:
    # observe: the bypass-default / trusted-fallback cases pin the absent-header
    # fallback, which enforce (the default) refuses — see the test below.
    tenant_fallback_mode("observe")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    mw = AuthMiddleware(MagicMock(), bypass_auth=bypass)
    seen: dict[str, Any] = {}
    request = _request("/api/artifacts/x", headers, host)
    current_tenant_var.set(None)
    with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as intro:
        intro.return_value = {"active": True, "tenant_id": licence} if licence else None
        await mw.dispatch(request, _capturing_call_next(seen))
    assert seen == {"var": expected, "state": expected}
    assert current_tenant_var.get() is None, "the ContextVar must be reset after the request"


@pytest.mark.parametrize(
    ("bypass", "host"),
    [(True, "8.8.8.8"), (False, "10.42.0.9")],
    ids=["bypass-no-header", "trusted-no-header"],
)
async def test_enforce_refuses_without_ever_binding_a_tenant(monkeypatch, bypass, host) -> None:
    """Default mode: the header-less request is 401 and the GUC source stays EMPTY —
    neither request.state.tenant_id nor the ContextVar is ever set."""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    mw = AuthMiddleware(MagicMock(), bypass_auth=bypass)
    seen: dict[str, Any] = {}
    request = _request("/api/artifacts/x", {}, host)
    current_tenant_var.set(None)
    response = await mw.dispatch(request, _capturing_call_next(seen))
    assert response.status_code == 401
    assert seen == {}, "the route ran on a header-less request"
    assert not hasattr(request.state, "tenant_id")
    assert current_tenant_var.get() is None


async def test_a_stale_tenant_in_the_context_is_cleared_for_an_unauthenticated_request() -> None:
    """dispatch starts every request with an EMPTY ContextVar."""
    mw = AuthMiddleware(MagicMock(), bypass_auth=False)
    seen: dict[str, Any] = {}

    async def _public(request: Any) -> MagicMock:
        seen["var"] = current_tenant_var.get()
        return MagicMock()

    current_tenant_var.set(TEST_TENANT_A)
    try:
        await mw.dispatch(_request("/api/health", {}, "8.8.8.8"), AsyncMock(side_effect=_public))
        assert seen["var"] is None
        assert current_tenant_var.get() == TEST_TENANT_A  # reset restores the outer value
    finally:
        current_tenant_var.set(None)


# --------------------------------------------------------------------------
# Startup check
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rls", "owner", "bypass", "mode", "verdict"),
    [
        (False, False, False, "enforce", RLS_NOT_INSTALLED),
        (None, None, None, "enforce", RLS_NOT_INSTALLED),
        (True, True, False, "off", RLS_INERT_FOR_THIS_ROLE),
        (True, False, True, "enforce", RLS_INERT_FOR_THIS_ROLE),
        (True, False, False, "off", RLS_FAIL_CLOSED_MODE_OFF),
        (True, False, False, "enforce", RLS_OK),
    ],
)
def test_classify_rls_state(rls, owner, bypass, mode, verdict) -> None:
    assert classify_rls_state(rls, owner, bypass, mode) == verdict


async def test_the_startup_check_reads_the_real_catalog(guc_engine, monkeypatch) -> None:
    """conftest's schema has no policies and the test role owns the tables."""
    _set_mode(monkeypatch, "off")
    log = logging.getLogger("test.rls")
    assert await rls_startup_check(guc_engine, log) == RLS_NOT_INSTALLED


async def test_the_startup_check_is_fail_soft() -> None:
    eng = create_async_engine("postgresql+psycopg://u:p@127.0.0.1:1/none")
    try:
        verdict = await rls_startup_check(eng, logging.getLogger("test.rls"), timeout_s=5)
    finally:
        await eng.dispose()
    assert verdict == tenant_guc.RLS_CHECK_FAILED
