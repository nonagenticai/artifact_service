"""Request-tenant ContextVar + the transaction-local ``app.current_tenant`` GUC (art#49).

The application half of the RLS backstop (the database half is alembic
``20261003_0001``). INERT by default: with ``TENANT_RLS_MODE`` unset or ``off``
the listener returns before touching the connection. With
``TENANT_RLS_MODE=enforce`` the only effect is that every transaction starts with
``SELECT set_config('app.current_tenant', <tenant>, true)``.

Copied from procedure_management ``src/tenant_guc.py`` (pm#94 PR-1), itself an
inline equivalent of ``kag_common.database.rls.register_tenant_guc``:

* ``begin`` listener on the engine ⇒ EVERY transaction is bound, including the
  ones a route opens after committing mid-request. A per-session bind would
  cover only the first transaction of the session.
* ``set_config(…, is_local => true)`` ⇒ transaction-scoped. ⛔ NEVER a
  session-level SET: this service reaches postgres through the
  TRANSACTION-pooling pgbouncer, where a session GUC survives into the NEXT
  client's transaction.
* No tenant bound ⇒ nothing is set ⇒ RLS fail-closes to 0 rows. Deliberate:
  never substitute a default tenant here.
* The mode is read from ``get_settings()`` at CALL time so a test can move it.
  Settings validates it at startup (Literal: off|enforce; built at import of
  ``main``): an unknown spelling refuses to start instead of silently meaning
  ``off``.

The tenant comes ONLY from ``current_tenant_var``, which ``AuthMiddleware`` sets
in lock-step with ``request.state.tenant_id`` — never from a header read here.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

from core.config import get_settings

TENANT_GUC = "app.current_tenant"
TENANT_RLS_MODE_OFF = "off"
TENANT_RLS_MODE_ENFORCE = "enforce"

#: The authenticated request's tenant. Set by ``AuthMiddleware`` wherever it
#: assigns ``request.state.tenant_id``; reset when the request ends.
current_tenant_var: ContextVar[str | None] = ContextVar("art_current_tenant", default=None)

_SET_GUC_SQL = "SELECT set_config('app.current_tenant', %s, true)"


def tenant_rls_mode() -> str:
    """``TENANT_RLS_MODE`` from Settings at call time (validated off|enforce at startup)."""
    return get_settings().tenant_rls_mode


def _bind_tenant_guc(conn: Any) -> None:
    """``begin`` listener: bind the request tenant for this transaction only."""
    if tenant_rls_mode() != TENANT_RLS_MODE_ENFORCE:
        return
    tenant = current_tenant_var.get()
    if not tenant:
        return
    conn.exec_driver_sql(_SET_GUC_SQL, (str(tenant),))


def register_tenant_guc(engine: AsyncEngine) -> None:
    """Attach the ``begin`` listener to ``engine`` (idempotent)."""
    sync_engine = engine.sync_engine
    if not event.contains(sync_engine, "begin", _bind_tenant_guc):
        event.listen(sync_engine, "begin", _bind_tenant_guc)


#: The one catalog read behind :func:`rls_startup_check`. Reads only pg_catalog,
#: so it is unaffected by any policy and needs no tenant.
_STARTUP_CHECK_SQL = """
SELECT c.relrowsecurity,
       pg_has_role(current_user, c.relowner, 'USAGE') AS acts_as_owner,
       r.rolsuper OR r.rolbypassrls AS bypasses
FROM pg_class c, pg_roles r
WHERE c.oid = to_regclass('public.artifacts') AND r.rolname = current_user
"""

#: Verdicts :func:`rls_startup_check` can return.
RLS_OK = "ok"
RLS_NOT_INSTALLED = "not_installed"
RLS_INERT_FOR_THIS_ROLE = "inert_for_this_role"
RLS_FAIL_CLOSED_MODE_OFF = "fail_closed_mode_off"
RLS_CHECK_FAILED = "check_failed"


def classify_rls_state(
    rls_enabled: bool | None, acts_as_owner: bool | None, bypasses: bool | None, mode: str
) -> str:
    """Pure verdict over the catalog facts (unit-testable without a database)."""
    if not rls_enabled:
        return RLS_NOT_INSTALLED
    if acts_as_owner or bypasses:
        return RLS_INERT_FOR_THIS_ROLE
    if mode != TENANT_RLS_MODE_ENFORCE:
        return RLS_FAIL_CLOSED_MODE_OFF
    return RLS_OK


async def rls_startup_check(engine: AsyncEngine, logger: Any, timeout_s: float = 5.0) -> str:
    """Log, once at startup, whether this pod's RLS posture can serve requests.

    The dangerous combination is policies present + runtime role subject to them
    + ``TENANT_RLS_MODE`` not ``enforce``: nothing binds the GUC, so every read
    returns 0 rows and every write fails WITH CHECK — with no other signal. That
    is logged CRITICAL. A role that owns the table or bypasses RLS makes the
    policies inert (WARNING). Fail-soft: a diagnostic never stops startup.
    """
    mode = tenant_rls_mode()

    async def _read() -> Any:
        async with engine.connect() as conn:
            return (await conn.exec_driver_sql(_STARTUP_CHECK_SQL)).first()

    try:
        # Bounded: an unreachable database must not stall startup here.
        row = await asyncio.wait_for(_read(), timeout=timeout_s)
        rls_enabled, acts_as_owner, bypasses = tuple(row) if row else (None, None, None)
        verdict = classify_rls_state(rls_enabled, acts_as_owner, bypasses, mode)
    except Exception as exc:  # noqa: BLE001 - never let a diagnostic stop startup
        logger.warning("rls.startup_check status=%s error=%s", RLS_CHECK_FAILED, exc)
        return RLS_CHECK_FAILED
    if verdict == RLS_FAIL_CLOSED_MODE_OFF:
        logger.critical(
            "rls.startup_check status=%s mode=%s: RLS is enabled and this role is subject "
            "to it, but TENANT_RLS_MODE is not 'enforce' — every request will read 0 rows",
            verdict,
            mode,
        )
    elif verdict == RLS_INERT_FOR_THIS_ROLE:
        logger.warning(
            "rls.startup_check status=%s mode=%s: the connecting role owns public.artifacts "
            "or bypasses RLS, so the tenant policies do not bind it",
            verdict,
            mode,
        )
    else:
        logger.info("rls.startup_check status=%s mode=%s", verdict, mode)
    return verdict
