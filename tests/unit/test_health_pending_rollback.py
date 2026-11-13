"""Regression tests for the live ``PendingRollbackError`` on the health probes.

The incident
------------
The ``artifacts`` pod logged::

    Readiness check timed out
    Database session error, rolling back
    ...
      File "/app/src/core/database.py", line 45, in get_db
        await session.commit()
    sqlalchemy.exc.PendingRollbackError: Can't reconnect until invalid
    transaction is rolled back.

``GET /health/ready`` is the endpoint. It is in
``middleware/logging.py::_SKIP_LOG_PATHS``, which is exactly why the traceback
carries no "Request started" line beside it (every logged request in the window
is matched by a "Request completed"), and ``Readiness check timed out``
(``routes/health.py``) is logged immediately before it.

The chain: ``asyncio.wait_for`` cancels the in-flight ``db.execute``, SQLAlchemy
**invalidates the connection**, the probe SWALLOWS the timeout and returns its
503 *normally*, and ``get_db``'s post-yield ``await session.commit()`` then hits
``_revalidate_connection`` -> ``_invalid_transaction``. ``get_db`` re-raises, so
the client gets a **500 with a traceback** from the one endpoint whose entire
contract is to answer cleanly when the database is unwell.

Two things this file is careful about
-------------------------------------
**1. The fake must commit.** ``tests/unit/test_health_routes.py::health_client``
overrides ``get_db`` with ``async with factory() as s: yield s`` — no commit. The
failing statement in production *is* ``session.commit()``, so a double that omits
it cannot fail however broken the session is. That is why the probe suite was
green while production 500ed. Every fixture here reproduces ``get_db``'s real
shape.

**2. Only a CANCELLED statement reproduces it.** Measured against a live
Postgres 18 before this file was written:

===========================================  ==========================
session state                                ``await session.commit()``
===========================================  ==========================
after a failed statement (``SELECT 1/0``)    **succeeds** (no raise)
after a statement cancelled by ``wait_for``  ``PendingRollbackError``
after cancellation *then* ``rollback()``     **succeeds** (no raise)
===========================================  ==========================

So a "poison" built from an ordinary SQL error proves nothing — it leaves the
session commit-able and the test passes with or without the fix. Only connection
invalidation (row 2) is the production state, and row 3 is the fix. The
``test_poison_really_poisons`` positive control below pins row 2 so this file
cannot silently decay into row 1.
"""

import pytest
import sqlalchemy.exc
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from routes.health import router as health_router

pytestmark = pytest.mark.timeout(60)


def _cancellable_execute(session):
    """Replace ``execute`` with a long server-side sleep.

    The caller's own ``asyncio.wait_for`` cancels it, invalidating the
    connection mid-statement — the exact production state.
    """
    original = session.execute

    async def sleeping_execute(*_a, **_kw):
        return await original(text("SELECT pg_sleep(30)"))

    return sleeping_execute


def _faithful_get_db(session_factory):
    """A ``get_db`` override matching ``core.database.get_db`` exactly.

    Args:
        session_factory: Async sessionmaker bound to the test engine.

    Returns:
        An async-generator dependency with the real commit/rollback/close shape.
    """

    async def dependency():
        async with session_factory() as session:
            session.execute = _cancellable_execute(session)
            try:
                yield session
                # The load-bearing line: core/database.py:45. This is the
                # statement that raised in production, and the one the
                # pre-existing fake omitted.
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
            finally:
                await session.close()

    return dependency


def _client(engine):
    app = FastAPI()
    app.include_router(health_router)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    from core.database import get_db

    app.dependency_overrides[get_db] = _faithful_get_db(factory)
    return TestClient(app)


class TestPoisonIsRealPositiveControl:
    """If the poison stops poisoning, every assertion in this file is vacuous."""

    async def test_poison_really_poisons(self, pg_engine):
        """A cancelled statement must leave ``commit()`` raising."""
        import asyncio

        factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(session.execute(text("SELECT pg_sleep(30)")), timeout=1.0)

            with pytest.raises(sqlalchemy.exc.PendingRollbackError):
                await session.commit()

    async def test_rollback_is_what_clears_it(self, pg_engine):
        """And the helper's ``rollback()`` is what makes the commit safe again."""
        import asyncio

        from routes.health import _discard_failed_statement

        factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(session.execute(text("SELECT pg_sleep(30)")), timeout=1.0)

            await _discard_failed_statement(session)

            # get_db's post-yield commit: autobegins, holds no connection, no-op.
            await session.commit()

    async def test_helper_never_raises_even_when_rollback_fails(self):
        """A probe must not 500 while reporting the database is unreachable."""
        from routes.health import _discard_failed_statement

        class ExplodingSession:
            async def rollback(self):
                raise sqlalchemy.exc.OperationalError("rollback", None, Exception("gone"))

        await _discard_failed_statement(ExplodingSession())  # must not propagate


class TestReadinessProbeSurvivesSessionTeardown:
    """``/health/ready`` must answer 503, never 500, however the DB misbehaves."""

    def test_cancelled_statement_yields_503_not_500(self, pg_engine):
        """The exact live path: the probe's own 5s ``wait_for`` cancels it."""
        response = _client(pg_engine).get("/health/ready")

        assert response.status_code == 503, (
            f"expected 503, got {response.status_code} — a cancelled statement "
            "left the session unusable and get_db's commit raised out of the probe"
        )
        body = response.json()
        assert body["status"] == "not_ready"
        assert body["error"] == "Database check timed out"


class TestFullHealthCheckSurvivesSessionTeardown:
    """``/health`` swallows DB failures the same way and shares the trap.

    Its 10s overall ``wait_for`` cancels ``db_check()`` mid-statement, and the
    inner ``except`` never runs on a cancellation — so the cleanup has to live on
    the outer timeout branch too.
    """

    def test_overall_timeout_yields_200_unhealthy_not_500(self, pg_engine):
        from unittest.mock import MagicMock, patch

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = _client(pg_engine).get("/health")

        assert response.status_code == 200, (
            f"expected 200 with checks.database=False, got {response.status_code} "
            "— the cancelled db_check escaped from the session teardown"
        )
        body = response.json()
        assert body["checks"]["database"] is False
        assert body["status"] == "unhealthy"


class TestPreExistingFakeWasTooNarrow:
    """Guard the reason this defect survived CI.

    Not a behaviour test — a pin on the test double. A ``get_db`` override
    without a commit puts the probe suites back to being unable to see this
    class of bug at all.
    """

    def test_this_suite_commits_like_production(self):
        import inspect

        src = inspect.getsource(_faithful_get_db)
        assert "await session.commit()" in src
        assert "await session.rollback()" in src
