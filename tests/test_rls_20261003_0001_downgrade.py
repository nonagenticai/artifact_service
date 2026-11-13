"""Alembic 20261003_0001 (art#49): downgrade and ``lock_timeout``.

A SEPARATE module from ``test_rls_20261003_0001.py`` on purpose: these tests
rebuild the schema from scratch, which must not happen while that module's
module-scoped fixture (an upgraded, seeded schema) is still alive.

* downgrade restores no-RLS, no policies and the pre-revision grants, and the
  revision re-applies cleanly after it;
* upgrade bounds its ACCESS EXCLUSIVE wait: a held conflicting lock FAILS the
  migrate init container in seconds instead of hanging it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

from core.database import Base
from tests.test_rls_20261003_0001 import (
    AUDIT,
    PREVIOUS,
    REVISION,
    RUNTIME,
    SYNC_URL,
    _alembic,
    _ensure_runtime_role,
    catalog_state,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def fresh_schema() -> Iterator[Engine]:
    eng = create_engine(SYNC_URL, poolclass=NullPool)
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        Base.metadata.drop_all(conn)
        Base.metadata.create_all(conn)
        conn.execute(text(f"CREATE TABLE IF NOT EXISTS {AUDIT} (id serial PRIMARY KEY)"))
        public_could_create = conn.execute(
            text("SELECT has_schema_privilege('public', 'public', 'CREATE')")
        ).scalar_one()
        conn.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
        created_role = _ensure_runtime_role(conn)
    try:
        yield eng
    finally:
        with eng.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            conn.execute(text(f"DROP TABLE IF EXISTS {AUDIT}"))
            Base.metadata.drop_all(conn)
            conn.execute(text(f"REVOKE ALL ON SCHEMA public FROM {RUNTIME}"))
            if created_role:
                conn.execute(text(f"DROP OWNED BY {RUNTIME}"))
                conn.execute(text(f"DROP ROLE {RUNTIME}"))
            if public_could_create:
                conn.execute(text("GRANT CREATE ON SCHEMA public TO PUBLIC"))
        eng.dispose()


def test_downgrade_restores_no_rls_no_policies_and_the_prior_grants(fresh_schema):
    with fresh_schema.connect() as conn:
        before = catalog_state(conn)
    _alembic("upgrade", PREVIOUS, REVISION)
    with fresh_schema.connect() as conn:
        assert len(catalog_state(conn)["policies"]) == 5
    _alembic("downgrade", None, PREVIOUS)
    with fresh_schema.connect() as conn:
        after = catalog_state(conn)
    assert after == before
    assert after["policies"] == {}
    assert after["runtime_grants"][AUDIT] == "DELETE,INSERT,SELECT,UPDATE"
    # and the chain re-applies cleanly after a downgrade
    _alembic("upgrade", None, REVISION)
    _alembic("downgrade", None, PREVIOUS)


def test_upgrade_fails_fast_when_a_conflicting_lock_is_held(fresh_schema):
    """lock_timeout: a held lock FAILS the migrate container instead of hanging it."""
    holder = fresh_schema.connect()
    tx = holder.begin()
    holder.execute(text("LOCK TABLE artifacts IN ACCESS SHARE MODE"))
    released = threading.Event()

    def _release_late() -> None:
        released.wait(60)
        tx.rollback()
        holder.close()

    t = threading.Thread(target=_release_late, daemon=True)
    t.start()
    started = time.monotonic()
    try:
        with pytest.raises(DBAPIError, match="lock timeout"):
            _alembic("upgrade", PREVIOUS, REVISION)
        assert time.monotonic() - started < 45
    finally:
        released.set()
        t.join(timeout=10)
