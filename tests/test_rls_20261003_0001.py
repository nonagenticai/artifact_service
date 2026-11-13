"""Alembic 20261003_0001: the Row-Level Security backstop (art#49), on a REAL chain.

The schema is conftest's ``create_all`` schema stamped at ``20260927_0001``; this
module runs ``alembic upgrade head`` on it as the connecting (owner) role, then
queries as a SEPARATE role named like production's runtime role
(``artifact_service``: NOSUPERUSER, NOBYPASSRLS, not the owner, granted ``arwd``
like prod's default ACL) with ``app.current_tenant`` bound by
``set_config(..., true)`` inside the transaction — exactly what
``src/tenant_guc.py`` does per request.

Pinned here:

* a tenant sees its own rows only; a CUSTOMER sees 0 system rows;
* every PLATFORM tenant sees SYSTEM ``published`` + ``visibility='tenant'`` rows
  and never a SYSTEM draft nor a user-private system row (art#47 semantics);
* the SYSTEM tenant sees ONLY its own rows — never a customer's (no system
  cross-tenant read; owner ruling 2026-10-02, rm#187 reverted);
* no GUC (never set, or '' after a RESET) sees 0 rows on every table;
* WITH CHECK refuses inserting / moving a row into another tenant; nobody can
  write a SYSTEM row it can read; an UPDATE/DELETE of another tenant's row hits 0;
* ``artifact_tags`` / ``artifact_reviews`` follow their PARENT artifact; a
  platform tenant reads an inherited artifact's tags but never its reviews;
* the REVOKEd ``tenant_id_remap_audit`` raises permission denied;
* the runtime role cannot CREATE in schema public;
* the catalog state at HEAD equals ``tests/fixtures/rls_20261003_0001_pin.json``;
* downgrade and ``lock_timeout``: ``tests/test_rls_20261003_0001_downgrade.py``
  (a separate module, so its own schema cannot run under this module's fixture).

Regenerate the pin (only after review):
``ART_RLS_PIN_REGENERATE=1 pytest tests/test_rls_20261003_0001.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, make_url, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.pool import NullPool

import models.artifact  # noqa: F401  (populates Base.metadata)
from alembic import command
from core.config import Settings
from core.database import Base
from repositories.visibility import PUBLISHED
from tests.conftest import TEST_DATABASE_URL, TEST_TENANT_A, TEST_TENANT_B
from tests.test_migration_20260826_0003_tenant_id_is_a_uuid import (
    _alembic_config,
    _alembic_pointing_at,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATION = REPO_ROOT / "alembic" / "versions" / "20261003_0001_rls_tenant_isolation.py"
PIN = REPO_ROOT / "tests" / "fixtures" / "rls_20261003_0001_pin.json"
REVISION = "20261003_0001"
PREVIOUS = "20260927_0001"


def _load_migration():
    spec = importlib.util.spec_from_file_location("_migration_20261003_0001", MIGRATION)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m = _load_migration()
RUNTIME = m.RUNTIME_ROLE
SYSTEM = m.SYSTEM_TENANT
N8N_DEV = "019de842-c92a-7e37-8fdd-eb0d8c5396f9"
WF_0002 = "0195f48b-d000-7000-8000-000000000002"
CUSTOMER_A = TEST_TENANT_A
CUSTOMER_B = TEST_TENANT_B
AUDIT = "tenant_id_remap_audit"
P = "rls49-"  # every seeded filename starts with this

# ---------------------------------------------------------------------------
# Static pins (no database)
# ---------------------------------------------------------------------------


def test_frozen_literals_equal_the_settings_defaults():
    fields = Settings.model_fields
    assert m.SYSTEM_TENANT == fields["system_tenant_id"].default
    assert set(m.PLATFORM_TENANTS) == set(fields["artifacts_platform_tenant_ids"].default)
    assert len(set(m.PLATFORM_TENANTS)) == len(m.PLATFORM_TENANTS)
    assert m.PUBLISHED == PUBLISHED


def test_no_policy_grants_the_system_tenant_a_cross_tenant_read():
    """The only cross-tenant direction is PLATFORM reading SYSTEM-PUBLISHED rows.

    Every system-read predicate is anchored on ``tenant_id = SYSTEM`` (the row
    is a system row) — never a predicate that admits any tenant's row because
    the GUC is the system tenant (rm#187's shape, reverted by rm#190/#192).
    """
    for table, name, cmd, using, check in m.policies():
        if name == m.TENANT_ISOLATION:
            assert cmd == "ALL" and using == check
            assert "current_setting('app.current_tenant', true), '')::uuid" in using
            assert SYSTEM not in using
        else:
            assert name == m.SYSTEM_PUBLISHED_READ and cmd == "SELECT" and check is None
            assert f"tenant_id = '{SYSTEM}'::uuid" in using, (table, name)
            assert "publish_status = 'published'" in using
            assert "visibility = 'tenant'" in using
    assert (m.REVIEWS, m.SYSTEM_PUBLISHED_READ) not in {(t, n) for t, n, *_ in m.policies()}


def test_the_chain_has_a_single_head_and_this_revision_follows_publish_status():
    assert (m.revision, m.down_revision) == (REVISION, PREVIOUS)
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    # Single head, and this revision on its ancestry — NOT "this revision IS the
    # head": that pin went red the moment a later revision (20261027_0001) landed.
    assert len(heads) == 1, f"migration chain has branched: {heads}"
    assert REVISION in {r.revision for r in script.iterate_revisions(heads[0], "base")}


def test_the_migration_file_has_no_percent_sign():
    """alembic doubles ``%`` in --sql output, which breaks the DO blocks."""
    assert "%" not in MIGRATION.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Real chain
# ---------------------------------------------------------------------------

SYNC_URL = make_url(TEST_DATABASE_URL).set(drivername="postgresql+psycopg")


def _alembic(fn: str, from_rev: str | None, to_rev: str) -> None:
    with _alembic_pointing_at(SYNC_URL):
        cfg = _alembic_config()
        if from_rev is not None:
            command.stamp(cfg, from_rev)
        getattr(command, fn)(cfg, to_rev)


def _ensure_runtime_role(conn: Connection) -> bool:
    created = False
    attrs = conn.execute(
        text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :r"), {"r": RUNTIME}
    ).first()
    if attrs is not None:
        assert tuple(attrs) == (False, False), "a pre-existing runtime role must be NOBYPASSRLS"
    else:
        conn.execute(text(f"CREATE ROLE {RUNTIME} NOLOGIN NOSUPERUSER NOBYPASSRLS"))
        created = True
    # prod (measured 2026-10-03): schema public USAGE only; arwd on every table.
    conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {RUNTIME}"))
    conn.execute(
        text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RUNTIME}")
    )
    return created


#: (tenant, filename, publish_status, visibility, tags, reviews)
CORPUS: list[tuple[str, str, str, str]] = [
    (SYSTEM, f"{P}sys-pub", "published", "tenant"),
    (SYSTEM, f"{P}sys-draft", "draft", "tenant"),
    (SYSTEM, f"{P}sys-userpriv", "published", "user"),
    (N8N_DEV, f"{P}n8n", "draft", "tenant"),
    (CUSTOMER_A, f"{P}a1", "published", "tenant"),
    (CUSTOMER_A, f"{P}a2", "draft", "tenant"),
    (CUSTOMER_B, f"{P}b1", "published", "tenant"),
]

_INSERT = text(
    "INSERT INTO artifacts (id, tenant_id, tenant_name, subject_id, visibility, project_id,"
    " version, filename, content_type, kind, sensitivity, size, sha256, storage_key,"
    " created_by, created_at, publish_status)"
    " VALUES (gen_random_uuid(), CAST(:t AS uuid), 't', CAST(:t AS text), :vis,"
    " gen_random_uuid(), 1, :n, 'text/plain', 'doc', 'internal', 1, 'x',"
    " 'k-' || gen_random_uuid(), 't', now(), :ps) RETURNING id"
)


def _seed(conn: Connection) -> None:
    for tenant, name, ps, vis in CORPUS:
        aid = conn.execute(_INSERT, {"t": tenant, "n": name, "vis": vis, "ps": ps}).scalar_one()
        conn.execute(
            text("INSERT INTO artifact_tags (artifact_id, tag) VALUES (:a, :g)"),
            {"a": aid, "g": f"{name}-tag"},
        )
        conn.execute(
            text(
                "INSERT INTO artifact_reviews (id, artifact_id, decision, comment, reviewer_id,"
                " reviewer_tenant_id, reviewed_at)"
                " VALUES (gen_random_uuid(), :a, 'approve', :c, 'r', CAST(:t AS uuid), now())"
            ),
            {"a": aid, "c": f"{name}-review", "t": tenant},
        )


def _cleanup_rows(conn: Connection) -> None:
    conn.execute(text("DELETE FROM artifacts WHERE filename LIKE :p"), {"p": P + "%"})


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    eng = create_engine(SYNC_URL, poolclass=NullPool)
    with eng.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
        Base.metadata.drop_all(conn)
        Base.metadata.create_all(conn)
        # The audit table alembic 20260826_0003 leaves behind (not in create_all).
        conn.execute(text(f"CREATE TABLE IF NOT EXISTS {AUDIT} (id serial PRIMARY KEY)"))
        public_could_create = conn.execute(
            text("SELECT has_schema_privilege('public', 'public', 'CREATE')")
        ).scalar_one()
        conn.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
        created_role = _ensure_runtime_role(conn)
    _alembic("upgrade", PREVIOUS, "head")
    try:
        with eng.begin() as conn:
            _seed(conn)
        yield eng
    finally:
        try:
            with eng.begin() as conn:
                _cleanup_rows(conn)
            _alembic("downgrade", None, PREVIOUS)
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


@contextmanager
def _txn(eng: Engine, tenant: str | None, *, as_runtime: bool = True) -> Iterator[Connection]:
    """One transaction that ALWAYS rolls back, so a write test never leaks rows."""
    with eng.connect() as conn:
        trans = conn.begin()
        try:
            if as_runtime:
                _as(conn, tenant)
            yield conn
        finally:
            trans.rollback()


def _as(conn: Connection, tenant: str | None) -> None:
    """Become the runtime role for THIS transaction, with the tenant GUC bound."""
    conn.execute(text(f"SET LOCAL ROLE {RUNTIME}"))
    if tenant is not None:
        conn.execute(text("SELECT set_config('app.current_tenant', :t, true)"), {"t": tenant})


_VISIBLE_SQL = {
    "artifacts": "SELECT filename FROM artifacts WHERE filename LIKE :p",
    "artifact_tags": "SELECT tag FROM artifact_tags WHERE tag LIKE :p",
    "artifact_reviews": "SELECT comment FROM artifact_reviews WHERE comment LIKE :p",
}
_SUFFIX = {"artifacts": "", "artifact_tags": "-tag", "artifact_reviews": "-review"}


def _visible(eng: Engine, tenant: str | None, table: str = "artifacts") -> set[str]:
    with eng.connect() as conn, conn.begin():
        _as(conn, tenant)
        rows = conn.execute(text(_VISIBLE_SQL[table]), {"p": P + "%"})
        return {r[0].removesuffix(_SUFFIX[table]) for r in rows}


def _names(tenant: str, published_tenant_visible_only: bool = False) -> set[str]:
    return {
        n
        for t, n, ps, vis in CORPUS
        if t == tenant
        and (not published_tenant_visible_only or (ps == "published" and vis == "tenant"))
    }


SYS_PUBLISHED = _names(SYSTEM, published_tenant_visible_only=True)
ALL_TABLES = ["artifacts", "artifact_tags", "artifact_reviews"]


class TestRead:
    @pytest.mark.parametrize("table", ALL_TABLES)
    def test_a_customer_sees_only_its_own_rows_and_no_system_row(self, engine, table):
        assert _visible(engine, CUSTOMER_A, table) == _names(CUSTOMER_A)
        assert _visible(engine, CUSTOMER_B, table) == _names(CUSTOMER_B)

    @pytest.mark.parametrize("platform", [N8N_DEV, WF_0002])
    @pytest.mark.parametrize("table", ["artifacts", "artifact_tags"])
    def test_a_platform_tenant_sees_system_published_never_draft(self, engine, table, platform):
        assert SYS_PUBLISHED == {f"{P}sys-pub"}, "vacuity: one inheritable system row"
        assert _visible(engine, platform, table) == _names(platform) | SYS_PUBLISHED

    def test_a_platform_tenant_never_reads_an_inherited_artifacts_reviews(self, engine):
        """The review log's gate is own-tenant (include_system=False)."""
        assert _visible(engine, N8N_DEV, "artifact_reviews") == _names(N8N_DEV)

    @pytest.mark.parametrize("table", ALL_TABLES)
    def test_the_system_tenant_sees_only_its_own_rows(self, engine, table):
        """No system cross-tenant read (owner ruling 2026-10-02)."""
        visible = _visible(engine, SYSTEM, table)
        assert visible == _names(SYSTEM)
        assert not visible & (_names(CUSTOMER_A) | _names(CUSTOMER_B) | _names(N8N_DEV))

    @pytest.mark.parametrize("guc", [None, ""])
    @pytest.mark.parametrize("table", ALL_TABLES)
    def test_no_guc_sees_nothing(self, engine, table, guc):
        assert _visible(engine, guc, table) == set()

    def test_the_owner_is_not_subject_to_rls(self, engine):
        """Positive control: the rows exist; RLS is what hides them."""
        with engine.connect() as conn:
            n = conn.execute(
                text("SELECT count(*) FROM artifacts WHERE filename LIKE :p"), {"p": P + "%"}
            ).scalar_one()
        assert n == len(CORPUS)


class TestWrite:
    def test_insert_into_another_tenant_is_refused(self, engine):
        with _txn(engine, CUSTOMER_A) as conn:
            with pytest.raises(ProgrammingError, match="row-level security"):
                conn.execute(
                    _INSERT, {"t": CUSTOMER_B, "n": f"{P}x", "vis": "tenant", "ps": "draft"}
                )

    def test_insert_into_own_tenant_is_admitted(self, engine):
        with _txn(engine, CUSTOMER_A) as conn:
            conn.execute(_INSERT, {"t": CUSTOMER_A, "n": f"{P}own", "vis": "tenant", "ps": "draft"})
            seen = conn.execute(
                text("SELECT count(*) FROM artifacts WHERE filename = :n"), {"n": f"{P}own"}
            ).scalar_one()
            assert seen == 1

    def test_moving_an_own_row_to_another_tenant_is_refused(self, engine):
        with _txn(engine, CUSTOMER_A) as conn:
            with pytest.raises(ProgrammingError, match="row-level security"):
                conn.execute(
                    text("UPDATE artifacts SET tenant_id = CAST(:b AS uuid) WHERE filename = :n"),
                    {"b": CUSTOMER_B, "n": f"{P}a1"},
                )

    @pytest.mark.parametrize("tenant", [CUSTOMER_A, N8N_DEV, WF_0002])
    def test_nobody_else_can_update_or_delete_a_system_row(self, engine, tenant):
        with _txn(engine, tenant) as conn:
            up = conn.execute(
                text("UPDATE artifacts SET filename = filename WHERE filename LIKE :p"),
                {"p": f"{P}sys-%"},
            )
            dl = conn.execute(
                text("DELETE FROM artifacts WHERE filename LIKE :p"), {"p": f"{P}sys-%"}
            )
            assert (up.rowcount, dl.rowcount) == (0, 0)

    def test_a_tag_cannot_be_attached_to_another_tenants_artifact(self, engine):
        with _txn(engine, None, as_runtime=False) as conn:
            b1 = conn.execute(
                text("SELECT id FROM artifacts WHERE filename = :n"), {"n": f"{P}b1"}
            ).scalar_one()
            _as(conn, CUSTOMER_A)
            with pytest.raises(ProgrammingError, match="row-level security"):
                conn.execute(
                    text("INSERT INTO artifact_tags (artifact_id, tag) VALUES (:a, 'x')"), {"a": b1}
                )

    def test_a_platform_tenant_cannot_tag_or_review_an_inherited_system_artifact(self, engine):
        with _txn(engine, None, as_runtime=False) as conn:
            sys_pub = conn.execute(
                text("SELECT id FROM artifacts WHERE filename = :n"), {"n": f"{P}sys-pub"}
            ).scalar_one()
            _as(conn, N8N_DEV)
            # Positive control: the platform tenant CAN read the parent artifact.
            assert (
                conn.execute(
                    text("SELECT count(*) FROM artifacts WHERE id = :a"), {"a": sys_pub}
                ).scalar_one()
                == 1
            )
            with pytest.raises(ProgrammingError, match="row-level security"):
                with conn.begin_nested():
                    conn.execute(
                        text("INSERT INTO artifact_tags (artifact_id, tag) VALUES (:a, 'x')"),
                        {"a": sys_pub},
                    )
            with pytest.raises(ProgrammingError, match="row-level security"):
                conn.execute(
                    text(
                        "INSERT INTO artifact_reviews (id, artifact_id, decision, reviewer_id,"
                        " reviewer_tenant_id, reviewed_at) VALUES (gen_random_uuid(), :a,"
                        " 'approve', 'r', CAST(:t AS uuid), now())"
                    ),
                    {"a": sys_pub, "t": N8N_DEV},
                )

    def test_no_guc_cannot_write(self, engine):
        with _txn(engine, None) as conn:
            with pytest.raises(ProgrammingError, match="row-level security"):
                conn.execute(
                    _INSERT, {"t": CUSTOMER_A, "n": f"{P}x", "vis": "tenant", "ps": "draft"}
                )


class TestPrivileges:
    def test_the_audit_table_is_revoked_from_the_runtime_role(self, engine):
        with _txn(engine, CUSTOMER_A) as conn:
            with pytest.raises(ProgrammingError, match="permission denied"):
                conn.execute(text(f"SELECT 1 FROM {AUDIT}"))

    def test_the_runtime_role_cannot_create_in_public(self, engine):
        with engine.connect() as conn:
            assert not conn.execute(
                text("SELECT has_schema_privilege(:r, 'public', 'CREATE')"), {"r": RUNTIME}
            ).scalar_one()
            assert conn.execute(
                text("SELECT has_schema_privilege(:r, 'public', 'USAGE')"), {"r": RUNTIME}
            ).scalar_one()


# ---------------------------------------------------------------------------
# The catalog pin
# ---------------------------------------------------------------------------


def catalog_state(conn: Connection) -> dict:
    pols = conn.execute(
        text(
            "SELECT tablename, policyname, permissive, roles::text, cmd, qual, with_check"
            " FROM pg_policies WHERE schemaname = 'public' ORDER BY 1, 2"
        )
    ).all()
    rls = conn.execute(
        text(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY(:t) ORDER BY 1"
        ),
        {"t": [*m.RLS_TABLES, AUDIT]},
    ).all()
    privs = conn.execute(
        text(
            "SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type)"
            " FROM information_schema.role_table_grants"
            " WHERE grantee = :r AND table_schema = 'public' AND table_name = ANY(:t)"
            " GROUP BY 1 ORDER BY 1"
        ),
        {"r": RUNTIME, "t": [*m.RLS_TABLES, AUDIT]},
    ).all()
    return {
        "policies": {
            f"{t}.{p}": {"permissive": pm, "roles": r, "cmd": c, "qual": q, "with_check": w}
            for t, p, pm, r, c, q, w in pols
        },
        "rls": {t: {"enabled": e, "forced": f} for t, e, f in rls},
        "runtime_grants": {t: g for t, g in privs},
    }


def test_the_catalog_at_head_equals_the_pin(engine):
    with engine.connect() as conn:
        state = catalog_state(conn)
    if os.getenv("ART_RLS_PIN_REGENERATE") == "1":
        PIN.parent.mkdir(parents=True, exist_ok=True)
        PIN.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert state == json.loads(PIN.read_text(encoding="utf-8"))
    # Vacuity: the pin is not empty and the audit table is really revoked.
    assert len(state["policies"]) == len(m.policies()) == 5
    assert AUDIT not in state["runtime_grants"]
    assert all(
        v == {"enabled": True, "forced": False} for k, v in state["rls"].items() if k != AUDIT
    )
