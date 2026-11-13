"""Behavioural tests for alembic ``20260826_0003_tenant_id_is_a_uuid``.

``20260826_0003`` re-types ``artifacts.tenant_id`` and
``artifact_reviews.reviewer_tenant_id`` from ``varchar(255)`` to ``uuid`` and, on
the way, REMAPS the one legacy literal ``'n8n-dev'`` onto the registry uuid
``019de842-…`` — 284 rows of a 51,238-row production table (measured 2026-08-26;
``artifact_reviews`` measured 0 rows, ``artifact_tags`` 32 rows and no tenant
column). It runs inside the ``migrate`` init container, in a single transaction,
behind guards that are supposed to ABORT rather than coerce — ownership,
totality, spelling collision, the postcondition, and, on the way back down, the
provenance guard that refuses to reverse a table with no witness column. Until
this file existed nothing exercised any of it.

⛔ THE VACUITY TRAP THIS FILE IS BUILT AROUND
---------------------------------------------
``tests/conftest.py`` bootstraps the schema with ``Base.metadata.create_all``,
and ``src/models/artifact.py`` declares BOTH tenant columns as
``Uuid(as_uuid=False)``. Under pytest they are therefore ALREADY ``uuid`` before
the migration runs — verified in :class:`TestPreStateIsVarchar`. A test that
merely calls ``command.upgrade`` hits the early return

    if all(dtype == "uuid" for dtype in live.values()):
        print("… already uuid — nothing to do"); return

so the ownership guard, the audit table, the remap, the totality guard, the
collision guard and both ALTERs are skipped, and every assertion written against
that run passes against a migration that did nothing at all.

Three independent defences, all required:

1. :func:`_force_varchar_pre_state` runs FIRST in every test that exercises the
   migration. It emits exactly what ``downgrade()`` emits —
   ``ALTER COLUMN … TYPE varchar(255) USING …::text`` — so the pre-state is the
   shape production is actually in and not an approximation of it.
2. :class:`TestPreStateIsVarchar` asserts that pre-state directly. If the trap
   ever reopens (a model reverted to ``String``, a conftest that stops using
   ``create_all``, a fixture that stops forcing), THAT test fails and names the
   reason instead of the rest of the file going quietly green.
3. Every seed below writes the literal ``'n8n-dev'`` into a tenant column.
   Against the default pytest schema that INSERT dies with ``invalid input
   syntax for type uuid`` — proved by
   ``test_the_corpus_cannot_be_seeded_without_the_forced_pre_state``. The corpus
   cannot be seeded unless the pre-state was really forced, so no test here can
   silently degrade into a no-op.

Plumbing notes
--------------
* ⛔ ``alembic/env.py`` READS ``DATABASE_URL`` FIRST. This bullet used to claim
  the opposite — that env.py only ever calls ``core.config.get_settings()`` — and
  that false belief is what made the two privilege guards vacuous in CI for a
  full run. ``env.py::_database_url()`` resolves ``DATABASE_URL`` ->
  ``PG_*``/``POSTGRES_CI_*`` -> ``settings.database_url_sync``, and the archetype
  exports all three families, so setting ``POSTGRES_*`` alone changed nothing
  there while working perfectly on a laptop that has none of the earlier names.
  :func:`_alembic_pointing_at` therefore pins ``DATABASE_URL`` and clears every
  lower-precedence name, then restores them and the ``lru_cache`` on the way out
  — a half-restored cache would hand every later test in the worker a Settings
  object pointing at the test database.
* The URL is taken from ``pg_engine.url`` rather than re-derived from
  ``TEST_DATABASE_URL``, so alembic can only ever reach the database conftest
  itself connected to.
* alembic is synchronous and opens its own connection, so every seed is
  COMMITTED before the upgrade and the run happens on a worker thread.
* ``alembic_version`` and ``tenant_id_remap_audit`` are not in
  ``Base.metadata``, so conftest's ``drop_all`` never touches them.
  :func:`_drop_migration_artifacts` runs on BOTH sides of the fixture so a
  crashed test cannot hand the next one a half-migrated schema.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError

# LOAD-BEARING IMPORT, not a leftover. conftest's ``pg_engine`` bootstraps the
# schema with ``Base.metadata.drop_all`` / ``create_all``, and ``Base.metadata``
# is populated as a SIDE EFFECT of importing the model module. Without this
# import, running THIS FILE ALONE (which is how it is developed, and how a
# `-k migration` CI shard runs it) hands every test an empty metadata: drop_all
# and create_all both become no-ops, no isolation happens between tests, and the
# vacuity controls measure whatever the previous test left behind.
import models.artifact  # noqa: F401
from alembic import command
from core.database import Base

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[1]

REVISION = "20260826_0003"
PREVIOUS_REVISION = "20260519_0002"

#: The whole chain, newest first. Asserted as a LIST in TestRevisionChain rather
#: than only "0003 follows 0002": a migration spliced in between the two would
#: keep the parent link intact on the pair and still change what
#: ``alembic upgrade head`` executes.
EXPECTED_CHAIN: tuple[str, ...] = (
    "20260826_0003",
    "20260519_0002",
    "006_add_review_status",
    "005_add_tenant_name",
    "004_per_user_isolation",
    "003_enum_to_varchar",
    "002_tenant_isolation",
    "001_initial",
)


# ---------------------------------------------------------------------------
# The migration module itself.
#
# Loaded by path because ``20260826_0003_tenant_id_is_a_uuid`` is not an
# importable module name. TENANT_COLUMNS / REMAP / _AUDIT_TABLE / _audit_key are
# read FROM the migration rather than retyped here, so a table added to (or
# dropped from) the migration's own work list fails a test instead of silently
# escaping every check below. ``_live_columns`` is called directly in
# TestCatalogSource.
# ---------------------------------------------------------------------------

_MIGRATION_PATH = REPO_ROOT / "alembic" / "versions" / f"{REVISION}_tenant_id_is_a_uuid.py"
_spec = importlib.util.spec_from_file_location("_migration_20260826_0003", _MIGRATION_PATH)
assert _spec is not None and _spec.loader is not None
migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migration)

TENANT_COLUMNS: dict[str, str] = migration.TENANT_COLUMNS
REMAP: dict[str, str] = migration.REMAP
AUDIT_TABLE: str = migration._AUDIT_TABLE
#: The column ``downgrade()`` scopes its reverse UPDATE by. Read from the
#: migration so a rename there fails a test instead of quietly making
#: TestDowngrade assert a column nobody uses any more.
PROVENANCE_COLUMN: str = migration._PROVENANCE_COLUMN

#: ``{(table, column)}`` — the two columns whose TYPE changes.
TENANT_TARGETS: tuple[tuple[str, str], ...] = tuple(sorted(TENANT_COLUMNS.items()))


# ---------------------------------------------------------------------------
# Corpus constants
# ---------------------------------------------------------------------------

LEGACY = "n8n-dev"

#: n8n-dev's REGISTRY uuid — read out of ``licenses.tenants``, and the value the
#: migration must move the 284 dirty rows onto.
N8N_DEV_UUID = "019de842-c92a-7e37-8fdd-eb0d8c5396f9"  # pragma: allowlist secret

#: A DIFFERENT tenant (``platform-cp-1``), which owns 42,387 rows in production.
#: It is the control for "the remap took only what it was told to take": folding
#: n8n-dev into this uuid is the exact cross-tenant merge the migration's
#: docstring exists to make un-repeatable.
OTHER_TENANT_UUID = "0195f48b-d000-7000-8000-000000000001"  # pragma: allowlist secret

#: Two legal spellings of ONE uuid. Postgres keeps both verbatim in a varchar
#: column, so under ``varchar`` they are two tenant silos and under ``uuid`` they
#: are one — see TestCollisionGuard.
OTHER_TENANT_UPPER = "0195F48B-D000-7000-8000-000000000001"  # pragma: allowlist secret
OTHER_TENANT_DASHLESS = "0195f48bd00070008000000000000001"  # pragma: allowlist secret

#: A legacy label nobody put in REMAP. Stands in for a value the OLD pod writes
#: between the pre-deploy census and the ALTER — see TestTotalityGuard.
UNLISTED_LABEL = "gerard-dev"

PROJECT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")

# Explicit ids so "which row moved" is an assertion, not a guess.
A_LEGACY = (
    uuid.UUID("00000000-0000-4000-8000-000000000001"),
    uuid.UUID("00000000-0000-4000-8000-000000000002"),
    uuid.UUID("00000000-0000-4000-8000-000000000003"),
)
A_OTHER = (
    uuid.UUID("00000000-0000-4000-8000-0000000000a1"),
    uuid.UUID("00000000-0000-4000-8000-0000000000a2"),
)
#: A row ALREADY sitting on the destination uuid before the migration runs.
#: Production measured 0 of these, so it is a pure control here: it must not be
#: counted by the audit and must not be moved.
A_DESTINATION = uuid.UUID("00000000-0000-4000-8000-0000000000d1")
A_UNLISTED = uuid.UUID("00000000-0000-4000-8000-0000000000e1")
A_UPPER = uuid.UUID("00000000-0000-4000-8000-0000000000f1")
A_DASHLESS = uuid.UUID("00000000-0000-4000-8000-0000000000f2")

R_LEGACY = (
    uuid.UUID("00000000-0000-4000-9000-000000000001"),
    uuid.UUID("00000000-0000-4000-9000-000000000002"),
)
R_OTHER = (uuid.UUID("00000000-0000-4000-9000-0000000000a1"),)

#: How many rows the corpus puts under the legacy literal, per column. These are
#: the numbers the audit must record — NOT production's 284/0, which describe a
#: database these tests never touch.
LEGACY_ARTIFACTS = len(A_LEGACY)
LEGACY_REVIEWS = len(R_LEGACY)

MIGRATOR_ROLE = "art_uuid_migrator"
MIGRATOR_PASSWORD = "art-uuid-migrator-not-a-real-secret"  # pragma: allowlist secret
ALIEN_ROLE = "art_uuid_alien"

#: Every index on ``artifacts`` that leads with (or contains) ``tenant_id``.
#: Asserted as a FLOOR of the measured set in TestTypesAfter, so that test cannot
#: pass by measuring an empty index list against itself.
EXPECTED_TENANT_INDEXES = frozenset(
    {
        "idx_artifacts_tenant_id",
        "idx_tenant_project",
        "idx_tenant_project_card",
        "idx_tenant_project_kind",
        "idx_tenant_project_step",
        "ix_artifacts_tenant_status",
        "ix_artifacts_tenant_subject",
        "ix_artifacts_tenant_visibility",
    }
)


# ---------------------------------------------------------------------------
# alembic plumbing
# ---------------------------------------------------------------------------


def _alembic_config() -> Config:
    """Alembic config WITHOUT an ini file.

    ``alembic.ini`` carries a ``[loggers]`` section which ``env.py`` feeds to
    ``logging.config.fileConfig``, whose ``disable_existing_loggers`` default
    would silence every logger already configured in this pytest session.
    Building the Config programmatically leaves ``config_file_name`` None so
    ``env.py`` skips that call.
    """
    cfg = Config()
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg


#: Every environment name ``alembic/env.py::_database_url()`` consults, in its
#: own precedence order. ⛔ THIS LIST IS LOAD-BEARING — see the docstring below.
#: If a name is added there and not here, this file silently starts migrating
#: whatever database the surrounding environment names instead of the one the
#: test asked for.
_ALEMBIC_DSN_ENV_NAMES = (
    "DATABASE_URL",
    "PG_HOST",
    "PG_PORT",
    "PG_USER",
    "PG_PASSWORD",
    "PG_DATABASE",
    "POSTGRES_CI_HOST",
    "POSTGRES_CI_PORT",
    "POSTGRES_CI_USER",
    "POSTGRES_CI_PASSWORD",
)


@contextlib.contextmanager
def _alembic_pointing_at(url: URL):
    """Make ``alembic upgrade`` connect as EXACTLY ``url``, and nothing else.

    ⛔ ``Settings`` IS THE LAST RESORT, NOT THE LEVER. ``env.py::_database_url()``
    reads, in order, ``DATABASE_URL`` -> ``PG_*``/``POSTGRES_CI_*`` -> and only
    then ``get_settings().database_url_sync``. This helper used to set the
    ``POSTGRES_*`` family alone, which reaches the THIRD branch — so it worked on
    a laptop, where none of the earlier names exist, and was inert in CI, where
    the archetype exports ``DATABASE_URL`` and both ``PG_*`` and ``POSTGRES_CI_*``.

    That is not a cosmetic difference. The two privilege guards
    (``TestOwnershipGuard``, ``TestCatalogSource``) hand this function a
    NON-SUPERUSER role precisely because ``pg_has_role(current_user, relowner,
    'USAGE')`` and ``information_schema``'s visibility filter are unconditionally
    true for a superuser. In CI the override was ignored, alembic reconnected as
    the sidecar's ``postgres`` superuser, the migration cheerfully ALTERed a
    table owned by a role it is not a member of, and both tests read
    ``DID NOT RAISE``. A guard that cannot fire is a guard that is not tested.

    So: pin ``DATABASE_URL`` to the requested DSN (the branch env.py consults
    FIRST, hence the only one whose answer cannot be overtaken) and REMOVE every
    lower-precedence name for the duration, leaving exactly one source of truth
    rather than a stack whose winner depends on which machine is running. The
    ``POSTGRES_*`` overrides stay so the ``Settings`` fallback — the path a
    developer with a bare checkout takes — resolves to the same database.

    Every mutated name is restored on the way out, together with the
    ``get_settings`` ``lru_cache``; leaving either dirty would hand every later
    test in this worker a Settings object pointing at the test database.
    """
    from core.config import get_settings

    overrides = {
        # env.py's FIRST branch. ``hide_password=False`` is required: plain
        # ``str(URL)`` renders the password as ``***`` and alembic would then
        # try to authenticate with three asterisks.
        "DATABASE_URL": url.render_as_string(hide_password=False),
        "POSTGRES_HOST": url.host or "localhost",
        "POSTGRES_PORT": str(url.port or 5432),
        "POSTGRES_DB": url.database or "",
        "POSTGRES_USER": url.username or "",
        "POSTGRES_PASSWORD": url.password or "",
        # Deterministic: the test server is a local container with no TLS, and
        # the default 'prefer' would make the connection string depend on how
        # that container happens to be built.
        "POSTGRES_SSLMODE": "disable",
    }
    shadowed = [name for name in _ALEMBIC_DSN_ENV_NAMES if name not in overrides]
    saved = {key: os.environ.get(key) for key in (*overrides, *shadowed)}
    os.environ.update(overrides)
    for name in shadowed:
        os.environ.pop(name, None)
    get_settings.cache_clear()
    try:
        yield
    finally:
        for key, previous in saved.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        get_settings.cache_clear()


def _upgrade_sync(url: URL) -> None:
    with _alembic_pointing_at(url):
        cfg = _alembic_config()
        command.stamp(cfg, PREVIOUS_REVISION)
        command.upgrade(cfg, REVISION)


def _downgrade_sync(url: URL) -> None:
    with _alembic_pointing_at(url):
        cfg = _alembic_config()
        command.stamp(cfg, REVISION)
        command.downgrade(cfg, PREVIOUS_REVISION)


async def _run_upgrade(engine, url: URL | None = None) -> None:
    """Alembic is synchronous and opens its OWN connection — run it off-loop."""
    await asyncio.to_thread(_upgrade_sync, url if url is not None else engine.url)


async def _run_downgrade(engine, url: URL | None = None) -> None:
    await asyncio.to_thread(_downgrade_sync, url if url is not None else engine.url)


def _query_as(url: URL, fn) -> Any:
    """Run ``fn(sync_connection)`` as whatever role ``url`` names."""
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return fn(conn)
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Live-schema helpers. Everything reads pg_catalog, never information_schema —
# TestCatalogSource is about exactly that difference and would be self-confirming
# if the assertions shared the migration's blind spot.
# ---------------------------------------------------------------------------


async def _column_types(conn) -> dict[tuple[str, str], str]:
    res = await conn.execute(
        text(
            "SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod) "
            "FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid = c.oid "
            "WHERE n.nspname = current_schema() AND c.relkind = 'r' "
            "AND a.attnum > 0 AND NOT a.attisdropped "
            # CAST(:x AS text[]) and NOT `:x::text[]`: SQLAlchemy's text()
            # bind-parameter regex mis-parses a bind name that is immediately
            # followed by `::`, so the postgres cast syntax silently produces a
            # DIFFERENT parameter name and the statement reaches the server with
            # a literal colon in it.
            "AND (c.relname, a.attname) IN ("
            "  SELECT t, col FROM unnest("
            "    CAST(:tables AS text[]), CAST(:columns AS text[])) AS u(t, col))"
        ),
        {"tables": [t for t, _ in TENANT_TARGETS], "columns": [c for _, c in TENANT_TARGETS]},
    )
    return {(r[0], r[1]): r[2] for r in res}


async def _one_column_type(conn, table: str, column: str) -> str | None:
    res = await conn.execute(
        text(
            "SELECT format_type(a.atttypid, a.atttypmod) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid = c.oid "
            "WHERE n.nspname = current_schema() AND c.relname = :t AND a.attname = :col "
            "AND a.attnum > 0 AND NOT a.attisdropped"
        ),
        {"t": table, "col": column},
    )
    return res.scalar_one_or_none()


async def _artifact_indexes(conn) -> dict[str, tuple[bool, str]]:
    """``{index name: (indisvalid, definition)}`` for every index on artifacts."""
    res = await conn.execute(
        text(
            "SELECT i.relname, ix.indisvalid, pg_get_indexdef(i.oid) "
            "FROM pg_index ix "
            "JOIN pg_class i ON i.oid = ix.indexrelid "
            "JOIN pg_class t ON t.oid = ix.indrelid "
            "JOIN pg_namespace n ON n.oid = t.relnamespace "
            "WHERE n.nspname = current_schema() AND t.relname = 'artifacts'"
        )
    )
    return {r[0]: (r[1], r[2]) for r in res}


def _tenant_id_indexes(indexes: dict[str, tuple[bool, str]]) -> dict[str, bool]:
    """Only the indexes whose DEFINITION references ``tenant_id``.

    Selected by definition rather than by name on purpose: ``ix_artifacts_
    tenant_name`` is named for a tenant but indexes ``tenant_name``, and the
    ALTER does not touch it.
    """
    return {
        name: valid
        for name, (valid, definition) in indexes.items()
        if "tenant_id" in definition.replace("tenant_name", "")
    }


async def _count(conn, table: str) -> int:
    res = await conn.execute(text(f"SELECT count(*) FROM {table}"))
    return int(res.scalar_one())


async def _tenant_of(conn, table: str, column: str, row_id: uuid.UUID) -> str | None:
    """One row's tenant column rendered as text.

    ``::text`` and not the raw column: before the migration it is ``varchar`` and
    after it is ``uuid`` (psycopg hands back a ``UUID`` object), and every
    assertion here wants one comparable spelling.
    """
    res = await conn.execute(
        text(f'SELECT "{column}"::text FROM "{table}" WHERE id = :id'),
        {"id": row_id},
    )
    return res.scalar_one_or_none()


async def _audit_rows(conn) -> dict[tuple[str, str], tuple[int, str]]:
    res = await conn.execute(
        text(f"SELECT table_name, legacy_value, row_count, new_value FROM {AUDIT_TABLE}")
    )
    return {(r[0], r[1]): (int(r[2]), r[3]) for r in res}


async def _table_exists(conn, table: str) -> bool:
    res = await conn.execute(text("SELECT to_regclass(:t)"), {"t": table})
    return res.scalar_one_or_none() is not None


# ---------------------------------------------------------------------------
# PRE-state
# ---------------------------------------------------------------------------


async def _force_varchar_pre_state(conn) -> None:
    """Put the schema back into the shape production is actually in.

    Byte-identical to what ``downgrade()`` emits, so the pre-state is production's
    and not an approximation of it. Without this the whole file is vacuous — see
    the module docstring.
    """
    for table, column in TENANT_TARGETS:
        await conn.execute(
            text(
                f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
                f'TYPE varchar(255) USING "{column}"::text'
            )
        )


async def _assert_pre_state(conn) -> None:
    types = await _column_types(conn)
    assert set(types) == set(TENANT_TARGETS), (
        f"expected both tenant columns present, missing {sorted(set(TENANT_TARGETS) - set(types))}"
    )
    wrong = {k: v for k, v in types.items() if v != "character varying(255)"}
    assert not wrong, f"pre-state was not forced; these are not varchar(255): {wrong}"


async def _drop_migration_artifacts(conn) -> None:
    """Remove everything alembic leaves behind that ``drop_all`` cannot see."""
    await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    await conn.execute(text(f"DROP TABLE IF EXISTS {AUDIT_TABLE}"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def uuid_db(pg_engine):
    """conftest's schema, untouched: both tenant columns are ``uuid``.

    This is the TRAP state. Only the vacuity controls use it.
    """
    async with pg_engine.begin() as conn:
        await _drop_migration_artifacts(conn)
    yield pg_engine
    async with pg_engine.begin() as conn:
        await _drop_migration_artifacts(conn)


@pytest.fixture
async def varchar_db(uuid_db):
    """``uuid_db`` with the production (varchar) pre-state forced."""
    async with uuid_db.begin() as conn:
        await _force_varchar_pre_state(conn)
    return uuid_db


@pytest.fixture
async def migrator_owned(varchar_db):
    """``varchar_db`` with every table owned by a NON-superuser login role.

    Needed because the ownership guard is ``pg_has_role(current_user, relowner,
    'USAGE')``, and a superuser is a member of every role — running the guard as
    ``postgres`` makes it structurally unable to fire, which is a test that
    passes against a deleted guard.

    Yields the URL alembic should use.
    """
    engine = varchar_db
    tables = [t.name for t in Base.metadata.sorted_tables]

    async with engine.begin() as conn:
        owner = (await conn.execute(text("SELECT current_user"))).scalar_one()
        for role in (MIGRATOR_ROLE, ALIEN_ROLE):
            await conn.execute(text(f"DROP ROLE IF EXISTS {role}"))
        # Inlined, not a bind parameter: CREATE ROLE is utility DDL and postgres
        # refuses a parameter placeholder in it. The value is a module constant,
        # never anything caller-supplied.
        await conn.exec_driver_sql(
            f"CREATE ROLE {MIGRATOR_ROLE} LOGIN PASSWORD '{MIGRATOR_PASSWORD}'"
        )
        await conn.execute(text(f"CREATE ROLE {ALIEN_ROLE} NOLOGIN"))
        # CREATE so `alembic stamp` can build alembic_version and the migration
        # can build its audit table.
        await conn.execute(text(f"GRANT USAGE, CREATE ON SCHEMA public TO {MIGRATOR_ROLE}"))
        for table in tables:
            await conn.execute(text(f'ALTER TABLE "{table}" OWNER TO {MIGRATOR_ROLE}'))

    yield engine.url.set(username=MIGRATOR_ROLE, password=MIGRATOR_PASSWORD)

    async with engine.begin() as conn:
        await _drop_migration_artifacts(conn)
        # REASSIGN before DROP OWNED: DROP OWNED would take the TABLES with it.
        await conn.execute(text(f"REASSIGN OWNED BY {MIGRATOR_ROLE}, {ALIEN_ROLE} TO {owner}"))
        await conn.execute(text(f"DROP OWNED BY {MIGRATOR_ROLE}, {ALIEN_ROLE}"))
        for role in (MIGRATOR_ROLE, ALIEN_ROLE):
            await conn.execute(text(f"DROP ROLE IF EXISTS {role}"))


@pytest.fixture
async def alien_owned_reviews(varchar_db, migrator_owned):
    """``migrator_owned`` with ONE table handed to a role the migrator is not in.

    ``artifact_reviews`` moves to ``art_uuid_alien`` with a NULL acl, so the
    migrator ends up with neither ownership nor any column privilege on it —
    which is simultaneously

    * the ownership-guard case (``pg_has_role(...,'USAGE')`` is false), and
    * the information_schema-invisibility case (the view's WHERE clause is
      ``pg_has_role(relowner,'USAGE') OR has_column_privilege(...)``, and both
      disjuncts are now false).

    Those two are the SAME state and cannot be separated — see the note on
    TestCatalogSource.
    """
    async with varchar_db.begin() as conn:
        await conn.execute(text(f"ALTER TABLE artifact_reviews OWNER TO {ALIEN_ROLE}"))
    return migrator_owned


# ---------------------------------------------------------------------------
# Seeds. Every INSERT writes the legacy STRING 'n8n-dev' into a tenant column and
# therefore cannot run at all unless the pre-state was really forced.
# ---------------------------------------------------------------------------

_INSERT_ARTIFACT = text(
    """
    INSERT INTO artifacts (
        id, tenant_id, tenant_name, subject_id, visibility, project_id, version,
        filename, content_type, kind, sensitivity, size, sha256, storage_key,
        created_by, created_at, origin_kind, created_by_user_id, status
    ) VALUES (
        :id, :tenant_id, :tenant_name, :subject_id, 'tenant', :project_id, 1,
        'f.txt', 'text/plain', 'doc', 'internal', 100, 'abc123', :storage_key,
        :created_by, now(), 'tenant', '', 'pending'
    )
    """
)

_INSERT_REVIEW = text(
    """
    INSERT INTO artifact_reviews (
        id, artifact_id, decision, comment, reviewer_id, reviewer_tenant_id, reviewed_at
    ) VALUES (
        :id, :artifact_id, 'approve', NULL, :reviewer_id, :reviewer_tenant_id, now()
    )
    """
)


async def _insert_artifact(
    conn,
    row_id: uuid.UUID,
    tenant_id: str,
    *,
    tenant_name: str | None = None,
    subject_id: str = "",
) -> None:
    await conn.execute(
        _INSERT_ARTIFACT,
        {
            "id": row_id,
            "tenant_id": tenant_id,
            "tenant_name": tenant_id if tenant_name is None else tenant_name,
            "subject_id": subject_id,
            "project_id": PROJECT_ID,
            "storage_key": f"projects/{PROJECT_ID}/{row_id}/v1/f.txt",
            "created_by": tenant_id,
        },
    )


async def _insert_review(
    conn, row_id: uuid.UUID, artifact_id: uuid.UUID, reviewer_tenant_id: str
) -> None:
    await conn.execute(
        _INSERT_REVIEW,
        {
            "id": row_id,
            "artifact_id": artifact_id,
            "reviewer_id": "some-subject",
            "reviewer_tenant_id": reviewer_tenant_id,
        },
    )


async def _seed_corpus(
    conn,
    *,
    with_reviews: bool = True,
    with_legacy_reviews: bool = False,
    with_destination_row: bool = True,
) -> None:
    """The corpus: legacy rows, another real tenant's rows, and a control.

    ``subject_id`` deliberately carries the SAME legacy literal on the legacy
    artifacts — that is the 224-row population the migration refuses to touch
    because it is an authz key (``src/repositories/visibility.py:29,34``).

    ⛔ ``with_legacy_reviews`` DEFAULTS TO FALSE, AND THAT DEFAULT IS AN
    ASSERTION ABOUT THE MIGRATION'S CONTRACT, not a convenience.
    ``artifact_reviews`` has no ``tenant_name`` column, so a row of it holding
    the legacy literal can be remapped but never un-remapped —
    ``_assert_legacy_rows_have_provenance`` therefore REFUSES the whole upgrade
    when one exists. The default corpus is production's measured state (0 legacy
    reviews) so that the ordinary upgrade tests exercise an upgrade that RUNS;
    the flag turns on the refusal case, and only ``TestProvenanceGuard`` sets it.

    ``with_reviews`` still seeds ``R_OTHER`` — reviews under a real uuid, which
    are castable and must survive the ALTER untouched. Without them the
    ``reviewer_tenant_id`` column would be empty in every test and its re-typing
    would be asserted against zero rows.
    """
    for row_id in A_LEGACY:
        await _insert_artifact(conn, row_id, LEGACY, subject_id=LEGACY)
    for row_id in A_OTHER:
        await _insert_artifact(
            conn, row_id, OTHER_TENANT_UUID, tenant_name="platform-cp-1", subject_id="someone"
        )
    if with_destination_row:
        # A row LEGITIMATELY written under the real tenant. Production measured 0
        # of these at migration time, but a downgrade happens later — after the
        # gate is live and such rows exist — so it is seeded here as the control
        # for two separate things: the audit must count the LEGACY value and not
        # the destination population, and ``downgrade()`` must not sweep it back
        # to 'n8n-dev'.
        #
        # ``tenant_name`` is the destination UUID STRING, not 'n8n-dev'. That is
        # what the live rows actually hold: tenant_name is a copy of tenant_id on
        # 51,238 of 51,238 rows, because nothing populates a resolved display
        # label yet. It is also exactly the discriminator downgrade() relies on,
        # and the migration names the day it expires.
        await _insert_artifact(
            conn, A_DESTINATION, N8N_DEV_UUID, tenant_name=N8N_DEV_UUID, subject_id="someone"
        )
    if with_legacy_reviews:
        for row_id in R_LEGACY:
            await _insert_review(conn, row_id, A_LEGACY[0], LEGACY)
    if with_reviews:
        for row_id in R_OTHER:
            await _insert_review(conn, row_id, A_OTHER[0], OTHER_TENANT_UUID)


# ---------------------------------------------------------------------------
# THE VACUITY CONTROL. If this class fails, nothing else in the file means
# anything — read the module docstring.
# ---------------------------------------------------------------------------


class TestPreStateIsVarchar:
    async def test_both_columns_are_varchar_255_before_the_migration(self, varchar_db) -> None:
        """The tripwire. The migration must have real work to do.

        ``upgrade()`` early-returns the moment both columns already read ``uuid``
        from ``pg_catalog``, skipping the ownership guard, the audit table, the
        remap, both abort guards and both ALTERs. Every other test in this file
        asserts against a run that reached those. If this fails, they are all
        asserting against a ``return``.
        """
        async with varchar_db.connect() as conn:
            types = await _column_types(conn)
        assert types == {target: "character varying(255)" for target in TENANT_TARGETS}, (
            f"the varchar pre-state was NOT forced; measured {types}. Every "
            "assertion in this file is vacuous until this passes."
        )

    async def test_the_default_pytest_schema_is_already_uuid_which_is_the_trap(
        self, uuid_db
    ) -> None:
        """The other half: the suite's DEFAULT state is already migrated.

        ``Base.metadata.create_all`` builds both columns from
        ``Uuid(as_uuid=False)``, so a test that just calls ``command.upgrade``
        exercises nothing at all. This asserts the trap is REAL, so
        ``_force_varchar_pre_state`` cannot be deleted as redundant.
        """
        async with uuid_db.connect() as conn:
            types = await _column_types(conn)
        assert types == {target: "uuid" for target in TENANT_TARGETS}, (
            f"expected create_all to hand us uuid columns, measured {types}"
        )

    async def test_the_corpus_cannot_be_seeded_without_the_forced_pre_state(self, uuid_db) -> None:
        """Self-enforcing control: the corpus is unseedable against uuid columns.

        This is why no other test here can quietly degrade into a no-op — if the
        pre-state stops being forced, the seed dies rather than going green.
        """
        with pytest.raises(DBAPIError) as excinfo:
            async with uuid_db.begin() as conn:
                await _seed_corpus(conn)
        # `.orig` is the psycopg diagnostic alone; `str(excinfo.value)` would also
        # echo the whole INSERT, which names uuid columns anyway and would make
        # this assertion pass for the wrong reason.
        assert "invalid input syntax for type uuid" in str(excinfo.value.orig)


# ---------------------------------------------------------------------------
# Chain wiring
# ---------------------------------------------------------------------------


class TestRevisionChain:
    def test_20260826_0003_sits_directly_after_20260519_0002(self) -> None:
        """One head, and the whole ancestry is the expected list.

        Two heads make ``alembic upgrade head`` ambiguous and one branch silently
        never runs; a revision spliced between 0002 and 0003 would keep the
        direct parent link and still change what the init container executes,
        which is why the full chain is compared rather than just the pair.
        """
        script = ScriptDirectory.from_config(_alembic_config())

        heads = list(script.get_heads())
        assert len(heads) == 1, f"migration chain has branched: {heads}"

        chain: list[str] = []
        rev: str | None = REVISION
        while rev is not None:
            chain.append(rev)
            down = script.get_revision(rev).down_revision
            assert not isinstance(down, tuple), f"{rev} is a merge revision: {down}"
            rev = down

        assert chain[1] == PREVIOUS_REVISION, (
            f"{REVISION} must sit directly after {PREVIOUS_REVISION}, not {chain[1]}"
        )
        assert tuple(chain) == EXPECTED_CHAIN
        assert len(chain) == len(EXPECTED_CHAIN) == 8

        ancestry = {r.revision for r in script.iterate_revisions(heads[0], "base")}
        assert REVISION in ancestry, f"{REVISION} is not an ancestor of head {heads[0]}"

    def test_revision_id_fits_the_alembic_version_column(self) -> None:
        """``alembic_version.version_num`` is varchar(32)."""
        assert len(REVISION) <= 32


# ---------------------------------------------------------------------------
# The remap
# ---------------------------------------------------------------------------


class TestRemap:
    async def test_upgrade_remaps_exactly_the_n8n_dev_rows_and_leaves_others_alone(
        self, varchar_db
    ) -> None:
        """The whole contract: the named tenant moves, nothing else does.

        ``platform-cp-1`` is the control. An over-broad ``UPDATE`` (no WHERE, or a
        WHERE on the wrong column) would move it too and every positive assertion
        would still pass.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            for row_id in A_LEGACY:
                assert await _tenant_of(conn, "artifacts", "tenant_id", row_id) == N8N_DEV_UUID, (
                    f"artifacts {row_id} was not remapped onto the registry uuid"
                )
            for row_id in A_OTHER:
                got = await _tenant_of(conn, "artifacts", "tenant_id", row_id)
                assert got == OTHER_TENANT_UUID, (
                    f"artifacts {row_id} belongs to another tenant and moved to {got} — "
                    "that is a cross-tenant merge"
                )
            assert await _tenant_of(conn, "artifacts", "tenant_id", A_DESTINATION) == N8N_DEV_UUID
            # No R_LEGACY rows to check: a legacy review makes the upgrade REFUSE
            # outright (TestProvenanceGuard), because artifact_reviews has no
            # tenant_name and so could never be un-remapped. What must hold here
            # is that the castable reviews are re-typed and NOT moved.
            for row_id in R_OTHER:
                got = await _tenant_of(conn, "artifact_reviews", "reviewer_tenant_id", row_id)
                assert got == OTHER_TENANT_UUID, (
                    f"artifact_reviews {row_id} belongs to another tenant and moved to {got}"
                )

            # And no row anywhere still carries the literal.
            res = await conn.execute(
                text("SELECT count(*) FROM artifacts WHERE tenant_id::text = :v"),
                {"v": LEGACY},
            )
            assert res.scalar_one() == 0

    async def test_row_count_is_conserved(self, varchar_db) -> None:
        """Nothing is deleted. The migration issues only UPDATE and ALTER.

        Both FKs into ``artifacts`` are ``ON DELETE CASCADE``, so a single stray
        DELETE would take ``artifact_tags`` and ``artifact_reviews`` rows with it
        without any error being raised.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)
            await conn.execute(
                text("INSERT INTO artifact_tags (artifact_id, tag) VALUES (:a, 'tag-1')"),
                {"a": A_LEGACY[0]},
            )

        tables = ("artifacts", "artifact_reviews", "artifact_tags")
        async with varchar_db.connect() as conn:
            before = {t: await _count(conn, t) for t in tables}
        assert before == {
            "artifacts": LEGACY_ARTIFACTS + len(A_OTHER) + 1,
            "artifact_reviews": len(R_OTHER),
            "artifact_tags": 1,
        }, f"the corpus did not seed as expected: {before}"

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            after = {t: await _count(conn, t) for t in tables}
        assert after == before, f"rows disappeared: before={before} after={after}"

    async def test_tenant_name_is_deliberately_not_touched(self, varchar_db) -> None:
        """``tenant_name`` still reads ``n8n-dev`` — the surviving provenance.

        It is the human display label for ``019de842-…`` and, for these rows, the
        only record of where they came from. Re-typing or rewriting it would
        destroy the crosswalk the migration relies on being readable afterwards.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            res = await conn.execute(
                text("SELECT tenant_name FROM artifacts WHERE id = ANY(:ids)"),
                {"ids": list(A_LEGACY)},
            )
            names = sorted(r[0] for r in res)
            assert names == [LEGACY] * LEGACY_ARTIFACTS, (
                f"tenant_name was rewritten to {names}; it is the only surviving "
                "provenance for these rows"
            )
            assert await _one_column_type(conn, "artifacts", "tenant_name") == (
                "character varying(255)"
            )

    async def test_subject_id_is_deliberately_not_touched_and_stays_varchar(
        self, varchar_db
    ) -> None:
        """``subject_id`` is an AUTHZ key, not a spare label.

        ``src/repositories/visibility.py:29`` narrows reads with
        ``model.subject_id == subject_id`` for ``visibility='user'`` rows and
        ``can_mutate()`` (:34) gates WRITES on it. Remapping it in the same pass —
        the obvious-looking "finish the set" move, 224 rows in production —
        changes WHO may mutate those rows inside a change whose entire contract
        is the TYPE of a different column.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            res = await conn.execute(
                text("SELECT subject_id FROM artifacts WHERE id = ANY(:ids)"),
                {"ids": list(A_LEGACY)},
            )
            subjects = sorted(r[0] for r in res)
            assert subjects == [LEGACY] * LEGACY_ARTIFACTS, (
                f"subject_id was rewritten to {subjects} — that is a silent "
                "authorization change wearing a typing change's clothes"
            )
            assert await _one_column_type(conn, "artifacts", "subject_id") == (
                "character varying(255)"
            ), "subject_id must stay varchar; it holds legacy labels, not uuids"


class TestRemapAudit:
    async def test_audit_row_records_the_count_before_the_update(self, varchar_db) -> None:
        """The count must be taken BEFORE the UPDATE, per column.

        Afterwards the legacy value no longer exists to be counted, so a count
        taken after the rewrite is always 0 — and ``downgrade()`` bounds its
        replay on ``row_count > 0``, so a 0 there silently turns the downgrade
        into a no-op that leaves the rows on the new uuid forever.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            rows = await _audit_rows(conn)

        artifacts_key = (migration._audit_key("artifacts", "tenant_id"), LEGACY)
        reviews_key = (migration._audit_key("artifact_reviews", "reviewer_tenant_id"), LEGACY)
        assert set(rows) == {artifacts_key, reviews_key}, (
            f"audit must hold one row per (table.column, legacy value); got {sorted(rows)}"
        )
        assert rows[artifacts_key] == (LEGACY_ARTIFACTS, N8N_DEV_UUID), (
            f"artifacts audit is {rows[artifacts_key]}, expected "
            f"({LEGACY_ARTIFACTS}, {N8N_DEV_UUID}) — a 0 here means the count was "
            "taken after the UPDATE"
        )
        # ZERO, and asserted rather than omitted. The audit row still EXISTS —
        # `_remap` writes one per (table, column) whether or not it moved
        # anything — and `downgrade()` skips the replay on `row_count > 0`. A
        # non-zero here would mean the corpus contained a legacy review, which
        # `_assert_legacy_rows_have_provenance` refuses before this point.
        assert rows[reviews_key] == (0, N8N_DEV_UUID)
        # The key is table.COLUMN, not the bare table: artifacts and
        # artifact_reviews would collide the moment a second column on one table
        # joins the remap, and downgrade() parses this key to know which column
        # to restore.
        assert artifacts_key[0] == "artifacts.tenant_id"
        assert reviews_key[0] == "artifact_reviews.reviewer_tenant_id"

    async def test_a_stale_audit_row_is_overwritten_not_kept(self, varchar_db) -> None:
        """``ON CONFLICT DO UPDATE``, never ``DO NOTHING``.

        A partial earlier attempt can leave an audit row behind. Under
        ``DO NOTHING`` that stale row is KEPT and this run's real counts are
        discarded, producing an audit that under-reports what was rewritten — and
        an audit that under-reports is worse than no audit, because it is
        believed. The stale row here names the WRONG destination tenant on
        purpose: that is the cross-tenant value a downgrade would replay.
        """
        stale_key = migration._audit_key("artifacts", "tenant_id")
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)
            await conn.run_sync(migration._create_audit_table)
            await conn.execute(
                text(
                    f"INSERT INTO {AUDIT_TABLE} "
                    "(table_name, legacy_value, row_count, new_value) "
                    "VALUES (:t, :legacy, :n, :new)"
                ),
                {"t": stale_key, "legacy": LEGACY, "n": 999999, "new": OTHER_TENANT_UUID},
            )

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            rows = await _audit_rows(conn)

        assert rows[(stale_key, LEGACY)] == (LEGACY_ARTIFACTS, N8N_DEV_UUID), (
            f"the stale audit row survived as {rows[(stale_key, LEGACY)]} — "
            "ON CONFLICT DO NOTHING keeps a wrong count AND a wrong destination"
        )


# ---------------------------------------------------------------------------
# The guards. Each must ABORT and NAME what it refused, never coerce.
# ---------------------------------------------------------------------------


class TestGuardsCanFire:
    """⛔ THE NON-VACUITY CONTROL FOR THE TWO PRIVILEGE GUARDS BELOW.

    Both of those tests assert that a guard FIRES. An assertion that something
    fires is only worth having if the thing is capable of not firing, and both
    guards rest on predicates —  ``pg_has_role(current_user, relowner, 'USAGE')``
    and ``information_schema``'s visibility filter — that are unconditionally
    TRUE for a superuser. Run as ``postgres`` neither can ever be false, so
    ``pytest.raises`` there is testing nothing at all.

    That is not hypothetical: it is exactly what CI did. The archetype exports
    ``DATABASE_URL``, ``env.py`` prefers it over the ``POSTGRES_*`` family the
    fixture was setting, alembic reconnected as the sidecar superuser and both
    guard tests reported ``DID NOT RAISE`` — while passing on every laptop, where
    ``DATABASE_URL`` is unset and the override happened to win.

    So this class measures the two preconditions directly, and it must run in the
    SAME environment as the guards it vouches for. If either test here fails, the
    two below prove nothing regardless of their own colour.
    """

    async def test_the_migrator_role_is_not_superuser(self, varchar_db, migrator_owned) -> None:
        """The guard predicate is genuinely FALSE for the role we hand alembic.

        Measured through a connection opened on the fixture's own URL, so this
        asserts about the identity the migration actually authenticates as — not
        about the role the fixture intended to create.
        """

        def _probe(conn):
            return conn.execute(
                sa.text(
                    "SELECT current_user::text, "
                    "(SELECT usesuper FROM pg_user WHERE usename = current_user), "
                    "pg_has_role(current_user, :alien, 'USAGE')"
                ),
                {"alien": ALIEN_ROLE},
            ).one()

        who, is_super, in_alien = await asyncio.to_thread(_query_as, migrator_owned, _probe)

        assert who == MIGRATOR_ROLE, (
            f"the fixture URL authenticates as {who}, not {MIGRATOR_ROLE} — the "
            "guard tests below are measuring some other role's privileges"
        )
        assert is_super is False, (
            f"{MIGRATOR_ROLE} is a superuser, so pg_has_role and "
            "information_schema are unconditionally permissive for it and "
            "neither guard below is able to fire"
        )
        assert in_alien is False, (
            f"{MIGRATOR_ROLE} is a member of {ALIEN_ROLE}, so the ownership "
            "guard's predicate is true and the abort it asserts cannot happen"
        )

    async def test_migration_uses_the_dsn_it_was_given(self, varchar_db, migrator_owned) -> None:
        """``_run_upgrade(url)`` connects as ``url``, whatever the ambient env says.

        Proved by a side effect the database records for us: ``CREATE TABLE``
        stamps ``relowner`` with whoever ran it, so the audit table's owner IS
        the identity alembic authenticated as. Under the CI defect this reads
        ``postgres``.

        This is the arm a ``pytest.raises`` cannot supply: the guard tests hand
        alembic a non-superuser URL and would report a plain green pass if that
        URL were ignored in favour of a superuser one.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db, migrator_owned)

        def _owner_of_audit(conn):
            return conn.execute(
                sa.text(
                    "SELECT pg_get_userbyid(relowner)::text "
                    "FROM pg_class WHERE oid = CAST(:t AS regclass)"
                ),
                {"t": AUDIT_TABLE},
            ).scalar_one()

        owner = await asyncio.to_thread(_query_as, migrator_owned, _owner_of_audit)
        assert owner == MIGRATOR_ROLE, (
            f"{AUDIT_TABLE} is owned by {owner}, so alembic ignored the URL the "
            f"test handed it and connected as {owner} instead — every privilege "
            "assertion in this file is measuring the wrong role"
        )


class TestOwnershipGuard:
    async def test_a_table_owned_by_another_role_aborts_by_name(
        self, varchar_db, alien_owned_reviews
    ) -> None:
        """``ALTER TABLE`` needs ownership, not write access.

        One clean named abort costs a retry; failing halfway through the ALTERs
        during a single-replica deploy is an outage with no old pod still
        serving. The guard is measured as a NON-superuser: a superuser is a
        member of every role, so ``pg_has_role`` is unconditionally true and the
        guard is structurally unable to fire.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        with pytest.raises(RuntimeError) as excinfo:
            await _run_upgrade(varchar_db, alien_owned_reviews)

        message = str(excinfo.value)
        assert f"artifact_reviews owned by {ALIEN_ROLE}" in message, (
            f"the guard did not name the table it refused: {message}"
        )
        # ...and did NOT drag in the table it does own. A guard that names
        # everything names nothing.
        assert "artifacts owned by" not in message, (
            f"the guard named a table the role legitimately owns: {message}"
        )

        # One transaction: the abort leaves the database exactly as it was.
        async with varchar_db.connect() as conn:
            await _assert_pre_state(conn)
            assert not await _table_exists(conn, AUDIT_TABLE), (
                "the audit table survived an aborted run"
            )
            assert await _tenant_of(conn, "artifacts", "tenant_id", A_LEGACY[0]) == LEGACY


class TestCatalogSource:
    async def test_a_table_invisible_to_information_schema_is_still_found(
        self, varchar_db, alien_owned_reviews
    ) -> None:
        """The defect that reports success while skipping a column.

        ``information_schema.columns`` is privilege-filtered:

            WHERE … AND (pg_has_role(c.relowner,'USAGE')
                         OR has_column_privilege(c.oid, a.attnum, 'SELECT,…'))

        A table the migration role can neither reach nor claim membership of
        DISAPPEARS from that view. Had ``_live_columns`` read it, the work list
        would have silently lost ``artifact_reviews.reviewer_tenant_id`` — and
        the postcondition re-reads the SAME source, so it would not have noticed
        either. The guard and the defect would share a source, and the run would
        report success having left a varchar column the application immediately
        starts writing uuids into.

        ⚠️ NOTE ON WHAT CANNOT BE TESTED HERE. "Invisible to information_schema"
        and "not owned by this role" are the SAME state — the view's first
        disjunct is exactly the ownership guard's predicate. So an invisible
        table can never be processed to completion; the strongest honest claim is
        that it is (a) genuinely invisible, (b) still FOUND by ``_live_columns``,
        and (c) therefore refused BY NAME instead of skipped in silence. That
        third arm is the whole point: silence is the failure mode.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        def _probe(conn):
            found = set(migration._live_columns(conn, TENANT_COLUMNS))
            visible = {
                (r[0], r[1])
                for r in conn.execute(
                    sa.text(
                        "SELECT table_name::text, column_name::text "
                        "FROM information_schema.columns "
                        "WHERE table_schema::text = current_schema()::text "
                        "AND column_name::text = ANY(:cols)"
                    ),
                    {"cols": [c for _, c in TENANT_TARGETS]},
                ).all()
            }
            return found, visible

        found, visible = await asyncio.to_thread(_query_as, alien_owned_reviews, _probe)

        hidden = ("artifact_reviews", "reviewer_tenant_id")
        # (a) the trap is real for this role
        assert hidden not in visible, (
            "information_schema still shows the alien-owned column, so this test "
            f"is not exercising the privilege filter at all: {sorted(visible)}"
        )
        assert ("artifacts", "tenant_id") in visible, (
            "the role lost sight of BOTH columns — the fixture over-revoked and "
            "the comparison below would be trivially true"
        )
        # (b) pg_catalog is not privilege-filtered, so the migration still sees it
        assert found == set(TENANT_TARGETS), (
            f"_live_columns lost a column the role cannot see: {sorted(found)}"
        )

        # (c) and it is therefore refused BY NAME rather than skipped in silence
        with pytest.raises(RuntimeError) as excinfo:
            await _run_upgrade(varchar_db, alien_owned_reviews)
        assert "artifact_reviews" in str(excinfo.value)

        async with varchar_db.connect() as conn:
            await _assert_pre_state(conn)


class TestTotalityGuard:
    async def test_a_value_written_after_the_census_aborts_and_is_not_coerced(
        self, varchar_db
    ) -> None:
        """A value nobody planned for is a human decision, not a cleanup.

        ``_assert_cast_is_total`` runs AFTER the remap, so it sees the population
        the ALTER will really cast — which is how it catches a label the OLD pod
        wrote between the pre-deploy census and this statement. It must abort,
        naming the value, and must neither sweep it into REMAP nor delete it.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)
            await _insert_artifact(conn, A_UNLISTED, UNLISTED_LABEL)

        with pytest.raises(RuntimeError) as excinfo:
            await _run_upgrade(varchar_db)

        message = str(excinfo.value)
        assert "the uuid cast is NOT total" in message
        assert UNLISTED_LABEL in message, f"the guard did not name the value: {message}"

        async with varchar_db.connect() as conn:
            # Not coerced, not deleted, and the whole transaction rolled back.
            assert await _tenant_of(conn, "artifacts", "tenant_id", A_UNLISTED) == UNLISTED_LABEL, (
                "the unlisted value was rewritten rather than refused"
            )
            assert await _tenant_of(conn, "artifacts", "tenant_id", A_LEGACY[0]) == LEGACY, (
                "the remap was not rolled back by the abort"
            )
            assert not await _table_exists(conn, AUDIT_TABLE)
            await _assert_pre_state(conn)


class TestCollisionGuard:
    async def test_two_spellings_of_one_uuid_abort_rather_than_merge(self, varchar_db) -> None:
        """Two varchar silos, one uuid: the cast MERGES them silently.

        ``0195F48B-…`` (uppercase) and the dashless form are distinct text values
        and one uuid. Under ``varchar`` equality they are separate tenants; the
        ALTER folds them together and nothing else in the migration would notice.
        The merge may well be correct — but it is a decision about whose rows
        become whose, and this migration's contract is a type change plus one
        named remap. Nothing else.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)
            await _insert_artifact(conn, A_UPPER, OTHER_TENANT_UPPER)
            await _insert_artifact(conn, A_DASHLESS, OTHER_TENANT_DASHLESS)

        with pytest.raises(RuntimeError) as excinfo:
            await _run_upgrade(varchar_db)

        message = str(excinfo.value)
        assert "refusing to MERGE tenants" in message
        for spelling in (OTHER_TENANT_UUID, OTHER_TENANT_UPPER, OTHER_TENANT_DASHLESS):
            assert spelling in message, (
                f"the guard did not name the colliding spelling {spelling}: {message}"
            )

        async with varchar_db.connect() as conn:
            assert (
                await _tenant_of(conn, "artifacts", "tenant_id", A_UPPER) == OTHER_TENANT_UPPER
            ), "a colliding spelling was rewritten instead of refused"
            assert (
                await _tenant_of(conn, "artifacts", "tenant_id", A_DASHLESS)
                == OTHER_TENANT_DASHLESS
            )
            await _assert_pre_state(conn)


# ---------------------------------------------------------------------------
# The happy path's shape
# ---------------------------------------------------------------------------


class TestTypesAfter:
    async def test_both_columns_are_uuid_and_every_tenant_index_survives_and_is_valid(
        self, varchar_db
    ) -> None:
        """Eight btree indexes lead with ``tenant_id``.

        Postgres rebuilds them in place as part of ``ALTER … TYPE``; the migration
        deliberately does not drop and recreate them, so this asserts the set is
        unchanged AND that every one of them is ``indisvalid`` — an invalid index
        is still listed in ``pg_indexes`` and is silently ignored by the planner,
        which turns a tenant-scoped query into a seq scan over every tenant.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        async with varchar_db.connect() as conn:
            before = _tenant_id_indexes(await _artifact_indexes(conn))
        assert EXPECTED_TENANT_INDEXES <= set(before), (
            "the pre-state is missing tenant_id indexes this test is supposed to "
            f"be watching: {sorted(EXPECTED_TENANT_INDEXES - set(before))}"
        )

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            types = await _column_types(conn)
            after = _tenant_id_indexes(await _artifact_indexes(conn))

        assert types == {target: "uuid" for target in TENANT_TARGETS}, (
            f"the migration did not complete: {types}"
        )
        assert set(after) == set(before), (
            f"tenant_id index set changed: dropped={sorted(set(before) - set(after))}, "
            f"added={sorted(set(after) - set(before))}"
        )
        invalid = sorted(name for name, valid in after.items() if not valid)
        assert not invalid, f"these indexes survived the ALTER but are NOT valid: {invalid}"


class TestZeroArms:
    async def test_empty_artifact_reviews_is_a_no_op_not_a_crash(self, varchar_db) -> None:
        """``artifact_reviews`` is EMPTY in production (0 rows measured).

        The init container runs this on every roll, and CI runs it against a
        brand-new ``postgres:18``. Nothing to remap must not be an error — and the
        audit must still record the 0, because ``downgrade()`` reads
        ``row_count > 0`` to decide what it is entitled to move back.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_reviews=False)

        async with varchar_db.connect() as conn:
            assert await _count(conn, "artifact_reviews") == 0, "precondition"

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            types = await _column_types(conn)
            rows = await _audit_rows(conn)
        assert types == {target: "uuid" for target in TENANT_TARGETS}
        reviews_key = (migration._audit_key("artifact_reviews", "reviewer_tenant_id"), LEGACY)
        assert rows[reviews_key] == (0, N8N_DEV_UUID), (
            f"the empty arm must still be audited, got {rows.get(reviews_key)}"
        )


class TestIdempotency:
    async def test_a_second_upgrade_is_a_clean_no_op(self, varchar_db) -> None:
        """A re-run on an already-migrated database must change nothing.

        The init container re-runs on every pod roll. The early return is what
        makes that safe — and it must NOT re-enter ``_remap``, which would
        overwrite the audit's real counts with 0 (there is no ``n8n-dev`` left to
        count) and destroy ``downgrade()``'s only record of what to move back.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn)

        await _run_upgrade(varchar_db)
        async with varchar_db.connect() as conn:
            first_types = await _column_types(conn)
            first_audit = await _audit_rows(conn)

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            second_types = await _column_types(conn)
            second_audit = await _audit_rows(conn)
            for row_id in A_LEGACY:
                assert await _tenant_of(conn, "artifacts", "tenant_id", row_id) == N8N_DEV_UUID

        assert second_types == first_types == {t: "uuid" for t in TENANT_TARGETS}
        assert second_audit == first_audit, (
            f"the second run rewrote the audit: {first_audit} -> {second_audit}"
        )


class TestDowngrade:
    async def test_downgrade_restores_varchar_reverses_the_remap_and_drops_the_audit_table(
        self, varchar_db
    ) -> None:
        """Real and lossless, because nothing was deleted.

        Order is load-bearing: the columns must go back to ``varchar`` FIRST,
        because the reverse remap writes the literal ``n8n-dev``, which a ``uuid``
        column cannot hold.

        ``A_DESTINATION`` is the load-bearing control. It sits on
        ``019de842-…`` legitimately, and the naive reverse ::

            UPDATE artifacts SET tenant_id = 'n8n-dev' WHERE tenant_id = '019de842-…'

        would relabel it as well — a data-loss bug that ``row_count > 0`` cannot
        catch, because that filter decides only WHETHER the statement runs, never
        WHICH rows it hits. The reverse must be scoped by the provenance column.

        ``artifact_reviews`` is seeded empty, which is production's measured
        state and the only state in which this table can be reversed at all — see
        the companion test.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_reviews=False, with_destination_row=True)

        async with varchar_db.connect() as conn:
            before_counts = {t: await _count(conn, t) for t in ("artifacts", "artifact_reviews")}

        await _run_upgrade(varchar_db)
        await _run_downgrade(varchar_db)

        async with varchar_db.connect() as conn:
            await _assert_pre_state(conn)

            for row_id in A_LEGACY:
                got = await _tenant_of(conn, "artifacts", "tenant_id", row_id)
                assert got == LEGACY, f"artifacts {row_id} came back as {got}, not {LEGACY}"
            for row_id in A_OTHER:
                assert (
                    await _tenant_of(conn, "artifacts", "tenant_id", row_id) == OTHER_TENANT_UUID
                ), "the reverse remap reached another tenant's rows"

            assert (
                await _tenant_of(conn, "artifacts", "tenant_id", A_DESTINATION) == N8N_DEV_UUID
            ), (
                "a row legitimately written under the real tenant was relabelled "
                "'n8n-dev' by the downgrade — the reverse UPDATE is not scoped by "
                f"{PROVENANCE_COLUMN!r}"
            )

            assert not await _table_exists(conn, AUDIT_TABLE), (
                "the audit table outlived the downgrade"
            )
            after_counts = {t: await _count(conn, t) for t in ("artifacts", "artifact_reviews")}
        assert after_counts == before_counts, (
            f"the round trip lost rows: {before_counts} -> {after_counts}"
        )

    async def test_downgrade_still_refuses_a_database_upgraded_by_an_earlier_build(
        self, varchar_db
    ) -> None:
        """The RESIDUAL branch, and it can no longer be reached from a fresh upgrade.

        Before ``_assert_legacy_rows_have_provenance`` existed, a single
        ``artifact_reviews`` row holding ``'n8n-dev'`` was remapped, audited, and
        then unreversible: ``downgrade()`` reached that audit row, found no
        ``tenant_name`` on the table, and raised — INSIDE alembic's single
        downgrade transaction, so the two type-widening ALTERs rolled back with
        it and ``artifacts`` was not reverted either. Identically on every retry.
        That is the one-way door.

        ``upgrade()`` now refuses those rows before writing anything, so a
        database upgraded by THIS revision cannot produce such an audit row. This
        test therefore FORGES one — which is exactly the residue an earlier build
        of this file left behind — and asserts the refusal still fires and still
        names the column, because for that database refusing really is the right
        answer.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_destination_row=False)

        await _run_upgrade(varchar_db)

        # The residue of an upgrade run by the PREVIOUS build: an audit row
        # claiming rows were moved on a table with no witness column.
        async with varchar_db.begin() as conn:
            await conn.execute(
                text(
                    f"UPDATE {AUDIT_TABLE} SET row_count = :n "
                    "WHERE table_name = :t AND legacy_value = :legacy"
                ),
                {
                    "n": LEGACY_REVIEWS,
                    "t": migration._audit_key("artifact_reviews", "reviewer_tenant_id"),
                    "legacy": LEGACY,
                },
            )

        with pytest.raises(RuntimeError) as excinfo:
            await _run_downgrade(varchar_db)

        message = str(excinfo.value)
        assert "cannot safely reverse artifact_reviews.reviewer_tenant_id" in message, (
            f"the refusal did not name the column it could not reverse: {message}"
        )
        assert PROVENANCE_COLUMN in message
        assert str(LEGACY_REVIEWS) in message, (
            f"the refusal did not say how many rows are stranded: {message}"
        )

        # One transaction: the refusal rolls the ALTERs back too, so the database
        # is left MIGRATED rather than half-reverted. This is the damage the
        # upgrade-time guard exists to make unreachable.
        async with varchar_db.connect() as conn:
            types = await _column_types(conn)
            assert types == {target: "uuid" for target in TENANT_TARGETS}, (
                f"the failed downgrade left a half-reverted schema: {types}"
            )
            assert await _table_exists(conn, AUDIT_TABLE), (
                "the audit table was dropped by a downgrade that refused to run — "
                "that discards the only record of what to restore"
            )

    async def test_downgrade_refuses_to_relabel_more_rows_than_the_audit_recorded(
        self, varchar_db
    ) -> None:
        """The KNOWN EXPIRY CONDITION, arriving — and detected instead of silent.

        ``downgrade()`` scopes the reverse by ``tenant_name = 'n8n-dev'``, which
        works only while nothing else writes that label. The middleware CAN mint
        it: ``request.state.tenant_name`` comes straight from ``X-Tenant-Name``,
        so a caller sending the correct uuid plus ``X-Tenant-Name: n8n-dev``
        creates a row that legitimately holds ``019de842-…`` and is labelled
        ``n8n-dev``. The reverse UPDATE matches it and drags it to a tenant that
        does not exist — silently, and the audit's ``row_count`` filter cannot
        catch it because it decides only WHETHER the statement runs.

        Only the OVER-revert direction raises. Fewer rows than recorded is an
        ordinary DELETE since the upgrade and must not block a correct rollback —
        raising on THAT would rebuild the one-way door in the other direction.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_destination_row=True)

        await _run_upgrade(varchar_db)

        # The look-alike: real tenant, minted display label. Written AFTER the
        # upgrade, which is when a live caller would create it.
        async with varchar_db.begin() as conn:
            await conn.execute(
                text('UPDATE artifacts SET "' + PROVENANCE_COLUMN + '" = :legacy WHERE id = :id'),
                {"legacy": LEGACY, "id": A_DESTINATION},
            )

        with pytest.raises(RuntimeError) as excinfo:
            await _run_downgrade(varchar_db)

        message = str(excinfo.value)
        assert "refusing to complete the downgrade" in message, message
        assert str(LEGACY_ARTIFACTS + 1) in message and str(LEGACY_ARTIFACTS) in message, (
            f"the refusal did not name both counts: {message}"
        )

        # Rolled back whole: the look-alike still holds the real tenant's uuid.
        async with varchar_db.connect() as conn:
            assert (
                await _tenant_of(conn, "artifacts", "tenant_id", A_DESTINATION) == N8N_DEV_UUID
            ), "the over-reverting UPDATE was committed despite the refusal"

    async def test_a_row_deleted_since_the_upgrade_does_not_block_the_rollback(
        self, varchar_db
    ) -> None:
        """The other direction, and it must NOT raise.

        The count check above is deliberately one-sided. A moved row deleted
        between upgrade and downgrade makes ``rowcount < recorded``, which this
        file has always documented as legitimate. Asserting strict equality (the
        shape ``procedure_management`` chose) would turn an ordinary DELETE into
        an un-rollback-able database — the very defect this class exists to close,
        pointed the other way.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_destination_row=True)

        await _run_upgrade(varchar_db)

        async with varchar_db.begin() as conn:
            await conn.execute(text("DELETE FROM artifacts WHERE id = :id"), {"id": A_LEGACY[0]})

        await _run_downgrade(varchar_db)

        async with varchar_db.connect() as conn:
            await _assert_pre_state(conn)
            for row_id in A_LEGACY[1:]:
                assert await _tenant_of(conn, "artifacts", "tenant_id", row_id) == LEGACY, (
                    "a surviving moved row was not reverted"
                )
            assert await _tenant_of(conn, "artifacts", "tenant_id", A_DESTINATION) == N8N_DEV_UUID
            assert not await _table_exists(conn, AUDIT_TABLE)


class TestProvenanceGuard:
    """⛔ D3: a legacy row in a table with no witness column must ABORT THE UPGRADE.

    ``artifact_reviews`` carries ``reviewer_tenant_id`` but no ``tenant_name``.
    Production measured it EMPTY — but the old pod serves right up to the moment
    the init container runs, and ``_assert_cast_is_total``'s own docstring is
    built on that window being real. One review landing in it used to remap
    cleanly and then make ``downgrade()`` raise forever.

    The guard moves that refusal to a point where it costs one clean abort
    instead of a database nobody can roll back.
    """

    async def test_upgrade_refuses_before_writing_anything(self, varchar_db) -> None:
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_legacy_reviews=True, with_destination_row=False)

        with pytest.raises(RuntimeError) as excinfo:
            await _run_upgrade(varchar_db)

        message = str(excinfo.value)
        assert "could never be un-remapped" in message, message
        assert f"artifact_reviews.reviewer_tenant_id: {LEGACY_REVIEWS} row(s)" in message, (
            f"the refusal did not name the table, column and count: {message}"
        )
        assert PROVENANCE_COLUMN in message
        assert LEGACY in message

    async def test_the_refused_upgrade_leaves_the_database_byte_identical(self, varchar_db) -> None:
        """⛔ THE HALF that makes the refusal a FIX rather than a different failure.

        The whole argument for moving the guard is that failing here is
        RECOVERABLE: one transaction, nothing written, retry after the row is
        dealt with. If the abort left an audit table, a partial remap or a
        half-typed column behind, it would just be the one-way door with a
        different error message.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_legacy_reviews=True, with_destination_row=False)

        with pytest.raises(RuntimeError):
            await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            await _assert_pre_state(conn)
            assert not await _table_exists(conn, AUDIT_TABLE), (
                "the refused upgrade left an audit table behind"
            )
            for row_id in A_LEGACY:
                assert await _tenant_of(conn, "artifacts", "tenant_id", row_id) == LEGACY, (
                    "the refused upgrade remapped artifacts before aborting"
                )
            for row_id in R_LEGACY:
                got = await _tenant_of(conn, "artifact_reviews", "reviewer_tenant_id", row_id)
                assert got == LEGACY, f"the refused upgrade remapped review {row_id} to {got}"

    async def test_the_guard_does_not_fire_on_a_castable_review(self, varchar_db) -> None:
        """⛔ THE OVER-REJECTION CONTROL. Every other test here is a refusal test.

        A guard hard-coded to raise would satisfy all of them. ``R_OTHER`` holds
        reviews under a REAL uuid on the same provenance-less table: they are
        castable, they are not in REMAP, and the upgrade must run straight past
        them. Without this, the guard could be "refuse whenever artifact_reviews
        is non-empty" and nothing would notice.
        """
        async with varchar_db.begin() as conn:
            await _seed_corpus(conn, with_legacy_reviews=False, with_destination_row=False)
            assert await _count(conn, "artifact_reviews") == len(R_OTHER), "precondition"

        await _run_upgrade(varchar_db)

        async with varchar_db.connect() as conn:
            types = await _column_types(conn)
            assert types == {target: "uuid" for target in TENANT_TARGETS}, types
            for row_id in R_OTHER:
                got = await _tenant_of(conn, "artifact_reviews", "reviewer_tenant_id", row_id)
                assert got == OTHER_TENANT_UUID, f"a castable review moved to {got}"
