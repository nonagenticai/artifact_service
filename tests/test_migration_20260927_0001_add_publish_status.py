"""Behavioural tests for alembic ``20260927_0001_add_publish_status``.

conftest's ``pg_engine`` builds the schema with ``create_all``, which ALREADY
carries ``publish_status`` — so a test that merely runs the upgrade would pass
against a no-op migration (``ADD COLUMN IF NOT EXISTS``). The fixture therefore
forces the PRE-state (column, CHECK and index dropped) first, and a vacuity
control asserts that pre-state is real.

Alembic plumbing (DSN pinning, ini-less Config) is reused from the 0003 test
module rather than copied: a second copy of the DSN resolution is exactly how a
test ends up migrating a database other than the one it asserts on.
"""

import asyncio

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import models.artifact  # noqa: F401  (populates Base.metadata for pg_engine)
from alembic import command
from tests.conftest import TEST_TENANT_A
from tests.test_migration_20260826_0003_tenant_id_is_a_uuid import (
    _alembic_config,
    _alembic_pointing_at,
    _drop_migration_artifacts,
)

pytestmark = pytest.mark.unit

REVISION = "20260927_0001"
PREVIOUS_REVISION = "20260826_0003"


def _upgrade_sync(url) -> None:
    with _alembic_pointing_at(url):
        cfg = _alembic_config()
        command.stamp(cfg, PREVIOUS_REVISION)
        command.upgrade(cfg, REVISION)


def _downgrade_sync(url) -> None:
    with _alembic_pointing_at(url):
        cfg = _alembic_config()
        command.stamp(cfg, REVISION)
        command.downgrade(cfg, PREVIOUS_REVISION)


async def _has_column(conn) -> bool:
    return bool(
        (
            await conn.execute(
                text(
                    "SELECT 1 FROM pg_attribute WHERE attrelid = 'artifacts'::regclass "
                    "AND attname = 'publish_status' AND NOT attisdropped"
                )
            )
        ).first()
    )


async def _insert_raw(conn, **extra) -> str:
    cols = {
        "id": "gen_random_uuid()",
        "tenant_id": f"'{TEST_TENANT_A}'::uuid",
        "tenant_name": "'t'",
        "project_id": "gen_random_uuid()",
        "version": "1",
        "filename": "'f.txt'",
        "content_type": "'text/plain'",
        "kind": "'doc'",
        "sensitivity": "'internal'",
        "size": "1",
        "sha256": "'x'",
        "storage_key": "'k-' || gen_random_uuid()",
        "created_by": "'t'",
        "created_at": "now()",
        **extra,
    }
    row = await conn.execute(
        text(
            f"INSERT INTO artifacts ({', '.join(cols)}) VALUES ({', '.join(cols.values())}) "
            "RETURNING id::text"
        )
    )
    return row.scalar_one()


@pytest.fixture
async def pre_state_db(pg_engine):
    async with pg_engine.begin() as conn:
        await _drop_migration_artifacts(conn)
        await conn.execute(text("DROP INDEX IF EXISTS ix_artifacts_tenant_publish_status"))
        await conn.execute(
            text("ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifacts_publish_status")
        )
        await conn.execute(text("ALTER TABLE artifacts DROP COLUMN IF EXISTS publish_status"))
    yield pg_engine
    async with pg_engine.begin() as conn:
        await _drop_migration_artifacts(conn)


class TestAddPublishStatus:
    async def test_pre_state_has_no_column(self, pre_state_db):
        """Vacuity control: the upgrade below must have something to add."""
        async with pre_state_db.begin() as conn:
            assert not await _has_column(conn)

    async def test_upgrade_defaults_existing_and_new_rows_to_draft(self, pre_state_db):
        async with pre_state_db.begin() as conn:
            legacy_id = await _insert_raw(conn)

        await asyncio.to_thread(_upgrade_sync, pre_state_db.url)

        async with pre_state_db.begin() as conn:
            assert await _has_column(conn)
            legacy = (
                await conn.execute(
                    text("SELECT publish_status FROM artifacts WHERE id = CAST(:i AS uuid)"),
                    {"i": legacy_id},
                )
            ).scalar_one()
            assert legacy == "draft", "a pre-existing row must NOT come out published"
            new_id = await _insert_raw(conn)
            new = (
                await conn.execute(
                    text("SELECT publish_status FROM artifacts WHERE id = CAST(:i AS uuid)"),
                    {"i": new_id},
                )
            ).scalar_one()
            assert new == "draft"
            idx = (
                await conn.execute(
                    text(
                        "SELECT indexdef FROM pg_indexes WHERE tablename = 'artifacts' "
                        "AND indexname = 'ix_artifacts_tenant_publish_status'"
                    )
                )
            ).scalar_one()
            assert "(tenant_id, publish_status)" in idx

    async def test_check_constraint_rejects_unknown_value(self, pre_state_db):
        await asyncio.to_thread(_upgrade_sync, pre_state_db.url)
        with pytest.raises(DBAPIError, match="ck_artifacts_publish_status"):
            async with pre_state_db.begin() as conn:
                await _insert_raw(conn, publish_status="'public'")

    async def test_downgrade_removes_column(self, pre_state_db):
        await asyncio.to_thread(_upgrade_sync, pre_state_db.url)
        await asyncio.to_thread(_downgrade_sync, pre_state_db.url)
        async with pre_state_db.begin() as conn:
            assert not await _has_column(conn)


class TestRevisionChain:
    def test_directly_follows_0003_on_a_single_head_chain(self) -> None:
        # The head moved on (20261003_0001, art#49); what this revision pins is
        # its place in a linear chain, not that it is forever the head.
        script = ScriptDirectory.from_config(_alembic_config())
        assert len(script.get_heads()) == 1
        assert REVISION in {r.revision for r in script.walk_revisions()}
        assert script.get_revision(REVISION).down_revision == PREVIOUS_REVISION
        assert len(REVISION) <= 32
