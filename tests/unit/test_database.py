"""Tests for database models, constraints, and session management."""

import uuid
from datetime import UTC
from unittest.mock import patch

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from core.database import get_db, get_db_context
from models.artifact import Artifact, ArtifactTag
from models.schemas import ArtifactKind, ArtifactSensitivity
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

PROJECT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


async def _create_artifact(session, *, storage_key=None, tenant_id=TEST_TENANT_A, tags=None, **kw):
    """Insert an Artifact row with sensible defaults. Returns the refreshed instance."""
    defaults = dict(
        id=uuid.uuid7(),
        tenant_id=tenant_id,
        project_id=kw.pop("project_id", PROJECT_ID),
        filename="test.txt",
        content_type="text/plain",
        kind="doc",
        sensitivity="internal",
        size=100,
        sha256="ab" * 32,
        storage_key=storage_key or f"test/{uuid.uuid7()}/v1/test.txt",
        created_by=tenant_id,
    )
    defaults.update(kw)
    artifact = Artifact(**defaults)
    session.add(artifact)
    if tags:
        for t in tags:
            session.add(ArtifactTag(artifact_id=artifact.id, tag=t))
    await session.commit()
    await session.refresh(artifact)
    return artifact


@pytest.mark.asyncio
async def test_create_artifact(db_session):
    project_id = uuid.uuid7()
    card_id = uuid.uuid7()
    artifact = await _create_artifact(
        db_session,
        tenant_id=TEST_TENANT_A,
        project_id=project_id,
        card_id=card_id,
        step="QA:review",
        container_name="container-1",
        filename="report.pdf",
        content_type="application/pdf",
        kind="doc",
        sensitivity="secret",
        size=999_888,
        sha256="a" * 64,
        storage_key="unique/key/create-test",
    )

    result = await db_session.execute(select(Artifact).where(Artifact.id == artifact.id))
    row = result.scalar_one()

    assert row.tenant_id == TEST_TENANT_A
    assert row.project_id == project_id
    assert row.card_id == card_id
    assert row.step == "QA:review"
    assert row.container_name == "container-1"
    assert row.filename == "report.pdf"
    assert row.content_type == "application/pdf"
    assert row.kind == ArtifactKind.DOC
    assert row.sensitivity == ArtifactSensitivity.SECRET
    assert row.size == 999_888
    assert row.sha256 == "a" * 64
    assert row.storage_key == "unique/key/create-test"
    assert row.created_by == TEST_TENANT_A


@pytest.mark.asyncio
async def test_artifact_default_values(db_session):
    artifact = await _create_artifact(db_session)

    result = await db_session.execute(select(Artifact).where(Artifact.id == artifact.id))
    row = result.scalar_one()

    assert row.version == 1
    assert row.created_at is not None
    # SQLite strips timezone info from DateTime(timezone=True); PostgreSQL preserves it.
    # Verify the timestamp exists and is close to now rather than requiring tz-awareness.
    from datetime import datetime

    now_naive = datetime.now(UTC).replace(tzinfo=None)
    created_naive = row.created_at.replace(tzinfo=None)
    assert abs((now_naive - created_naive).total_seconds()) < 10, "created_at should be recent"


@pytest.mark.asyncio
async def test_artifact_tags_relationship(db_session):
    artifact = await _create_artifact(db_session, tags=["ml", "production", "v2"])

    result = await db_session.execute(
        select(Artifact).where(Artifact.id == artifact.id).options(selectinload(Artifact.tags))
    )
    row = result.scalar_one()

    tag_values = sorted(t.tag for t in row.tags)
    assert tag_values == ["ml", "production", "v2"]
    for t in row.tags:
        assert t.artifact_id == artifact.id


@pytest.mark.asyncio
async def test_cascade_delete(db_session):
    artifact = await _create_artifact(db_session, tags=["delete-me", "also-delete"])
    artifact_id = artifact.id

    tag_result = await db_session.execute(
        select(ArtifactTag).where(ArtifactTag.artifact_id == artifact_id)
    )
    assert len(tag_result.scalars().all()) == 2

    await db_session.execute(delete(Artifact).where(Artifact.id == artifact_id))
    await db_session.commit()

    tag_result = await db_session.execute(
        select(ArtifactTag).where(ArtifactTag.artifact_id == artifact_id)
    )
    assert tag_result.scalars().all() == []


@pytest.mark.asyncio
async def test_unique_storage_key(db_session):
    await _create_artifact(db_session, storage_key="unique/key/duplicate-test")

    with pytest.raises(IntegrityError):
        await _create_artifact(db_session, storage_key="unique/key/duplicate-test")

    await db_session.rollback()


@pytest.mark.asyncio
async def test_tenant_id_filtering(db_session):
    for i in range(3):
        await _create_artifact(db_session, tenant_id=TEST_TENANT_A, storage_key=f"a/{i}")
    for i in range(2):
        await _create_artifact(db_session, tenant_id=TEST_TENANT_B, storage_key=f"b/{i}")

    result_a = await db_session.execute(select(Artifact).where(Artifact.tenant_id == TEST_TENANT_A))
    rows_a = result_a.scalars().all()
    assert len(rows_a) == 3
    assert all(r.tenant_id == TEST_TENANT_A for r in rows_a)

    result_b = await db_session.execute(select(Artifact).where(Artifact.tenant_id == TEST_TENANT_B))
    rows_b = result_b.scalars().all()
    assert len(rows_b) == 2
    assert all(r.tenant_id == TEST_TENANT_B for r in rows_b)


@pytest.mark.asyncio
async def test_get_db_yields_session(test_engine):
    """Verify get_db() yields a working AsyncSession."""
    test_session_maker = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    with patch("core.database.async_session_maker", test_session_maker):
        gen = get_db()
        session = await gen.__anext__()
        try:
            assert isinstance(session, AsyncSession)
            result = await session.execute(text("SELECT 1"))
            assert result.scalar() == 1
        finally:
            try:
                await gen.__anext__()
            except StopAsyncIteration:
                pass


@pytest.mark.asyncio
async def test_get_db_rollback_on_exception(test_engine):
    """Verify get_db() rolls back and re-raises when session code raises."""
    test_session_maker = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    with patch("core.database.async_session_maker", test_session_maker):
        gen = get_db()
        session = await gen.__anext__()

        # Insert a valid row so we can verify rollback later
        art = Artifact(
            id=uuid.uuid7(),
            tenant_id=TEST_TENANT_A,
            project_id=PROJECT_ID,
            filename="rollback.txt",
            content_type="text/plain",
            kind="doc",
            sensitivity="internal",
            size=1,
            sha256="b" * 64,
            storage_key=f"rollback/{uuid.uuid7()}",
            created_by=TEST_TENANT_A,
        )
        session.add(art)

        # Simulate an exception during the request — drive generator to the except branch
        with pytest.raises(RuntimeError, match="boom"):
            try:
                await gen.athrow(RuntimeError("boom"))
            except RuntimeError:
                raise

    # Verify the insert was rolled back — artifact should NOT exist
    async with test_session_maker() as verify_session:
        result = await verify_session.execute(
            select(Artifact).where(Artifact.tenant_id == TEST_TENANT_A)
        )
        assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_get_db_context_works(test_engine):
    """Verify get_db_context() yields a working AsyncSession."""
    test_session_maker = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    with patch("core.database.async_session_maker", test_session_maker):
        async with get_db_context() as session:
            assert isinstance(session, AsyncSession)
            result = await session.execute(text("SELECT 1"))
            assert result.scalar() == 1


@pytest.mark.asyncio
async def test_get_db_context_rollback_on_exception(test_engine):
    """Verify get_db_context() rolls back when code inside the context raises."""
    test_session_maker = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    with patch("core.database.async_session_maker", test_session_maker):
        with pytest.raises(RuntimeError, match="context boom"):
            async with get_db_context() as session:
                session.add(
                    Artifact(
                        id=uuid.uuid7(),
                        tenant_id=TEST_TENANT_A,
                        project_id=PROJECT_ID,
                        filename="ctx.txt",
                        content_type="text/plain",
                        kind="doc",
                        sensitivity="internal",
                        size=1,
                        sha256="c" * 64,
                        storage_key=f"ctx/{uuid.uuid7()}",
                        created_by=TEST_TENANT_A,
                    )
                )
                raise RuntimeError("context boom")

    # Verify rollback — artifact should NOT exist
    async with test_session_maker() as verify_session:
        result = await verify_session.execute(
            select(Artifact).where(Artifact.tenant_id == TEST_TENANT_A)
        )
        assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_artifact_repr(db_session):
    """Verify Artifact.__repr__ returns useful debug string."""
    artifact = await _create_artifact(db_session, filename="repr_test.txt")
    repr_str = repr(artifact)
    assert "Artifact" in repr_str
    assert "repr_test.txt" in repr_str
    assert str(artifact.id) in repr_str


@pytest.mark.asyncio
async def test_artifact_tag_repr(db_session):
    """Verify ArtifactTag.__repr__ returns useful debug string."""
    artifact = await _create_artifact(db_session, tags=["repr-tag"])
    result = await db_session.execute(
        select(ArtifactTag).where(ArtifactTag.artifact_id == artifact.id)
    )
    tag = result.scalar_one()
    repr_str = repr(tag)
    assert "ArtifactTag" in repr_str
    assert "repr-tag" in repr_str
