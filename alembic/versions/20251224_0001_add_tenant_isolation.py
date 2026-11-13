"""Add tenant isolation - fresh start migration

This migration implements tenant isolation for multi-tenancy support.
FRESH START: Drops and recreates tables (dev/staging only).

For production with existing data:
1. Add tenant_id as nullable
2. Backfill with admin tenant ID
3. Add NOT NULL constraint
4. Add indexes

Revision ID: 002_tenant_isolation
Revises: 001_initial
Create Date: 2025-12-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_tenant_isolation"
down_revision: str | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Fresh start: drop and recreate tables with tenant_id."""

    # Drop existing tables (cascade handles foreign keys)
    op.drop_index("idx_tag_lookup", table_name="artifact_tags")
    op.drop_table("artifact_tags")

    op.drop_index("idx_project_kind", table_name="artifacts")
    op.drop_index("idx_project_step", table_name="artifacts")
    op.drop_index("idx_project_card", table_name="artifacts")
    op.drop_index("idx_artifacts_created_at_desc", table_name="artifacts")
    op.drop_index("idx_artifacts_sha256", table_name="artifacts")
    op.drop_index("idx_artifacts_sensitivity", table_name="artifacts")
    op.drop_index("idx_artifacts_kind", table_name="artifacts")
    op.drop_index("idx_artifacts_container_name", table_name="artifacts")
    op.drop_index("idx_artifacts_step", table_name="artifacts")
    op.drop_index("idx_artifacts_card_id", table_name="artifacts")
    op.drop_index("idx_artifacts_project_id", table_name="artifacts")
    op.drop_table("artifacts")

    # Recreate artifacts table WITH tenant_id
    op.create_table(
        "artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        # TENANT ISOLATION - new column
        sa.Column("tenant_id", sa.String(255), nullable=False),
        # Project references
        sa.Column("project_id", UUID(as_uuid=True), nullable=False),
        sa.Column("card_id", UUID(as_uuid=True), nullable=True),
        sa.Column("step", sa.String(100), nullable=True),
        sa.Column("container_name", sa.String(255), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "doc",
                "presentation",
                "image",
                "dataset",
                "json",
                "graph",
                "other",
                name="artifactkind",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "sensitivity",
            sa.Enum("public", "internal", "secret", name="artifactsensitivity", create_type=False),
            nullable=False,
        ),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False, unique=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Create indexes - TENANT-FIRST for efficient filtering
    op.create_index("idx_artifacts_tenant_id", "artifacts", ["tenant_id"])
    op.create_index("idx_tenant_project", "artifacts", ["tenant_id", "project_id"])
    op.create_index("idx_tenant_project_card", "artifacts", ["tenant_id", "project_id", "card_id"])
    op.create_index("idx_tenant_project_step", "artifacts", ["tenant_id", "project_id", "step"])
    op.create_index("idx_tenant_project_kind", "artifacts", ["tenant_id", "project_id", "kind"])
    op.create_index("idx_artifacts_sha256", "artifacts", ["sha256"])
    op.create_index("idx_artifacts_created_at_desc", "artifacts", [sa.text("created_at DESC")])

    # Recreate artifact_tags table
    op.create_table(
        "artifact_tags",
        sa.Column("artifact_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tag", sa.String(50), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id", "tag"),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
    )

    op.create_index("idx_tag_lookup", "artifact_tags", ["tag"])


def downgrade() -> None:
    """Downgrade removes tenant_id (data loss!)."""

    # Drop tables
    op.drop_index("idx_tag_lookup", table_name="artifact_tags")
    op.drop_table("artifact_tags")

    op.drop_index("idx_tenant_project_kind", table_name="artifacts")
    op.drop_index("idx_tenant_project_step", table_name="artifacts")
    op.drop_index("idx_tenant_project_card", table_name="artifacts")
    op.drop_index("idx_tenant_project", table_name="artifacts")
    op.drop_index("idx_artifacts_tenant_id", table_name="artifacts")
    op.drop_index("idx_artifacts_created_at_desc", table_name="artifacts")
    op.drop_index("idx_artifacts_sha256", table_name="artifacts")
    op.drop_table("artifacts")

    # Recreate original schema without tenant_id
    op.create_table(
        "artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), nullable=False),
        sa.Column("card_id", UUID(as_uuid=True), nullable=True),
        sa.Column("step", sa.String(100), nullable=True),
        sa.Column("container_name", sa.String(255), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "doc",
                "presentation",
                "image",
                "dataset",
                "json",
                "graph",
                "other",
                name="artifactkind",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "sensitivity",
            sa.Enum("public", "internal", "secret", name="artifactsensitivity", create_type=False),
            nullable=False,
        ),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False, unique=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    op.create_index("idx_artifacts_project_id", "artifacts", ["project_id"])
    op.create_index("idx_artifacts_card_id", "artifacts", ["card_id"])
    op.create_index("idx_artifacts_step", "artifacts", ["step"])
    op.create_index("idx_artifacts_container_name", "artifacts", ["container_name"])
    op.create_index("idx_artifacts_kind", "artifacts", ["kind"])
    op.create_index("idx_artifacts_sensitivity", "artifacts", ["sensitivity"])
    op.create_index("idx_artifacts_sha256", "artifacts", ["sha256"])
    op.create_index("idx_artifacts_created_at_desc", "artifacts", [sa.text("created_at DESC")])
    op.create_index("idx_project_card", "artifacts", ["project_id", "card_id"])
    op.create_index("idx_project_step", "artifacts", ["project_id", "step"])
    op.create_index("idx_project_kind", "artifacts", ["project_id", "kind"])

    op.create_table(
        "artifact_tags",
        sa.Column("artifact_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tag", sa.String(50), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id", "tag"),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
    )

    op.create_index("idx_tag_lookup", "artifact_tags", ["tag"])
