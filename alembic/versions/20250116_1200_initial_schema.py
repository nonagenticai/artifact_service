"""Initial schema for artifacts and tags

Revision ID: 001_initial
Revises:
Create Date: 2025-01-16 12:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create artifacts table
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
            ),
            nullable=False,
        ),
        sa.Column(
            "sensitivity",
            sa.Enum("public", "internal", "secret", name="artifactsensitivity"),
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

    # Create indexes for artifacts
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

    # Create artifact_tags table
    op.create_table(
        "artifact_tags",
        sa.Column("artifact_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tag", sa.String(50), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id", "tag"),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="CASCADE"),
    )

    # Create index for tag lookups
    op.create_index("idx_tag_lookup", "artifact_tags", ["tag"])


def downgrade() -> None:
    # Drop tables and enums
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

    op.execute("DROP TYPE artifactsensitivity")
    op.execute("DROP TYPE artifactkind")
