"""Add artifact review status + history + callback URL.

Adds:
- artifacts.status VARCHAR(20) NOT NULL DEFAULT 'pending'
  (enum check: pending | approved | rejected | needs_revision)
- artifacts.review_callback_url TEXT NULL
  (set by n8n on upload so fr-backend can POST the human decision back to
   the producing workflow; never set by humans)
- artifact_reviews table for full review history (one row per decision).

Revision ID: 006_add_review_status
Revises:     005_add_tenant_name
Create Date: 2026-05-19
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "006_add_review_status"
down_revision: str | None = "005_add_tenant_name"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE artifacts "
        "ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending'"
    )
    op.execute(
        "ALTER TABLE artifacts "
        "ADD CONSTRAINT ck_artifacts_status "
        "CHECK (status IN ('pending', 'approved', 'rejected', 'needs_revision'))"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_status ON artifacts (tenant_id, status)"
    )
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS review_callback_url TEXT")

    op.create_table(
        "artifact_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "artifact_id",
            sa.Uuid(),
            sa.ForeignKey("artifacts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.String(255), nullable=False),
        sa.Column("reviewer_tenant_id", sa.String(255), nullable=False),
        sa.Column(
            "reviewed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "decision IN ('approve', 'reject', 'revise')",
            name="ck_artifact_reviews_decision",
        ),
    )
    op.create_index("ix_artifact_reviews_artifact_id", "artifact_reviews", ["artifact_id"])
    op.create_index("ix_artifact_reviews_reviewed_at", "artifact_reviews", ["reviewed_at"])


def downgrade() -> None:
    op.drop_index("ix_artifact_reviews_reviewed_at", table_name="artifact_reviews")
    op.drop_index("ix_artifact_reviews_artifact_id", table_name="artifact_reviews")
    op.drop_table("artifact_reviews")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS review_callback_url")
    op.execute("DROP INDEX IF EXISTS ix_artifacts_tenant_status")
    op.execute("ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifacts_status")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS status")
