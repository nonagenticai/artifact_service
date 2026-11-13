"""Per-user-within-tenant visibility: add subject_id + visibility to artifacts.

artifact_service already has tenant_id on the artifacts table. This migration
adds subject_id + visibility columns (additive only — NO creator_id drop, NO
unique constraint swap) and backfills:

    subject_id := '' (no recorded creator for existing rows)
    visibility := 'tenant'

so ALL existing artifacts remain visible to ALL tenant members, exactly as today.
New artifacts default to visibility='tenant' unless the caller sends
X-Visibility: user at upload time.

Revision ID: 004_per_user_isolation
Revises:     003_enum_to_varchar
Create Date: 2026-04-27
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004_per_user_isolation"
down_revision: str | None = "003_enum_to_varchar"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Only the artifacts table — artifact_tags is a join table with no tenant scoping
TABLES = ("artifacts",)


def upgrade() -> None:
    for table in TABLES:
        # 1. Add columns nullable first so existing rows survive
        op.add_column(
            table,
            sa.Column("subject_id", sa.String(255), nullable=True),
        )
        op.add_column(
            table,
            sa.Column(
                "visibility",
                sa.String(16),
                server_default="tenant",
                nullable=True,
            ),
        )

        # 2. Backfill — empty subject_id means "no recorded creator"; visibility='tenant'
        #    keeps existing artifacts visible to all tenant members exactly as today
        op.execute(
            f"UPDATE {table} SET subject_id = '', visibility = 'tenant' "
            f"WHERE subject_id IS NULL OR visibility IS NULL"
        )

        # 3. Tighten to NOT NULL now that every row has a value
        op.alter_column(table, "subject_id", nullable=False)
        op.alter_column(table, "visibility", nullable=False)

        # 4. New composite indexes for visibility scoping queries
        op.create_index(f"ix_{table}_tenant_subject", table, ["tenant_id", "subject_id"])
        op.create_index(f"ix_{table}_tenant_visibility", table, ["tenant_id", "visibility"])

        # 5. CHECK constraint — only two valid values
        op.create_check_constraint(
            f"ck_{table}_visibility",
            table,
            "visibility IN ('tenant', 'user')",
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS ck_{table}_visibility")
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_tenant_visibility")
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_tenant_subject")
        op.drop_column(table, "visibility")
        op.drop_column(table, "subject_id")
