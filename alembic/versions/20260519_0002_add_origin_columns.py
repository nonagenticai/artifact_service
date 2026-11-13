"""Add asset-bindings origin columns to artifacts.

Plan ref: ~/.claude/plans/fr-asset-bindings-and-reuse.md (Phase G)

Mirrors the shape used in requirements_management + procedure_management:

  origin_kind            'tenant' | 'project' | 'workflow'
  origin_project_id      UUID, NULL unless origin_kind='project'
  origin_workflow_run_id text, NULL unless origin_kind='workflow'
  created_by_user_id     subject_id of the creator

Existing rows backfill to origin_kind='tenant' via server_default —
project-scoped artifacts that pre-date this migration stay 'tenant'
because we can't reconstruct the creator-intent retroactively.

Forward-only — pre-prod, no rollback shims.

Revision ID: 20260519_0002
Revises: 006_add_review_status
Create Date: 2026-05-19
"""

import sqlalchemy as sa

from alembic import op

revision = "20260519_0002"
down_revision = "006_add_review_status"
branch_labels = None
depends_on = None


TABLE = "artifacts"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column(
            "origin_kind",
            sa.String(length=20),
            nullable=False,
            server_default="tenant",
        ),
    )
    op.add_column(TABLE, sa.Column("origin_project_id", sa.Uuid(), nullable=True))
    op.add_column(
        TABLE,
        sa.Column("origin_workflow_run_id", sa.String(length=200), nullable=True),
    )
    op.add_column(
        TABLE,
        sa.Column(
            "created_by_user_id",
            sa.String(length=255),
            nullable=False,
            server_default="",
        ),
    )
    op.create_check_constraint(
        f"ck_{TABLE}_origin_kind",
        TABLE,
        "origin_kind IN ('tenant', 'project', 'workflow')",
    )
    op.create_check_constraint(
        f"ck_{TABLE}_origin_consistency",
        TABLE,
        "(origin_kind = 'tenant'   AND origin_project_id IS NULL     AND origin_workflow_run_id IS NULL) OR "
        "(origin_kind = 'project'  AND origin_project_id IS NOT NULL AND origin_workflow_run_id IS NULL) OR "
        "(origin_kind = 'workflow' AND origin_workflow_run_id IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(f"ck_{TABLE}_origin_consistency", TABLE, type_="check")
    op.drop_constraint(f"ck_{TABLE}_origin_kind", TABLE, type_="check")
    op.drop_column(TABLE, "created_by_user_id")
    op.drop_column(TABLE, "origin_workflow_run_id")
    op.drop_column(TABLE, "origin_project_id")
    op.drop_column(TABLE, "origin_kind")
