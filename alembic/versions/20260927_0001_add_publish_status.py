"""Add artifacts.publish_status for system-tenant read inheritance.

Adds:
- artifacts.publish_status TEXT NOT NULL DEFAULT 'draft'
  CHECK (publish_status IN ('draft', 'published'))
- index ix_artifacts_tenant_publish_status ON artifacts (tenant_id, publish_status)

A PUBLISHED, tenant-visible artifact owned by the system tenant is readable
(never writable) by every other tenant — see src/repositories/visibility.py.

⚠️ Named ``publish_status``, NOT ``status``: ``artifacts.status`` already exists
(006_add_review_status) and carries the REVIEW decision. Two meanings on one
column would make "approved" silently mean "shared with every tenant".

Every existing row — including every system-tenant row — lands on 'draft', so
this migration shares NOTHING by itself: inheritance starts only when a system
artifact is explicitly published. That is the safe direction.

On Postgres 11+ ``ADD COLUMN ... NOT NULL DEFAULT <constant>`` is a catalog-only
change (no table rewrite), so it is cheap on the ~58k-row production table.

Revision ID: 20260927_0001
Revises:     20260826_0003
Create Date: 2026-09-27
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260927_0001"
down_revision: str | None = "20260826_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE artifacts "
        "ADD COLUMN IF NOT EXISTS publish_status TEXT NOT NULL DEFAULT 'draft'"
    )
    # Postgres has no ADD CONSTRAINT IF NOT EXISTS; guard on pg_constraint so a
    # re-run is as safe as the IF NOT EXISTS column/index statements around it.
    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_constraint "
        "WHERE conname = 'ck_artifacts_publish_status' "
        "AND conrelid = 'artifacts'::regclass) THEN "
        "ALTER TABLE artifacts "
        "ADD CONSTRAINT ck_artifacts_publish_status "
        "CHECK (publish_status IN ('draft', 'published')); "
        "END IF; END $$"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_publish_status "
        "ON artifacts (tenant_id, publish_status)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_artifacts_tenant_publish_status")
    op.execute("ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS ck_artifacts_publish_status")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS publish_status")
