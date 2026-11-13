"""Add tenant_name VARCHAR(255) column to artifacts table.

Phase 3 of the UUIDv7 tenant-identity migration.
license-authz now injects both X-Tenant-Id (UUIDv7) and X-Tenant-Name
(human-readable) on every authenticated request. This adds tenant_name
column with backfill tenant_name := tenant_id for all existing rows.
tenant_id stays VARCHAR(255) for now (UUID strings fit; native UUID type
flip is Phase 4).

Revision ID: 005_add_tenant_name
Revises:     004_per_user_isolation
Create Date: 2026-04-27
"""

from collections.abc import Sequence

from alembic import op

revision: str = "005_add_tenant_name"
down_revision: str | None = "004_per_user_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("artifacts",)


def upgrade() -> None:
    for table in TABLES:
        # 1. Add column nullable first so existing rows survive
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255)")

        # 2. Backfill: tenant_name := tenant_id for all rows that have none
        op.execute(f"UPDATE {table} SET tenant_name = tenant_id WHERE tenant_name IS NULL")

        # 3. Tighten to NOT NULL now that every row has a value
        op.alter_column(table, "tenant_name", nullable=False)

        # 4. Index for filtering / reporting by tenant_name
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_tenant_name ON {table} (tenant_name)")


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_tenant_name")
        op.drop_column(table, "tenant_name")
