"""Add document metadata columns: title, doc_type, phase, summary, planka_card_id.

Adds (all NULLABLE, no default, so every existing row is untouched):
- artifacts.title     TEXT
- artifacts.doc_type  VARCHAR(100)
- artifacts.phase     VARCHAR(100)
- artifacts.summary   TEXT
- artifacts.planka_card_id VARCHAR(64)
- index ix_artifacts_tenant_project_phase ON artifacts (tenant_id, project_id, phase)
- index ix_artifacts_tenant_planka_card ON artifacts (tenant_id, planka_card_id)

``planka_card_id`` is SEPARATE from ``card_id`` on purpose: ``card_id`` is a uuid
column (fr and n8n-nodes-artifacts treat it as one), while Planka's own card ids are
19-digit snowflakes (e.g. ``1885787636753237021``). The conveyor links artifacts to
cards only through a ``planka_card:<id>`` tag; this column makes that link queryable.

Purpose (DOC-1, ~/.claude/plans/program/20-designs/FR-PROJECT-HOME-REDESIGN-2026-10-26.md
§7.2): fr's Outputs page shows conveyor documents by human title, type, phase and
one-line summary. Review state / publication / version are NOT duplicated here —
they already live in ``status``, ``publish_status``, ``version`` and
``artifact_reviews``.

The index leads with ``tenant_id`` like every other composite index on this table
(``idx_tenant_project*``): every read path is tenant-scoped by
``repositories.visibility.scope``, so a (project_id, phase) index without the tenant
would be the one index the planner cannot use as a prefix.

``ADD COLUMN`` of a nullable column with no default is catalog-only on Postgres 11+
(no rewrite). The index build takes a SHARE lock for its duration; on the ~58k-row
table that is well under a second, and CREATE INDEX CONCURRENTLY cannot run inside
the transaction alembic opens.

Revision ID: 20261027_0001
Revises:     20261003_0001
Create Date: 2026-10-27
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20261027_0001"
down_revision: str | None = "20261003_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS title TEXT")
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS doc_type VARCHAR(100)")
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS phase VARCHAR(100)")
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS summary TEXT")
    op.execute("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS planka_card_id VARCHAR(64)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_project_phase "
        "ON artifacts (tenant_id, project_id, phase)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_planka_card "
        "ON artifacts (tenant_id, planka_card_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_artifacts_tenant_planka_card")
    op.execute("DROP INDEX IF EXISTS ix_artifacts_tenant_project_phase")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS planka_card_id")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS summary")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS phase")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS doc_type")
    op.execute("ALTER TABLE artifacts DROP COLUMN IF EXISTS title")
