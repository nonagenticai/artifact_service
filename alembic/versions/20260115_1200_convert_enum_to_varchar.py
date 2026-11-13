"""Convert native enum columns to VARCHAR for psycopg3 compatibility

SQLAlchemy 2.0 with psycopg3 sends Python enum names (DOC) instead of
values (doc) for native PostgreSQL enums. Converting to VARCHAR fixes this.

Revision ID: 003_enum_to_varchar
Revises: 002_tenant_isolation
Create Date: 2026-01-15 12:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003_enum_to_varchar"
down_revision: str | None = "002_tenant_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Step 1: Add temporary VARCHAR columns
    op.add_column("artifacts", sa.Column("kind_new", sa.String(50), nullable=True))
    op.add_column("artifacts", sa.Column("sensitivity_new", sa.String(50), nullable=True))

    # Step 2: Copy data from enum columns to VARCHAR columns (values are already lowercase)
    op.execute("UPDATE artifacts SET kind_new = kind::text, sensitivity_new = sensitivity::text")

    # Step 3: Drop the old enum columns
    op.drop_index("idx_tenant_project_kind", table_name="artifacts")
    op.drop_column("artifacts", "kind")
    op.drop_column("artifacts", "sensitivity")

    # Step 4: Rename new columns to original names
    op.alter_column("artifacts", "kind_new", new_column_name="kind", nullable=False)
    op.alter_column("artifacts", "sensitivity_new", new_column_name="sensitivity", nullable=False)

    # Step 5: Recreate indexes
    op.create_index("idx_tenant_project_kind", "artifacts", ["tenant_id", "project_id", "kind"])
    op.create_index("idx_kind", "artifacts", ["kind"])
    op.create_index("idx_sensitivity", "artifacts", ["sensitivity"])

    # Step 6: Drop the enum types
    op.execute("DROP TYPE IF EXISTS artifactkind")
    op.execute("DROP TYPE IF EXISTS artifactsensitivity")


def downgrade() -> None:
    # Recreate enum types
    op.execute(
        "CREATE TYPE artifactkind AS ENUM ('doc', 'presentation', 'image', 'dataset', 'json', 'graph', 'other')"
    )
    op.execute("CREATE TYPE artifactsensitivity AS ENUM ('public', 'internal', 'secret')")

    # Add temporary enum columns
    op.add_column(
        "artifacts",
        sa.Column(
            "kind_old",
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
            nullable=True,
        ),
    )
    op.add_column(
        "artifacts",
        sa.Column(
            "sensitivity_old",
            sa.Enum("public", "internal", "secret", name="artifactsensitivity"),
            nullable=True,
        ),
    )

    # Copy data
    op.execute(
        "UPDATE artifacts SET kind_old = kind::artifactkind, sensitivity_old = sensitivity::artifactsensitivity"
    )

    # Drop VARCHAR columns and indexes
    op.drop_index("idx_sensitivity", table_name="artifacts")
    op.drop_index("idx_kind", table_name="artifacts")
    op.drop_index("idx_tenant_project_kind", table_name="artifacts")
    op.drop_column("artifacts", "kind")
    op.drop_column("artifacts", "sensitivity")

    # Rename enum columns
    op.alter_column("artifacts", "kind_old", new_column_name="kind", nullable=False)
    op.alter_column("artifacts", "sensitivity_old", new_column_name="sensitivity", nullable=False)

    # Recreate indexes
    op.create_index("idx_tenant_project_kind", "artifacts", ["tenant_id", "project_id", "kind"])
