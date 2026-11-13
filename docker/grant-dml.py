"""Grant the runtime role its DML privileges after migrations.

The RLS revision (alembic 20261003_0001) REVOKEs ALL on the three tables it puts
under row-level security, because a runtime role must not be able to change the
schema. Nothing in the migrations gives the DML back: a real deployment applies it
out of band as the schema owner. This script is that step for the local compose
stack, and it is the one piece of setup you must reproduce in your own deployment.

Run as the schema owner AFTER `alembic upgrade head`.
"""

from __future__ import annotations

import psycopg

RUNTIME_ROLE = "artifact_service"

DSN = "host=db port=5432 dbname=artifact_registry user=postgres password=postgres"

STATEMENTS = (
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RUNTIME_ROLE}",
    f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {RUNTIME_ROLE}",
)


def main() -> None:
    with psycopg.connect(DSN) as conn, conn.cursor() as cur:
        for statement in STATEMENTS:
            cur.execute(statement)
    print(f"granted DML to {RUNTIME_ROLE}")


if __name__ == "__main__":
    main()
