"""Row-Level Security backstop: tenant_isolation + platform-gated system read (art#49).

The application already scopes every read and write by tenant
(``repositories.visibility.scope`` / ``can_mutate``); this migration adds the
DATABASE layer, so a query that forgets its tenant filter returns nothing
instead of every tenant's rows. ``src/tenant_guc.py`` binds
``app.current_tenant`` per TRANSACTION with ``set_config(..., true)`` when
``TENANT_RLS_MODE=enforce``; the shared pgbouncer RESETs the GUC per client
(gitops#4336).

Copied from procedure_management alembic ``019`` (pm#107), shape of the system
read from requirements_management ``2026_10_02_0047``.

⛔ DEPLOY ORDER: ``TENANT_RLS_MODE=enforce`` must be live on the artifacts
Deployment BEFORE this revision runs. With the mode ``off`` nothing binds the
GUC, so every request on the runtime role reads 0 rows and every write fails
WITH CHECK. (The listener is harmless without policies, so flipping the env
first is safe.) ``main.lifespan`` logs CRITICAL at startup on that combination.

ENABLE, not FORCE: the owner ``artifact_service_owner`` (migrations) is not
subject to these policies; the runtime role ``artifact_service`` (non-owner,
NOBYPASSRLS — role split measured live 2026-10-03) is. FORCE would make every
future data migration run by the owner silently match 0 rows.

Fails CLOSED: no GUC ⇒ ``current_setting(..., true)`` is NULL (or '' after a
RESET, which ``NULLIF`` maps to NULL) ⇒ ``tenant_id = NULL`` is NULL and
``NULL IN (...)`` is NULL ⇒ no row is admitted by any policy.

Policies (PERMISSIVE, OR-ed per command):

* ``tenant_isolation`` FOR ALL, USING = WITH CHECK ``tenant_id = <GUC>::uuid`` on
  ``artifacts``. ``artifact_tags`` and ``artifact_reviews`` carry no tenant
  column: their rows follow the PARENT artifact's ``tenant_id`` via EXISTS.
  (``artifact_reviews.reviewer_tenant_id`` is an audit field, never a scope.)
* ``system_published_read`` FOR SELECT on ``artifacts`` and ``artifact_tags`` —
  the PLATFORM tenants (and only them) read SYSTEM rows that are
  ``visibility='tenant'`` AND ``publish_status='published'``. Exactly what
  ``visibility.scope(include_system=True)`` admits (art#47, owner ruling
  2026-09-30). Reviews of an inherited artifact are NOT readable: the review
  log's gate is own-tenant (``include_system`` left False), so no system-read
  policy exists on ``artifact_reviews``.
* No system WRITE policy and no cross-tenant read for the SYSTEM tenant (owner
  ruling 2026-10-02, G-B cancelled; rm#187 reverted by rm#190/#192): the system
  tenant reads its own rows through ``tenant_isolation`` like any tenant.
  Customers (every non-platform tenant) see 0 system rows.

REVOKE ALL from the runtime role on ``tenant_id_remap_audit``: only alembic
``20260826_0003`` (run as the owner) reads or writes it. Downgrade re-grants the
pre-revision production grant (``arwd``).

REVOKE CREATE ON SCHEMA public FROM the runtime role, then RAISE if it can still
create there: an object the runtime role creates is owned by it and sits
outside this design. Prod already holds only USAGE (measured 2026-10-03), so
this is a guard, and the downgrade grants nothing back.

⛔ FROZEN literals: ``SYSTEM_TENANT`` and ``PLATFORM_TENANTS`` MUST equal the
``core.config.Settings`` defaults (pinned by ``tests/test_rls_20261003_0001.py``).
Change settings and the policies (a NEW migration) together, or a platform
tenant reads as a customer at the DB layer.

Revision ID: 20261003_0001
Revises: 20260927_0001
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20261003_0001"
down_revision: str | None = "20260927_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RUNTIME_ROLE = "artifact_service"

SYSTEM_TENANT = "0195f48b-d000-7000-8000-000000000001"
PLATFORM_TENANTS: tuple[str, ...] = (
    "0195f48b-d000-7000-8000-000000000001",  # system
    "0195f48b-d000-7000-8000-000000000002",  # workflow-improvement
    "0195f48b-d000-7000-8000-000000000003",  # execution
    "0195f48b-d000-7000-8000-000000000004",  # prompt-improvement
    "0195f48b-d000-7000-8000-000000000005",  # procedure-improvement
    "019de842-c92a-7e37-8fdd-eb0d8c5396f9",  # n8n-dev (AA conveyor)
)
PUBLISHED = "published"

ARTIFACTS = "artifacts"
TAGS = "artifact_tags"
REVIEWS = "artifact_reviews"
RLS_TABLES: tuple[str, ...] = (ARTIFACTS, TAGS, REVIEWS)

#: No live code path reads or writes these through the runtime role. A table
#: missing from a database (test schema) is skipped.
REVOKED_TABLES: tuple[str, ...] = ("tenant_id_remap_audit",)

TENANT_ISOLATION = "tenant_isolation"
SYSTEM_PUBLISHED_READ = "system_published_read"

GUC_TENANT = "NULLIF(current_setting('app.current_tenant', true), '')::uuid"


def _quoted_uuids(values: Sequence[str]) -> str:
    # Same uuid comparison as tenant_isolation (GUC_TENANT): a text compare
    # would treat a differently-cased/formatted platform id as non-platform.
    return ", ".join(f"'{v}'::uuid" for v in values)


def system_published_predicate(alias: str) -> str:
    """SYSTEM published tenant-visible rows, admitted only for a PLATFORM GUC."""
    p = f"{alias}." if alias else ""
    return (
        f"{p}tenant_id = '{SYSTEM_TENANT}'::uuid "
        f"AND {p}visibility = 'tenant' "
        f"AND {p}publish_status = '{PUBLISHED}' "
        f"AND {GUC_TENANT} IN ({_quoted_uuids(PLATFORM_TENANTS)})"
    )


def _parent(child: str, predicate: str) -> str:
    return f"EXISTS (SELECT 1 FROM artifacts a WHERE a.id = {child}.artifact_id AND {predicate})"


TENANT_PREDICATE = f"tenant_id = {GUC_TENANT}"
TAGS_TENANT_PREDICATE = _parent(TAGS, f"a.tenant_id = {GUC_TENANT}")
REVIEWS_TENANT_PREDICATE = _parent(REVIEWS, f"a.tenant_id = {GUC_TENANT}")
SYSTEM_PUBLISHED_PREDICATE = system_published_predicate("")
TAGS_SYSTEM_PUBLISHED_PREDICATE = _parent(TAGS, system_published_predicate("a"))


def policies() -> list[tuple[str, str, str, str, str | None]]:
    """(table, policy, command, USING, WITH CHECK) — every policy this revision creates."""
    return [
        (ARTIFACTS, TENANT_ISOLATION, "ALL", TENANT_PREDICATE, TENANT_PREDICATE),
        (ARTIFACTS, SYSTEM_PUBLISHED_READ, "SELECT", SYSTEM_PUBLISHED_PREDICATE, None),
        (TAGS, TENANT_ISOLATION, "ALL", TAGS_TENANT_PREDICATE, TAGS_TENANT_PREDICATE),
        (TAGS, SYSTEM_PUBLISHED_READ, "SELECT", TAGS_SYSTEM_PUBLISHED_PREDICATE, None),
        (REVIEWS, TENANT_ISOLATION, "ALL", REVIEWS_TENANT_PREDICATE, REVIEWS_TENANT_PREDICATE),
    ]


def create_policy_sql(table: str, name: str, cmd: str, using: str, check: str | None) -> str:
    sql = f"CREATE POLICY {name} ON public.{table} AS PERMISSIVE FOR {cmd} USING ({using})"
    if check is not None:
        sql += f" WITH CHECK ({check})"
    return sql


def _privilege_ddl(relation: str, stmt: str) -> str:
    """Run ``stmt`` for ``relation`` only when the relation AND the runtime role exist,
    and only when ``current_user`` may act as the relation's owner."""
    return f"""
DO $do$
BEGIN
    IF to_regclass('public.{relation}') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN
        RETURN;
    END IF;
    IF NOT pg_has_role(
        current_user,
        (SELECT relowner FROM pg_class WHERE oid = 'public.{relation}'::regclass),
        'USAGE'
    ) THEN
        RAISE EXCEPTION 'migration 20261003_0001: current_user does not own public.{relation}';
    END IF;
    EXECUTE '{stmt}';
END
$do$;
"""


def revoke_ddl(relation: str) -> str:
    return _privilege_ddl(relation, f"REVOKE ALL ON TABLE public.{relation} FROM {RUNTIME_ROLE}")


def regrant_ddl(relation: str) -> str:
    """Downgrade: the pre-revision production grant (``arwd``)."""
    return _privilege_ddl(
        relation,
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{relation} TO {RUNTIME_ROLE}",
    )


REVOKE_SCHEMA_CREATE = f"""
DO $do$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RUNTIME_ROLE}') THEN
        RETURN;
    END IF;
    EXECUTE 'REVOKE CREATE ON SCHEMA public FROM {RUNTIME_ROLE}';
    IF has_schema_privilege('{RUNTIME_ROLE}', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'migration 20261003_0001: {RUNTIME_ROLE} still holds CREATE on schema public';
    END IF;
END
$do$;
"""


def upgrade() -> None:
    # CREATE/DROP POLICY and ENABLE RLS take ACCESS EXCLUSIVE on three live
    # tables; bound the wait so a long transaction FAILS the migrate init
    # container instead of hanging it and queueing every reader behind it.
    # Everything is one transaction.
    op.get_bind().exec_driver_sql("SET LOCAL lock_timeout = '10s'")
    for table, name, cmd, using, check in policies():
        op.execute(f"DROP POLICY IF EXISTS {name} ON public.{table}")
        op.execute(create_policy_sql(table, name, cmd, using, check))
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    for relation in REVOKED_TABLES:
        op.execute(revoke_ddl(relation))
    op.execute(REVOKE_SCHEMA_CREATE)


def downgrade() -> None:
    op.get_bind().exec_driver_sql("SET LOCAL lock_timeout = '10s'")
    for relation in REVOKED_TABLES:
        op.execute(regrant_ddl(relation))
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
    for table, name, _cmd, _using, _check in policies():
        op.execute(f"DROP POLICY IF EXISTS {name} ON public.{table}")
