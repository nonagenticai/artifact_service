"""tenant_id becomes a real uuid column, and the one legacy tenant is REMAPPED

``artifacts.tenant_id`` and ``artifact_reviews.reviewer_tenant_id`` were both
``varchar(255)``, so the boundary could mint a tenant simply by sending a header
that matched a charset rule. That is how the literal string ``n8n-dev`` came to
own rows in this database. A charset rule is not a validation rule.

WHY THIS REMAPS RATHER THAN DELETES
-----------------------------------
Measured on the rehearsal copy of production (2026-08-26):

* ``artifacts`` holds **51,238** rows (51,226 at the earlier census — the
  population moves while the migration is being written, which is exactly why
  the guards below run INSIDE the transaction instead of being replaced by that
  census), of which **284** carry the literal ``tenant_id = 'n8n-dev'``.

The identity is not guessed. ``licenses.tenants`` was read directly:

* ``019de842-c92a-7e37-8fdd-eb0d8c5396f9`` **is** the row named ``n8n-dev``.
* ``0195f48b-d000-7000-8000-000000000001`` is a **different** tenant named
  ``platform-cp-1`` — and it owns 42,387 of the rows in this table. Folding
  ``n8n-dev`` into it (the shape a sibling service's Keycloak realm map would
  have suggested) would have been a silent CROSS-TENANT MERGE of 284 rows into
  the largest tenant in the database. That is the mistake this docstring exists
  to make un-repeatable.

The remap cannot collide: ``artifacts`` currently holds **0** rows already under
``019de842-c92a-7e37-8fdd-eb0d8c5396f9``, so no pre-existing row of the real
tenant is being joined by these 284 — they simply arrive.

``artifacts.subject_id`` IS DELIBERATELY LEFT ALONE — DO NOT "FINISH THE SET"
-----------------------------------------------------------------------------
``subject_id`` also holds the literal ``n8n-dev``, on **224** rows, and the
obvious-looking move is to remap it in the same pass. That would be a silent
authorization change, so it is NOT done here.

``subject_id`` is an authz key in this service, not a spare label:
``src/repositories/visibility.py`` narrows reads with
``model.subject_id == subject_id`` for ``visibility == 'user'`` rows (:29) and
``can_mutate()`` (:33) gates WRITES on it. Measured, the 284 dirty rows split:

* ``visibility='tenant'``, ``subject_id='n8n-dev'`` → **224**
* ``visibility='tenant'``, ``subject_id=''``        → **60**

All 284 are ``visibility='tenant'``, so ``subject_id`` does not gate their READS
either way — but it does gate ``can_mutate``. Rewriting it would change WHO may
mutate 224 rows, inside a change whose entire contract is the TYPE of a
different column. That is a separate decision and a separate PR. Leaving it is
exactly behaviour-preserving, and it needs no cast at all because the column
stays ``varchar(255)``.

``tenant_name`` IS LOAD-BEARING TWICE — DO NOT "TIDY UP" THE REDUNDANT COLUMN
-----------------------------------------------------------------------------
``artifacts.tenant_name`` stays ``varchar`` and keeps the value ``n8n-dev``. It
looks redundant — measured, **0 of 51,238** rows have
``tenant_name IS DISTINCT FROM tenant_id``, because ``_autofill_subject_id``
(``src/models/artifact.py:154-167``) sets ``tenant_name := tenant_id`` when the
caller leaves it unset and no caller has ever sent ``X-Tenant-Name``. Deleting a
column that is a perfect copy of its neighbour is exactly the kind of tidy-up a
future reader will reach for. It must not happen, for TWO independent reasons:

1. **Provenance.** For these 284 rows it is the only surviving record that they
   arrived as the literal ``n8n-dev`` rather than as the uuid.
2. **Rollback correctness.** It is the ONLY discriminator ``downgrade()`` has
   between the rows this migration moved and rows that legitimately belong to
   tenant ``019de842-…``. See ``downgrade()`` — without it the reverse remap is
   an unscoped ``UPDATE`` that relabels the real tenant's data as ``n8n-dev``.

Reason 2 is not hypothetical merely because ``artifacts`` holds **0** rows under
``019de842-…`` today. That zero is a SNAPSHOT. ``downgrade()`` runs at an unknown
later time, by which point the boundary gate is live and callers are legitimately
writing rows under that uuid — the window between upgrade and rollback is
precisely when those rows appear. A sibling service (``procedure_management``)
measured the damage on its own data: 232 moved rows plus **1,019** pre-existing
legitimate rows, 1,251 wrongly relabelled by the unscoped form.

``artifact_reviews`` is **empty** (0 rows measured), so the cast of
``reviewer_tenant_id`` is total by construction — there is no value in it that
could fail ``::uuid``. The guard still runs, because the old pod keeps writing
between the census and this statement.

NOTHING IS DELETED, SO NO CASCADE CAN FIRE
------------------------------------------
Measured: there are exactly **two** foreign keys into ``artifacts``, and BOTH are
``ON DELETE CASCADE`` — ``artifact_tags.artifact_id`` and
``artifact_reviews.artifact_id``. (An earlier note claimed only ``artifact_tags``;
that was wrong and is corrected here.) ``artifact_tags`` carries no tenant column
at all, ``artifact_reviews`` is empty, and this migration issues no ``DELETE`` of
any kind — only ``UPDATE`` and ``ALTER``. So there is no cross-tenant cascade
surface to guard, and the guard that a sibling service needed is deliberately
absent rather than copied in as decoration.

INDEXES ARE LEFT ALONE ON PURPOSE
---------------------------------
Eight btree indexes lead with ``tenant_id`` (``idx_artifacts_tenant_id``,
``idx_tenant_project{,_card,_kind,_step}``, ``ix_artifacts_tenant_{status,
subject,visibility}``). Postgres rebuilds every one of them in place as part of
the ``ALTER … TYPE``. There is no RLS on any table here, no functional index on
the column, no generated column derived from it and no view depending on it
(measured: only the two ``pg_stat_statements`` views exist in this schema). So
there is nothing to drop and recreate, and doing so by hand would only add a
window in which the indexes do not exist.

REVERSIBILITY. ``downgrade()`` is REAL and lossless here, which is the whole
dividend of remapping instead of deleting: the columns go back to
``varchar(255)`` and then ``tenant_id_remap_audit`` is replayed backwards to
restore the literal ``n8n-dev``. The recovery of record is still the verified
pre-deploy database dump taken before this revision ran
(``pg_restore`` exit 0, zero stderr, every row identical).

⛔ ROLLBACK — READ THIS BEFORE TOUCHING THE DEPLOYMENT
======================================================
THE ONLY SUPPORTED ROLLBACKS ARE:

  A. ``alembic downgrade 20260519_0002``  **and THEN** roll the image back.
     Database first, image second. Always that order.
  B. Restore the verified dump named above.

⛔ **NEVER ``kubectl rollout undo``.** It is the obvious move and it is a
one-way door, in two independent ways. Both were reproduced; both are stated
with the exact string the operator will actually see, because the failure does
not announce that it is this failure.

FAILURE 1 — THE OLD IMAGE CANNOT READ THE NEW COLUMN.
``rollout undo`` changes only the image. The previous image's model declares
``tenant_id: Mapped[str] = mapped_column(String(255))`` while the column is now
``uuid``, so every list/get emits ``WHERE artifacts.tenant_id = $1`` with a text
parameter and postgres answers::

    psycopg.errors.UndefinedFunction: operator does not exist:
    uuid = character varying

and, where the comparison happens in Python instead of SQL, the old
``get_resource_with_tenant_check`` runs a bare ``resource.tenant_id != tenant_id``
— ``uuid.UUID`` against ``str`` — which is ALWAYS ``True``, so the rightful owner
gets **404 for their own artifact**. That second one is worse than the crash:
it is a silent, total, tenant-wide data outage that reads as "the data is gone".

FAILURE 2 — THE OLD IMAGE'S INIT CONTAINER CANNOT START.
``rollout undo`` also reverts the init container, which runs
``alembic upgrade head`` against a database whose ``alembic_version`` now says
``20260826_0003``. The old image's ``alembic/versions/`` does not contain that
revision, so::

    alembic.util.exc.CommandError: Can't locate revision identified by
    '20260826_0003'

exit status **255**. The init container CrashLoopBackOffs. This Deployment is
``strategy: Recreate`` with ``replicas: 1``, so the new pod's predecessor is
ALREADY GONE: nothing serves, and no amount of waiting fixes it because the
retry is deterministic. Recovery from there is A or B anyway — ``rollout undo``
has bought nothing and cost the whole service.

Note the ordering constraint inside option A: ``downgrade()`` writes the literal
``'n8n-dev'``, which a ``uuid`` column cannot hold, so the ALTERs back to
``varchar`` must run BEFORE the reverse remap — that is why ``downgrade()`` is
written in that order and why it must be run while the NEW image is still
deployed (it is the only image that has the revision).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260826_0003"
down_revision = "20260519_0002"
branch_labels = None
depends_on = None


#: The columns whose TYPE this migration changes, as ``{table: column}``.
TENANT_COLUMNS = {"artifacts": "tenant_id", "artifact_reviews": "reviewer_tenant_id"}

#: ``{legacy literal: real uuid}``. Frozen deliberately: any other non-uuid value
#: must ABORT the run (see ``_assert_cast_is_total``), never be swept up here.
#: Widening this map is a decision about tenant ownership, so it must be a diff.
REMAP = {"n8n-dev": "019de842-c92a-7e37-8fdd-eb0d8c5396f9"}  # pragma: allowlist secret

#: There is deliberately NO value-only remap list. ``artifacts.subject_id`` holds
#: the same legacy literal on 224 rows and is the obvious candidate, but it gates
#: ``can_mutate()`` — rewriting it here would be an authorization change wearing a
#: typing change's clothes. See the docstring section that names the numbers.

#: ``pg_input_is_valid`` (PG>=16) rather than a regex, on purpose: it is exactly
#: the predicate "will ``::uuid`` succeed on this value", so the guard and the
#: cast can never disagree. A hand-rolled regex would reject the dashless and
#: braced spellings ``::uuid`` accepts, turning a castable value into a spurious
#: abort. Measured server here: 180004.
_MIN_PG_VERSION = 160000

_AUDIT_TABLE = "tenant_id_remap_audit"

#: The column ``downgrade()`` uses to tell "a row this migration moved" apart
#: from "a row that legitimately belongs to the real tenant". It is deliberately
#: never written by this migration, which is what makes it a witness. A table
#: with an audit row but no such column cannot be reversed safely and must
#: RAISE — see ``downgrade()``.
_PROVENANCE_COLUMN = "tenant_name"


def _audit_key(table: str, column: str) -> str:
    """Audit rows are keyed by ``table.column``, not by table.

    The audit primary key is ``(table_name, legacy_value)``, and the two tenant
    columns have DIFFERENT names on different tables, so a bare table name would
    happen to be unique today. It is still wrong to rely on that: the moment a
    second column on one table is added to the remap (``subject_id`` is the
    standing candidate — see the docstring), the second write would overwrite the
    first under ``ON CONFLICT DO UPDATE`` and the audit would under-report by an
    entire column, while ``downgrade()`` would not know which column to restore.
    An audit that under-reports is worse than no audit, because it is believed.
    ``downgrade()`` therefore parses this key rather than assuming a column.
    """
    return f"{table}.{column}"


def _server_version(bind: sa.engine.Connection) -> int:
    return int(bind.exec_driver_sql("SHOW server_version_num").scalar_one())


def _live_columns(bind: sa.engine.Connection, wanted: dict[str, str]) -> dict[tuple[str, str], str]:
    """Live ``{(table, column): type}`` read from ``pg_catalog``.

    Read from the catalog and NOT from ``Base.metadata``: the models describe the
    tree being deployed, the catalog describes the database being migrated.

    ⛔ AND READ FROM ``pg_catalog`` RATHER THAN ``information_schema``, WHICH IS
    PRIVILEGE-FILTERED. ``information_schema.columns`` exposes only columns of
    relations the current role holds some privilege on, so a table this role
    cannot see SILENTLY DISAPPEARS from the work list — and because the
    postcondition re-reads the very same view, it would not see it either and the
    run would report success having skipped a column. The guard and the defect
    would share a source. ``pg_class``/``pg_attribute`` are not privilege
    filtered, so an unreadable table reaches ``_assert_owned`` and is refused BY
    NAME.

    ⛔ THE CASTS HERE ARE ``CAST(:p AS text[])`` AND MUST NOT BE "SIMPLIFIED" BACK
    TO ``:p::text[]``. SQLAlchemy's ``text()`` bind-parameter regex has a negative
    lookahead for a following colon, so a parameter written immediately before a
    ``::`` cast is not parsed as written. It does not reliably raise — measured::

        sa.text("SELECT :tables::text[]")._bindparams.keys()
        -> dict_keys(['table'])       # silently a DIFFERENT parameter name
        sa.text("SELECT CAST(:tables AS text[])")._bindparams.keys()
        -> dict_keys(['tables'])      # correct

    The first form binds ``table``, not ``tables``. The quiet version of that bug
    is far worse than the loud one: this query would read whatever it happened to
    bind, and the postcondition, which calls this same function, would agree with
    it. Here it failed loudly with a ``psycopg.errors.SyntaxError``. That was
    luck, not a safety net.
    """
    rows = bind.execute(
        sa.text(
            "SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod) "
            "FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid = c.oid "
            "WHERE n.nspname = current_schema() AND c.relkind = 'r' "
            "AND a.attnum > 0 AND NOT a.attisdropped "
            "AND (c.relname, a.attname) IN ("
            "  SELECT t, col FROM unnest("
            "    CAST(:tables AS text[]), CAST(:columns AS text[])"
            "  ) AS u(t, col)"
            ")"
        ),
        {"tables": list(wanted), "columns": list(wanted.values())},
    ).all()
    return {(r[0], r[1]): r[2] for r in rows}


def _assert_owned(bind: sa.engine.Connection, tables: list[str]) -> None:
    """Refuse to run if the migration role cannot ALTER one of these tables.

    ``ALTER TABLE`` requires ownership, not merely write access. Failing here
    costs one clean named abort; failing halfway through the ALTERs during a
    single-replica deploy is an outage with no old pod still serving.
    """
    rows = bind.execute(
        sa.text(
            "SELECT c.relname, pg_get_userbyid(c.relowner) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = current_schema() AND c.relkind = 'r' "
            "AND c.relname = ANY(:tables) "
            "AND NOT pg_has_role(current_user, c.relowner, 'USAGE')"
        ),
        {"tables": tables},
    ).all()
    if rows:
        detail = ", ".join(f"{t} owned by {o}" for t, o in rows)
        raise RuntimeError(
            f"cannot ALTER tables this role does not own: {detail}. "
            "Fix ownership before deploying; do not grant around it."
        )


def _create_audit_table(bind: sa.engine.Connection) -> None:
    bind.exec_driver_sql(
        f"CREATE TABLE IF NOT EXISTS {_AUDIT_TABLE} ("
        "  table_name   text        NOT NULL,"
        "  legacy_value text        NOT NULL,"
        "  row_count    bigint      NOT NULL,"
        "  new_value    text        NOT NULL,"
        "  remapped_at  timestamptz NOT NULL DEFAULT now(),"
        "  PRIMARY KEY (table_name, legacy_value)"
        ")"
    )


def _remap(bind: sa.engine.Connection, targets: list[tuple[str, str]]) -> None:
    """Record the count, then rewrite the value. Audit first, always.

    The count is taken BEFORE the ``UPDATE`` because afterwards the old value no
    longer exists to be counted, and ``downgrade()`` needs to know how many rows
    it is entitled to move back.
    """
    for table, column in targets:
        for legacy, new in REMAP.items():
            n = int(
                bind.execute(
                    sa.text(f'SELECT count(*) FROM "{table}" WHERE "{column}" = :v'),
                    {"v": legacy},
                ).scalar_one()
            )
            bind.execute(
                sa.text(
                    # DO UPDATE, never DO NOTHING. A stale audit row left by an
                    # earlier partial attempt would otherwise be KEPT and the
                    # real counts discarded, producing an audit that
                    # under-reports what this run actually rewrote.
                    f"INSERT INTO {_AUDIT_TABLE} "
                    "(table_name, legacy_value, row_count, new_value) "
                    "VALUES (:t, :legacy, :n, :new) "
                    "ON CONFLICT (table_name, legacy_value) DO UPDATE SET "
                    "row_count = EXCLUDED.row_count, "
                    "new_value = EXCLUDED.new_value, "
                    "remapped_at = now()"
                ),
                {"t": _audit_key(table, column), "legacy": legacy, "n": n, "new": new},
            )
            if n:
                bind.execute(
                    sa.text(f'UPDATE "{table}" SET "{column}" = :new WHERE "{column}" = :legacy'),
                    {"new": new, "legacy": legacy},
                )
            # Present participle on purpose. This prints INSIDE the single
            # transaction alembic wraps the whole upgrade in, so a later guard
            # can still roll all of it back while this line stays in the log.
            # "remapped" would be a claim about a commit that has not happened.
            print(  # noqa: T201
                f"REMAP {table}.{column}: {legacy} -> {new}, remapping {n} rows"
            )


def _assert_legacy_rows_have_provenance(
    bind: sa.engine.Connection, targets: list[tuple[str, str]]
) -> None:
    """Refuse, BEFORE the first write, to remap rows that could never be un-remapped.

    ⛔ THIS IS THE GUARD THAT USED TO LIVE IN ``downgrade()``, AND MOVING IT IS
    THE WHOLE POINT.

    ``artifact_reviews`` carries ``reviewer_tenant_id`` but has NO
    ``tenant_name`` column — it is a flat decision log, not a
    tenant-labelled resource row. It holds 0 rows in production today, which is
    exactly the snapshot ``_assert_cast_is_total``'s own docstring warns about:
    the old pod serves right up to the moment the init container runs, so it can
    acquire an ``n8n-dev`` review between the pre-deploy census and this
    statement.

    ONE such row was enough to make this migration a ONE-WAY DOOR. Reproduced on
    a restore (3 artifacts + 2 reviews under ``n8n-dev``): ``_remap()`` wrote an
    audit row ``artifact_reviews.reviewer_tenant_id row_count=2``; ``downgrade()``
    then reached that audit row, found no ``tenant_name`` to scope the reverse
    by, and raised. ``alembic/env.py`` wraps the whole downgrade in ONE
    transaction, so that raise rolled back the two type-widening ALTERs as well —
    ``artifacts`` was not reverted either. Identically on every retry, forever.
    The database is stuck at ``20260826_0003`` and only the dump recovers it, at
    which point "reversible migration" is decoration.

    Failing HERE is recoverable in the way that one was not: nothing has been
    written, the operator gets the table and the count by name, and a retry after
    the row is dealt with succeeds.

    WHY REFUSE RATHER THAN "SKIP REMAPPING THAT TABLE BUT STILL RE-TYPE IT".
    Because that option does not exist. Re-typing means ``reviewer_tenant_id::uuid``
    and ``'n8n-dev'`` has no uuid cast, so leaving the row alone only moves the
    failure a few lines down into :func:`_assert_cast_is_total` with a worse
    message. The real choice is between refusing and remapping IRREVERSIBLY, and
    a migration that quietly makes itself one-way is not one this service ships.

    WHY NOT SCOPE THE REVIEW REVERSE THROUGH ITS FK TO ``artifacts.tenant_name``.
    It was considered and it is WRONG, not merely awkward.
    ``artifact_reviews.reviewer_tenant_id`` is the tenant of the REVIEWER, and
    ``artifacts.tenant_id`` is the tenant that OWNS the artifact; nothing in the
    schema makes them equal. Scoping the reverse through the parent would revert
    reviews whose parent happened to be an ``n8n-dev`` artifact (over-revert) and
    miss ``n8n-dev`` reviews of some other tenant's artifact (under-revert). A
    discriminator that is merely CORRELATED with provenance is not provenance.

    WHY NOT A ROW-ID MANIFEST captured at upgrade time. It is genuinely the
    stronger crosswalk — ``WHERE id = ANY(:ids)`` needs no witness column at all —
    and it would retire the KNOWN EXPIRY CONDITION in ``downgrade()`` too. It is
    rejected here for SHAPE, not merit: the sibling repo ``procedure_management``
    hit the identical defect in ``meta_procedure_executions`` and is landing this
    same upgrade-time refusal, and two services whose rollback procedure differs
    in kind is a worse operational outcome than two services with the same
    slightly-weaker guard. If the id crosswalk lands, it lands in both, together.
    """
    offenders = []
    for table, column in sorted(targets):
        if _live_columns(bind, {table: _PROVENANCE_COLUMN}):
            continue
        for legacy in sorted(REMAP):
            n = int(
                bind.execute(
                    sa.text(f'SELECT count(*) FROM "{table}" WHERE "{column}" = :v'),
                    {"v": legacy},
                ).scalar_one()
            )
            if n:
                offenders.append(f"{table}.{column}: {n} row(s) hold {legacy!r}")
    if offenders:
        raise RuntimeError(
            "refusing to remap rows that could never be un-remapped: "
            + "; ".join(offenders)
            + f". These tables have no {_PROVENANCE_COLUMN!r} column, so downgrade() "
            "would have no discriminator between the rows this migration moved and "
            "rows that already belonged to the target tenant — remapping them makes "
            "this migration ONE-WAY, and the failure would surface as a downgrade "
            "that rolls itself back on every retry. Re-tenant or remove those rows "
            "(they come from a caller sending a non-uuid X-Tenant-Id, which the "
            "hardened middleware now rejects), then re-run. Nothing has been "
            "written; this transaction rolls back clean."
        )


def _assert_no_dependent_views_or_rules(
    bind: sa.engine.Connection, targets: list[tuple[str, str]]
) -> None:
    """Refuse if a view, materialized view or rule reads one of the tenant columns.

    ``ALTER TABLE … ALTER COLUMN … TYPE`` does not rewrite dependent rewrite
    rules; it refuses outright::

        psycopg.errors.FeatureNotSupported: cannot alter type of a column used
        by a view or rule

    The module docstring measures that no such object exists in this schema
    today. "None today" is a census, not a guard, and the cost of being wrong is
    not a failed statement — this Deployment is ``strategy: Recreate`` with
    ``replicas: 1``, so the old pod is already gone when the init container runs.
    Learning it from a crashlooping init container costs the whole service;
    learning it here costs one named refusal with nothing written.

    ``pg_depend`` is read directly rather than inferred from ``pg_views``: the
    dependency Postgres enforces is the ``pg_rewrite`` -> column edge, and only
    that edge distinguishes a view that merely MENTIONS the table from one that
    SELECTs the column. Matching ``d.refobjsubid`` against the column's attnum is
    what keeps this from refusing views that never touch it.
    """
    rows = bind.execute(
        sa.text(
            "SELECT DISTINCT c.relname AS table_name, a.attname AS column_name, "
            "dep.relname AS dependent_name, dep.relkind AS dependent_kind "
            "FROM pg_depend d "
            "JOIN pg_rewrite r ON r.oid = d.objid "
            "JOIN pg_class dep ON dep.oid = r.ev_class "
            "JOIN pg_class c ON c.oid = d.refobjid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.refobjsubid "
            "WHERE d.classid = 'pg_rewrite'::regclass "
            "AND d.refclassid = 'pg_class'::regclass "
            "AND n.nspname = current_schema() "
            "AND a.attnum > 0 AND NOT a.attisdropped "
            "AND (c.relname, a.attname) IN ("
            "  SELECT t, col FROM unnest("
            "    CAST(:tables AS text[]), CAST(:columns AS text[])"
            "  ) AS u(t, col)"
            ") "
            "ORDER BY 1, 2, 3"
        ),
        {"tables": [t for t, _ in targets], "columns": [c for _, c in targets]},
    ).all()
    if not rows:
        return
    kinds = {"v": "view", "m": "materialized view", "r": "rule on table"}
    detail = "; ".join(
        f"{r.table_name}.{r.column_name} is used by "
        f"{kinds.get(r.dependent_kind, r.dependent_kind)} {r.dependent_name!r}"
        for r in rows
    )
    raise RuntimeError(
        "cannot re-type the tenant columns: PostgreSQL refuses ALTER COLUMN TYPE "
        f"while a view or rule depends on the column — {detail}. Drop and recreate "
        "the dependent object(s) around this migration. Refusing BEFORE writing "
        "anything: this Deployment is Recreate/replicas=1, so failing on the ALTER "
        "instead would be a full outage with no old pod serving."
    )


def _assert_cast_is_total(bind: sa.engine.Connection, targets: list[tuple[str, str]]) -> None:
    """Every surviving value must already be castable, or abort before the ALTER.

    Runs AFTER the remap, so it sees the post-remap population — which is the
    population the ``ALTER`` will actually cast. This is the guard that catches a
    value written by the still-running OLD pod between the pre-deploy census and
    this statement.

    It deliberately does NOT coerce and does NOT delete. A legacy value nobody
    planned for is a human decision about tenant ownership, not a cleanup, and
    the whole run is one transaction so aborting costs a retry and nothing else.
    """
    offenders = []
    for table, column in targets:
        rows = (
            bind.execute(
                sa.text(
                    f'SELECT DISTINCT "{column}" FROM "{table}" '
                    f'WHERE "{column}" IS NOT NULL '
                    f"AND NOT pg_input_is_valid(\"{column}\", 'uuid') LIMIT 5"
                )
            )
            .scalars()
            .all()
        )
        if rows:
            offenders.append(f"{table}.{column}: {sorted(rows)!r}")
    if offenders:
        raise RuntimeError(
            "the uuid cast is NOT total — these values are neither uuids nor in "
            f"REMAP {sorted(REMAP)!r}: " + "; ".join(offenders) + ". Decide what "
            "tenant they belong to and add them to REMAP; do not coerce them here."
        )


def _assert_no_spelling_collisions(
    bind: sa.engine.Connection, targets: list[tuple[str, str]]
) -> None:
    """Refuse if two distinct TEXT values would become the same uuid.

    Under ``varchar`` equality ``019DE842-…`` (uppercase) and ``019de842…``
    (dashless) are separate tenant silos; under ``uuid`` they are one value, so
    the cast MERGES them and nothing else in this migration would notice. The
    merge is arguably correct — they really are the same uuid, and the varchar
    behaviour was the bug — but it is still a decision about whose rows become
    whose, and this migration's contract is that it re-types a column and remaps
    one named tenant. Nothing else. So it aborts and names the values.

    The window is real: the old pod is still accepting the old header format
    while this runs, so a second spelling can arrive after the census.
    """
    offenders = []
    for table, column in targets:
        rows = bind.execute(
            sa.text(
                f'SELECT "{column}"::uuid AS u, array_agg(DISTINCT "{column}") AS spellings '
                f'FROM "{table}" WHERE "{column}" IS NOT NULL '
                f"AND pg_input_is_valid(\"{column}\", 'uuid') "
                'GROUP BY 1 HAVING count(DISTINCT "' + column + '") > 1'
            )
        ).all()
        for r in rows:
            offenders.append(f"{table}.{column}: {sorted(r.spellings)!r} all mean {r.u}")
    if offenders:
        raise RuntimeError(
            "refusing to MERGE tenants: distinct spellings collapse to one uuid "
            "under the cast. Decide which rows belong to whom, then re-run: " + "; ".join(offenders)
        )


def upgrade() -> None:
    bind = op.get_bind()

    # Bound every lock this migration takes. Without it one long-running reader
    # parks the ALTER behind an ACCESS EXCLUSIVE wait while the whole query queue
    # piles up behind IT. Failing fast is free: one transaction, so an abort
    # leaves the database exactly as it was and the init container retries.
    bind.exec_driver_sql("SET LOCAL lock_timeout = '10s'")

    version = _server_version(bind)
    if version < _MIN_PG_VERSION:
        raise RuntimeError(f"needs PostgreSQL >= 16 for pg_input_is_valid(); server is {version}")

    live = _live_columns(bind, TENANT_COLUMNS)
    if len(live) != len(TENANT_COLUMNS):
        missing = sorted(f"{t}.{c}" for t, c in TENANT_COLUMNS.items() if (t, c) not in live)
        raise RuntimeError(
            f"expected {len(TENANT_COLUMNS)} tenant columns, found {len(live)} — "
            f"missing: {missing}. A rename or drop must be an explicit decision, "
            "not a column this migration silently skips."
        )

    if all(dtype == "uuid" for dtype in live.values()):
        print("20260826_0003: both tenant columns are already uuid — nothing to do")  # noqa: T201
        return

    tenant_targets = sorted(live)
    _assert_owned(bind, sorted({t for t, _ in tenant_targets}))

    # ⛔ BOTH OF THESE RUN BEFORE THE FIRST WRITE, and that placement is the fix,
    # not a style choice. Everything after this point either succeeds or is a
    # rollback someone has to reason about; these two are the failures that are
    # cheap precisely because nothing has happened yet. Read each docstring for
    # what it costs to learn the same fact later — for the provenance guard the
    # answer is "a permanently un-downgradable database".
    _assert_no_dependent_views_or_rules(bind, tenant_targets)
    _assert_legacy_rows_have_provenance(bind, tenant_targets)

    _create_audit_table(bind)
    # Only the two typed columns are rewritten. artifacts.subject_id keeps its
    # legacy literal on purpose — see the docstring; it is an authz gate, not a
    # label, and it is not part of this change's contract.
    _remap(bind, tenant_targets)

    _assert_cast_is_total(bind, tenant_targets)
    _assert_no_spelling_collisions(bind, tenant_targets)

    for table, column in tenant_targets:
        op.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE uuid USING "{column}"::uuid'
        )

    # Postcondition, re-read from the same privilege-blind catalog query. A
    # column skipped for ANY reason must abort the transaction rather than leave
    # a varchar the application now writes uuids into — that half-migrated shape
    # is worse than not migrating at all.
    after = _live_columns(bind, TENANT_COLUMNS)
    still_text = sorted(f"{t}.{c}" for (t, c), dtype in after.items() if dtype != "uuid")
    if still_text or len(after) != len(TENANT_COLUMNS):
        raise RuntimeError(
            f"postcondition FAILED — expected {len(TENANT_COLUMNS)} uuid columns, "
            f"read {len(after)}; still not uuid: {still_text}"
        )
    print(f"20260826_0003: uuid on {sorted(f'{t}.{c}' for t, c in after)}")  # noqa: T201


def downgrade() -> None:
    """Real and lossless — nothing was deleted, so everything can go back.

    Order is load-bearing. The columns must return to ``varchar`` FIRST: the
    reverse remap writes the literal ``n8n-dev``, which a ``uuid`` column cannot
    hold, so replaying the audit against a still-typed column would fail on its
    first statement.

    The replay is bounded TWICE, and both bounds are load-bearing.

    **By audit row.** Only rows with ``row_count > 0`` are replayed. A row
    recorded with ``0`` means this migration rewrote nothing on that column, so
    reversing it could only ever hit rows some OTHER writer legitimately put
    under the real uuid.

    **By provenance column — this is the important one.** Matching on the new
    value ALONE is a data-loss bug::

        UPDATE artifacts SET tenant_id = legacy WHERE tenant_id = new   -- WRONG

    That reverts every row holding ``019de842-…``: the 284 this migration moved
    AND every row a caller has legitimately written under the real tenant since.
    ``row_count > 0`` does not save it — that filter decides only WHETHER the
    statement runs, never WHICH rows it hits. ``artifact_registry`` holding 0
    rows under ``019de842-…`` at migration time does not save it either, because
    a downgrade happens later, after the gate is live and those rows exist.

    So the reverse is scoped by ``tenant_name``, which this migration never
    writes and which therefore still says where each row came from: moved rows
    read ``tenant_name = 'n8n-dev'``, legitimate rows read the uuid string.

    KNOWN EXPIRY CONDITION, stated rather than assumed: ``019de842-…`` really IS
    named ``n8n-dev`` in ``licenses.tenants``. Today nothing writes that display
    label — ``tenant_name`` is a copy of ``tenant_id`` on 51,238 of 51,238 rows.
    The day license-authz starts populating ``tenant_name`` with resolved display
    labels, new legitimate rows will also read ``n8n-dev`` and this discriminator
    stops discriminating. If that ships, this downgrade must be changed to replay
    an explicit manifest of row ids captured at upgrade time. It is safe now, and
    it is safe for a knowable reason rather than by luck.
    """
    bind = op.get_bind()
    bind.exec_driver_sql("SET LOCAL lock_timeout = '10s'")

    for table, column in sorted(TENANT_COLUMNS.items()):
        op.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE varchar(255) '
            f'USING "{column}"::text'
        )

    if bind.execute(sa.text("SELECT to_regclass(:t)"), {"t": _AUDIT_TABLE}).scalar_one_or_none():
        rows = bind.execute(
            sa.text(
                "SELECT table_name, legacy_value, new_value, row_count "
                f"FROM {_AUDIT_TABLE} WHERE row_count > 0"
            )
        ).all()
        for table_name, legacy, new, n in rows:
            table, _, column = table_name.partition(".")
            if not column:
                raise RuntimeError(
                    f"{_AUDIT_TABLE}.table_name {table_name!r} is not 'table.column'; "
                    "refusing to guess which column to restore."
                )
            # RESIDUAL, and no longer the primary gate. `upgrade()` now REFUSES
            # to remap a provenance-less table at all
            # (`_assert_legacy_rows_have_provenance`), so a database upgraded by
            # THIS revision can never reach here with such an audit row. This
            # survives for a database upgraded by an EARLIER build of this file,
            # which could — and for that database the raise is still the right
            # answer, because those rows really are unrecoverable by value.
            # Before the upgrade-time guard existed, this raise was the one-way
            # door: it aborts inside alembic's single downgrade transaction, so
            # it rolled back the ALTERs too and left the database stuck at this
            # revision on every retry.
            if not _live_columns(bind, {table: _PROVENANCE_COLUMN}):
                raise RuntimeError(
                    f"cannot safely reverse {table}.{column}: {table} has no "
                    f"{_PROVENANCE_COLUMN!r} column to distinguish the {n} rows this "
                    f"migration moved from rows legitimately written under {new}. "
                    "Refusing to run an unscoped UPDATE that would relabel the real "
                    "tenant's data. This database was upgraded by an earlier build of "
                    "this migration, which did not refuse those rows up front; restore "
                    "from the dump named in the module docstring."
                )
            result = bind.execute(
                sa.text(
                    f'UPDATE "{table}" SET "{column}" = :legacy '
                    f'WHERE "{column}" = :new AND "{_PROVENANCE_COLUMN}" = :legacy'
                ),
                {"legacy": legacy, "new": new},
            )
            # Printed BEFORE the check below, deliberately: the whole downgrade is
            # one transaction, so a raise rolls the UPDATE back while this line
            # survives in the log — and that is the run where the numbers matter
            # most.
            print(  # noqa: T201
                f"UNREMAP {table}.{column}: {new} -> {legacy}, "
                f"restoring {result.rowcount} of {n} recorded rows"
            )
            # ⛔ ONLY THE OVER-REVERT DIRECTION RAISES, and the asymmetry is the
            # point.
            #
            # MORE rows than the audit recorded means `tenant_name` has stopped
            # discriminating and every row past `n` is being dragged into a
            # tenant that does not exist — the KNOWN EXPIRY CONDITION in this
            # function's docstring, arriving. The middleware can mint exactly
            # that shape: it takes `tenant_name` straight from `X-Tenant-Name`,
            # so a caller sending the correct uuid plus `X-Tenant-Name: n8n-dev`
            # creates a look-alike row. That is damage, and rolling back is free.
            #
            # FEWER rows is NOT an error and must not raise. Rows this migration
            # moved can legitimately have been DELETED since the upgrade, which
            # this file has documented from the start. Raising on that direction
            # would block a correct rollback for a benign reason — i.e. it would
            # re-create, in the opposite direction, the one-way door
            # `_assert_legacy_rows_have_provenance` exists to close. It is loud
            # in the log and nothing more.
            #
            # (`procedure_management` shipped strict equality here first and it
            # WAS a real defect — an ordinary DELETE between upgrade and rollback
            # bricked its downgrade. It has since been corrected to match this
            # shape, so the two services now agree. Do not "harmonise" back to
            # `!=`: that is the direction that was wrong.)
            if result.rowcount > n:
                raise RuntimeError(
                    f"refusing to complete the downgrade: {table}.{column} matched "
                    f"{result.rowcount} rows but the audit recorded {n}. "
                    f"{_PROVENANCE_COLUMN} = {legacy!r} no longer identifies exactly "
                    f"the rows this migration moved, so {result.rowcount - n} row(s) "
                    f"that legitimately hold {new} would be relabelled to a tenant "
                    "that does not exist. Rolling back — nothing has changed. Restore "
                    "from the pre-deploy dump, or reconcile tenant_name by hand and "
                    "re-run."
                )

    op.execute(f"DROP TABLE IF EXISTS {_AUDIT_TABLE}")
