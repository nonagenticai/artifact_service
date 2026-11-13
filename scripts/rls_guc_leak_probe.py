#!/usr/bin/env python3
"""DISCRIMINATING tenant-GUC leak probe for the art#49 RLS backstop (post-deploy).

Copied from procedure_management ``scripts/rls_guc_leak_probe.py`` (pm#107).

Only meaningful once alembic 20261003_0001's policies exist: without policies every
transaction sees every row and a leak is invisible (the pre-policy "enforce-flip"
interleaved probe was a no-regression check only, and must be labelled so).

What it does, ``--rounds`` times (default 50), each step on a DIFFERENT client
connection to the same pool (pgbouncer, transaction pooling), so a server
backend handed from one client to the next is exactly the path a leaked
session GUC would travel:

1. tenant-A transaction: ``set_config('app.current_tenant', A, true)``; must
   see >= 1 row whose ``tenant_id = A`` (proves the binding + policies work);
2. UNBOUND transaction straight after: must see ``app.current_tenant`` unset or
   '' AND 0 rows of ``--table``;
3. tenant-B transaction: must see 0 rows whose ``tenant_id = A``.

Every transaction is ``READ ONLY`` and ends in ROLLBACK. Exit 0 = no leak in
any round; exit 1 = a leak (or A saw nothing, which would make the run vacuous);
exit 2 = usage / connection error.

In a deployed pod (runtime role, through a connection pooler; A = a tenant that
owns rows, B = a different customer tenant)::

    python scripts/rls_guc_leak_probe.py \\
        --tenant-a 0198c2d4-7a10-7c3e-8b91-4f6a2d5e8c07 \\
        --tenant-b 0198c2d4-7a10-7f52-b0a4-9e1c33d7b6f1

POSITIVE CONTROL (proves the instrument can fail): ``--poison`` makes step 1
bind A with ``set_config(..., false)`` — SESSION level, the bug class pgbouncer
transaction pooling turns into a cross-client leak. Against a local pgbouncer
WITHOUT ``server_reset_query`` it must exit 1. ``--poison`` is refused unless
the DSN host is local: never poison the production pool.
``tests/test_rls_guc_leak_probe.py`` runs that rehearsal on a throwaway local
pgbouncer (and the same run with ``RESET app.current_tenant`` as
``server_reset_query`` + ``server_reset_query_always=1``, prod's setting,
which must exit 0).
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlsplit

import psycopg

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_BIND = "SELECT set_config('app.current_tenant', %s, {local})"


def libpq_url(url: str) -> str:
    for prefix in ("postgresql+psycopg://", "postgresql+asyncpg://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


def _txn(conn: psycopg.Connection, bind: str | None, poison: bool, sql: str, args: tuple):
    # A session-level set_config inside a ROLLED-BACK transaction is undone with
    # it, so the poisoned (positive-control) transaction must COMMIT to model the
    # bug; every other transaction rolls back. All are READ ONLY.
    with conn.transaction(force_rollback=not poison):
        conn.execute("SET TRANSACTION READ ONLY")
        if bind is not None:
            conn.execute(_BIND.format(local="false" if poison else "true"), (bind,))
        guc = conn.execute("SELECT current_setting('app.current_tenant', true)").fetchone()
        row = conn.execute(sql, args).fetchone()
    return (guc[0] if guc else None), (row[0] if row else None)


def probe(
    dsn: str, tenant_a: str, tenant_b: str, table: str, rounds: int, poison: bool, clients: int
) -> list[str]:
    """Run the probe; return the list of failures (empty = no leak)."""
    if not table.isidentifier():
        raise ValueError(f"bad table name {table!r}")
    conns = [psycopg.connect(dsn, autocommit=False) for _ in range(clients)]
    count_a = f"SELECT count(*) FROM {table} WHERE tenant_id = %s::uuid"  # noqa: S608 - identifier checked
    count_all = f"SELECT count(*) FROM {table}"  # noqa: S608 - identifier checked
    failures: list[str] = []
    try:
        for i in range(rounds):
            ca, cu, cb = (conns[(3 * i + k) % clients] for k in range(3))
            _, own = _txn(ca, tenant_a, poison, count_a, (tenant_a,))
            if not own:
                failures.append(f"round {i}: tenant A saw 0 of its own rows (vacuous run)")
            guc_u, n_u = _txn(cu, None, False, count_all, ())
            if guc_u not in (None, "") or n_u:
                failures.append(f"round {i}: UNBOUND txn saw GUC={guc_u!r} and {n_u} rows")
            guc_b, leak_b = _txn(cb, tenant_b, False, count_a, (tenant_a,))
            if leak_b:
                failures.append(f"round {i}: tenant B (GUC={guc_b!r}) saw {leak_b} of A's rows")
    finally:
        for c in conns:
            c.close()
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--dsn", default=os.getenv("DATABASE_URL", ""))
    ap.add_argument("--tenant-a", required=True)
    ap.add_argument("--tenant-b", required=True)
    ap.add_argument("--table", default="artifacts")
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--clients", type=int, default=3)
    ap.add_argument("--poison", action="store_true", help="POSITIVE CONTROL (local only)")
    args = ap.parse_args(argv)
    if not args.dsn:
        print("no --dsn and no DATABASE_URL", file=sys.stderr)
        return 2
    dsn = libpq_url(args.dsn)
    if args.poison and (urlsplit(dsn).hostname or "") not in LOCAL_HOSTS:
        print("--poison is refused against a non-local host", file=sys.stderr)
        return 2
    if args.rounds < 1 or args.clients < 2:
        print("--rounds >= 1 and --clients >= 2 required", file=sys.stderr)
        return 2
    try:
        failures = probe(
            dsn, args.tenant_a, args.tenant_b, args.table, args.rounds, args.poison, args.clients
        )
    except psycopg.Error as exc:
        print(f"connection/query error: {exc}", file=sys.stderr)
        return 2
    for f in failures:
        print(f"LEAK {f}")
    print(
        f"{'FAIL' if failures else 'PASS'}: {len(failures)} failure(s) in {args.rounds} rounds"
        f" x 3 transactions over {args.clients} clients (poison={args.poison})"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
