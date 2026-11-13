"""The GUC-leak probe (``scripts/rls_guc_leak_probe.py``) CAN FAIL — positive control.

Copied from procedure_management ``tests/test_rls_guc_leak_probe.py`` (pm#107).

A throwaway local pgbouncer (transaction pooling, ONE server connection, so
every client transaction reuses the same backend) fronts the test database. A
throwaway table carries alembic 20261003_0001's own ``tenant_isolation`` predicate, and a
throwaway NOBYPASSRLS login role (not the owner) is the client. The role gets a
random per-run password, carried in pgbouncer's auth_file (pgbouncer -> postgres
leg) and in the probe's conninfo, so the rehearsal works whether the test
postgres uses trust or scram-sha-256 (the stock ``postgres:18`` image).

* poisoned (session-level ``set_config(..., false)``) + NO ``server_reset_query``
  ⇒ the probe MUST report a leak (the instrument can fail);
* clean (``set_config(..., true)``, what ``src/tenant_guc.py`` does) ⇒ no leak;
* poisoned + prod's pgbouncer setting (``RESET app.current_tenant``,
  ``server_reset_query_always = 1``, gitops#4336) ⇒ no leak (defence in depth).

Skipped ONLY when no ``pgbouncer`` binary is on PATH (the archetype CI runner
installs none, so CI skips with that reason) or the test database is not on a
local host (pgbouncer is started locally and must reach it). Auth mode is never
a skip reason.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from tests.conftest import TEST_DATABASE_URL

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probe_mod = _load("scripts/rls_guc_leak_probe.py", "_rls_guc_leak_probe")
m_rls = _load("alembic/versions/20261003_0001_rls_tenant_isolation.py", "_migration_rls_probe")

TENANT_A = "0196c0de-a11a-7e01-9c4b-2f8d5a3b7104"
TENANT_B = "0196c0de-b22b-7e02-8d5c-3a9e6b4c8215"
TABLE = "rlsprobe_rows"
DB_URL = probe_mod.libpq_url(TEST_DATABASE_URL)
_PARTS = urlsplit(DB_URL)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(shutil.which("pgbouncer") is None, reason="no pgbouncer binary on PATH"),
    pytest.mark.skipif(
        (_PARTS.hostname or "") not in probe_mod.LOCAL_HOSTS,
        reason="rehearsal needs a local test database",
    ),
]


def _free_port() -> int:
    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port != 8000:
            return port


@pytest.fixture(scope="module")
def fixture_db() -> Iterator[tuple[str, str]]:
    """Throwaway table + NOBYPASSRLS login role; yields (role, password)."""
    role = f"art_rlsprobe_{uuid.uuid4().hex[:8]}"
    password = secrets.token_hex(24)
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(TABLE)))
        conn.execute(
            sql.SQL("CREATE TABLE {} (tenant_id uuid NOT NULL)").format(sql.Identifier(TABLE))
        )
        conn.execute(
            sql.SQL("INSERT INTO {} VALUES (%s), (%s), (%s)").format(sql.Identifier(TABLE)),
            (TENANT_A, TENANT_A, TENANT_B),
        )
        # The migration's own predicate, so the rehearsal tests the shipped policy.
        conn.execute(
            m_rls.create_policy_sql(
                TABLE, "tenant_isolation", "ALL", m_rls.TENANT_PREDICATE, m_rls.TENANT_PREDICATE
            )
        )
        conn.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        conn.execute(
            sql.SQL("GRANT SELECT ON {} TO {}").format(sql.Identifier(TABLE), sql.Identifier(role))
        )
    try:
        yield role, password
    finally:
        with psycopg.connect(DB_URL, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(TABLE)))
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def _pgbouncer(tmp: Path, role: str, password: str, reset: bool) -> tuple[subprocess.Popen, str]:
    port = _free_port()
    db = _PARTS.path.lstrip("/")
    ini = tmp / f"pgb-{port}.ini"
    reset_lines = (
        "server_reset_query = RESET app.current_tenant\nserver_reset_query_always = 1\n"
        if reset
        else "server_reset_query =\n"
    )
    ini.write_text(
        "[databases]\n"
        f"{db} = host={_PARTS.hostname} port={_PARTS.port or 5432} dbname={db}\n"
        "[pgbouncer]\n"
        f"listen_addr = 127.0.0.1\nlisten_port = {port}\n"
        f"unix_socket_dir =\nauth_type = trust\nauth_file = {tmp / 'users.txt'}\n"
        "pool_mode = transaction\ndefault_pool_size = 1\nmax_client_conn = 20\n"
        f"{reset_lines}"
        f"logfile = {tmp / f'pgb-{port}.log'}\n"
    )
    # Plaintext password: pgbouncer needs it to answer postgres's SCRAM
    # challenge on the server leg. 0600, deleted with tmp_path.
    users = tmp / "users.txt"
    fd = os.open(users, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f'"{role}" "{password}"\n')
    proc = subprocess.Popen(
        ["pgbouncer", str(ini)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    dsn = make_conninfo(host="127.0.0.1", port=port, dbname=db, user=role, password=password)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return proc, dsn
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError(f"pgbouncer exited: {proc.stderr.read() if proc.stderr else ''}")
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("pgbouncer did not start")


@pytest.mark.parametrize(
    ("poison", "reset", "leaks"),
    [
        (True, False, True),  # positive control: the instrument CAN fail
        (False, False, False),  # transaction-local binding (tenant_guc.py): no leak
        (True, True, False),  # prod pgbouncer RESET: defence in depth
    ],
)
def test_the_probe_discriminates(fixture_db, tmp_path, poison, reset, leaks):
    role, password = fixture_db
    proc, dsn = _pgbouncer(tmp_path, role, password, reset)
    try:
        failures = probe_mod.probe(
            dsn, TENANT_A, TENANT_B, TABLE, rounds=50, poison=poison, clients=3
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    if leaks:
        # Every round's UNBOUND transaction inherits A's session GUC and sees
        # A's rows. (B's own set_config(..., true) masks A inside B's txn.)
        unbound = [f for f in failures if "UNBOUND" in f]
        assert len(unbound) == 50, failures[:3]
        assert all(f"GUC='{TENANT_A}'" in f for f in unbound)
    else:
        assert failures == []


def test_poison_is_refused_against_a_non_local_host():
    rc = probe_mod.main(
        [
            "--dsn",
            "postgresql://u@pgbouncer.example:6432/db",
            "--tenant-a",
            TENANT_A,
            "--tenant-b",
            TENANT_B,
            "--poison",
        ]
    )
    assert rc == 2
