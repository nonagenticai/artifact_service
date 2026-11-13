"""The DB-backed suite must actually reach a database — or go RED.

History: ``tests/conftest.py`` once read only ``TEST_DATABASE_URL``, a name the
CI archetype never sets, so every DB-backed test skipped and CI reported
``232 passed, 86 skipped`` without touching postgres. The fix has three halves,
all pinned here:

* resolution: ``TEST_DATABASE_URL`` -> ``DATABASE_URL`` (the archetype export)
  -> an ephemeral docker ``postgres:18`` started by conftest;
* an unreachable database is a FAILURE, never a skip, anywhere;
* a session that collected DB-backed tests and ran none is a FAILURE.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import conftest as root_conftest
import pytest
from sqlalchemy import text

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def clean_dsn_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in ("TEST_DATABASE_URL", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class TestDsnResolution:
    def test_database_url_alone_is_enough(self, clean_dsn_env: pytest.MonkeyPatch) -> None:
        """The archetype's own export."""
        clean_dsn_env.setenv(
            "DATABASE_URL",
            "postgresql+psycopg://ci_test:ci_test@127.0.0.1:5599/ar_ci",  # pragma: allowlist secret
        )
        assert (
            root_conftest._resolve_test_database_url()
            == "postgresql+psycopg://ci_test:ci_test@127.0.0.1:5599/ar_ci"  # pragma: allowlist secret
        )

    def test_test_database_url_wins(self, clean_dsn_env: pytest.MonkeyPatch) -> None:
        clean_dsn_env.setenv(
            "TEST_DATABASE_URL",
            "postgresql+psycopg://me:pw@127.0.0.1:5601/mine",  # pragma: allowlist secret
        )
        clean_dsn_env.setenv(
            "DATABASE_URL",
            "postgresql+psycopg://ci_test:ci_test@127.0.0.1:5599/ar_ci",  # pragma: allowlist secret
        )
        assert (
            root_conftest._resolve_test_database_url()
            == "postgresql+psycopg://me:pw@127.0.0.1:5601/mine"  # pragma: allowlist secret
        )

    def test_a_bare_postgresql_scheme_is_given_the_psycopg_driver(
        self, clean_dsn_env: pytest.MonkeyPatch
    ) -> None:
        clean_dsn_env.setenv(
            "DATABASE_URL",
            "postgresql://ci_test:ci_test@127.0.0.1:5599/ar_ci",  # pragma: allowlist secret
        )
        assert root_conftest._resolve_test_database_url().startswith("postgresql+psycopg://")

    def test_no_env_means_start_a_container_not_a_localhost_default(
        self, clean_dsn_env: pytest.MonkeyPatch
    ) -> None:
        assert root_conftest._resolve_test_database_url() is None

    def test_the_password_is_redacted_before_it_reaches_a_log(self) -> None:
        redacted = root_conftest._redact("postgresql+psycopg://ci_test:s3cret@127.0.0.1:5599/ar_ci")
        assert redacted == "postgresql+psycopg://ci_test:***@127.0.0.1:5599/ar_ci"

    def test_the_resolved_url_is_exported_for_subprocesses(self) -> None:
        import os

        assert os.environ["TEST_DATABASE_URL"] == root_conftest.TEST_DATABASE_URL


async def test_the_session_database_is_postgres_18(pg_engine) -> None:
    """Whatever the source (env or the auto-started container), it is real PG 18."""
    async with pg_engine.connect() as conn:
        version = (await conn.execute(text("SHOW server_version_num"))).scalar_one()
    assert int(version) // 10000 == 18


class TestThereIsExactlyOneDsnResolution:
    def test_no_test_module_re_derives_the_dsn(self) -> None:
        """Nothing under ``tests/`` may carry its own getenv default for the DSN."""
        offenders = []
        for path in sorted((REPO_ROOT / "tests").rglob("test_*.py")):
            if path.name == "test_ci_reaches_the_database.py":
                continue
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if 'getenv("TEST_DATABASE_URL"' in line or "getenv('TEST_DATABASE_URL'" in line:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}")
        assert not offenders, f"re-derive the test DSN instead of using conftest: {offenders}"

    def test_visibility_shares_the_resolved_dsn(self) -> None:
        import importlib

        module = importlib.import_module("tests.test_visibility")
        assert module.TEST_DATABASE_URL == root_conftest.TEST_DATABASE_URL

    def test_conftest_and_tests_conftest_are_different_module_objects(self) -> None:
        """pytest loads the root conftest as ``conftest``; ``tests.conftest`` is a
        second module object. The counter must be bumped through ``conftest``."""
        import tests.conftest as package_spelling

        assert package_spelling is not root_conftest
        assert sys.modules["conftest"] is root_conftest
        # ...and the second object did NOT start a second container.
        assert package_spelling._ephemeral_container is None
        assert package_spelling.TEST_DATABASE_URL == root_conftest.TEST_DATABASE_URL


class TestTheNonVacuityGuard:
    class _FakeSession:
        def __init__(self, config: pytest.Config) -> None:
            self.config = config
            self.exitstatus = pytest.ExitCode.OK

    @pytest.mark.parametrize(
        ("collected", "ran", "expected"),
        [
            (86, 0, pytest.ExitCode.TESTS_FAILED),
            (86, 86, pytest.ExitCode.OK),
            (0, 0, pytest.ExitCode.OK),
        ],
    )
    def test_guard(
        self,
        monkeypatch: pytest.MonkeyPatch,
        request: pytest.FixtureRequest,
        collected: int,
        ran: int,
        expected: pytest.ExitCode,
    ) -> None:
        monkeypatch.setattr(root_conftest, "_DB_BACKED_COLLECTED", collected)
        monkeypatch.setattr(root_conftest, "_DB_BACKED_RAN", ran)
        session = self._FakeSession(request.config)
        root_conftest.pytest_sessionfinish(session, 0)
        assert session.exitstatus == expected


def _child_pytest(env: dict[str, str], tmp_path: Path) -> tuple[int, str]:
    """Run one DB-backed test in a child pytest under ``tests/`` (so the root
    conftest loads) and return (exit status, output)."""
    with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tests") as scratch:
        test_file = Path(scratch) / "test_needs_a_database.py"
        test_file.write_text(
            "async def test_touches_the_database(pg_engine):\n    assert pg_engine is not None\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-p", "no:cacheprovider", "-q"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={
                "HOME": str(tmp_path),
                "JWT_SECRET_KEY": "test-secret-key-for-unit-tests-min-32-chars",  # pragma: allowlist secret
                "PYTHONPATH": str(REPO_ROOT / "src"),
                **env,
            },
            timeout=180,
        )
    return proc.returncode, proc.stdout + proc.stderr


def test_an_unreachable_database_fails_and_is_never_skipped(tmp_path: Path) -> None:
    """END TO END: a run whose database refuses connections exits non-zero.

    No CI env vars on purpose — this is now true on a laptop too.
    """
    rc, out = _child_pytest(
        {
            "PATH": "/usr/bin:/bin",
            # 127.0.0.1:1 is refused instantly: a bounded failure, not a timeout.
            "TEST_DATABASE_URL": "postgresql+psycopg://nobody:nobody@127.0.0.1:1/nothing",  # pragma: allowlist secret
        },
        tmp_path,
    )
    assert "fixture 'pg_engine' not found" not in out, out
    assert "no tests ran" not in out, out
    assert rc != 0, out
    assert not re.search(r"\d+ skipped", out), out
    assert "A DB-backed test is never skipped" in out, out


def test_no_url_and_no_docker_fails_the_run(tmp_path: Path) -> None:
    """END TO END: nothing to connect to and no docker to start one => RED."""
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()
    rc, out = _child_pytest({"PATH": str(empty_bin)}, tmp_path)
    assert rc != 0, out
    assert "no `docker` on PATH" in out, out
    assert not re.search(r"\d+ (passed|skipped)", out), out
