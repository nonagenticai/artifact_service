"""
Shared test fixtures and configuration for all tests.

This module provides common fixtures used across different test modules:
- RSA key pair generation
- JWT token generation for multiple test users
- Environment setup/cleanup
- Real database session fixtures. The database is TEST_DATABASE_URL, else
  DATABASE_URL (what CI exports), else an ephemeral docker ``postgres:18``
  started for this session and removed at teardown. No docker => the run FAILS.
- FastAPI test client setup
"""

import atexit
import os
import shutil
import subprocess
import time

# Set required env vars BEFORE any app imports (for unit tests that import main.app)
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")
# Tests run as `development` so the production validator (which requires
# real service URLs from gitops env) does not trip on the test fixture set.
os.environ.setdefault("ENVIRONMENT", "development")
# ClamAV is not reachable from CI / local laptops; the unit tests that
# exercise infected-file paths mock the scanner explicitly. Default off here
# so unrelated upload tests don't try to dial a non-existent socket via the
# cached Settings instance (settings is lru_cached, so the override at the
# top of tests/unit/test_artifact_routes.py used to be too late once another
# test file imported `main` first).
os.environ.setdefault("ENABLE_VIRUS_SCANNING", "false")

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ============================================================================
# TENANT IDS — two fixed uuids, shared by every test module
# ============================================================================
#
# A tenant id is a uuid (``src/auth/tenant_id.py``), and since alembic revision
# ``20260826_0003`` ``artifacts.tenant_id`` / ``artifact_reviews.reviewer_tenant_id``
# are native ``uuid`` columns. The old fixture literals — ``"test-tenant"``,
# ``"tenant-1"``, ``"tenant-alpha"``, ``"n8n-dev"`` — are exactly the shape the
# boundary now refuses, so they cannot be written to the database and cannot be
# sent as ``X-Tenant-Id`` any more. They ENCODED the defect; keeping them would
# have meant a suite that only passes against the minting behaviour.
#
# TWO of them, not one, and they are DELIBERATELY DISTINCT. Several tests prove
# CROSS-TENANT ISOLATION by writing under one tenant and reading as another
# (``tests/unit/test_artifact_routes.py`` cross-tenant class,
# ``tests/test_visibility.py::test_cross_tenant_isolation``,
# ``tests/unit/test_artifact_reviews.py::test_cross_tenant_review_returns_404``,
# ``tests/unit/test_database.py::test_tenant_id_filtering``,
# ``tests/unit/test_auth_extended.py::test_introspection_cache_isolation``).
# Collapsing A and B into one constant would leave every one of those tests
# GREEN while deleting what they test. Never substitute one for the other.
#
# Both are uuid7-shaped (version nibble 7, RFC 9562 variant) so they sort and
# read like the ids license-authz actually issues. Both are FICTIONAL: neither
# is ``019de842-c92a-7e37-8fdd-eb0d8c5396f9`` (the real ``n8n-dev``) nor
# ``0195f48b-d000-7000-8000-000000000001`` (the real ``platform-cp-1``, which is
# also ``Settings.default_tenant_id``) — a test must not be able to touch a
# production tenant's scope by accident.
TEST_TENANT_A = "0198c2d4-7a10-7c3e-8b91-4f6a2d5e8c07"
TEST_TENANT_B = "0198c2d4-7a10-7f52-b0a4-9e1c33d7b6f1"

assert TEST_TENANT_A != TEST_TENANT_B, "the isolation fixtures must stay two tenants"


# ============================================================================
# CRYPTOGRAPHY FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def rsa_key_pair_session() -> dict[str, str]:
    """
    Generate RSA key pair for entire test session.

    Using session scope for performance - generating keys is expensive.
    Creates a 2048-bit RSA key pair used for JWT signing and verification.

    Returns:
        dict: {"private": str, "public": str} - PEM-encoded keys
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return {"private": private_pem, "public": public_pem}


@pytest.fixture
def rsa_key_pair(rsa_key_pair_session: dict[str, str]) -> dict[str, str]:
    """
    Function-scoped RSA key pair fixture.

    References the session-scoped key pair. Use this in tests that
    don't require key isolation between tests.

    Returns:
        dict: {"private": str, "public": str} - PEM-encoded keys
    """
    return rsa_key_pair_session


# ============================================================================
# JWT TOKEN GENERATION HELPERS
# ============================================================================


def create_jwt_token(
    user_id: str,
    private_key: str,
    expires_delta: timedelta = timedelta(hours=1),
    additional_claims: dict[str, Any] | None = None,
) -> str:
    """
    Helper function to create JWT tokens for testing.

    Args:
        user_id: Subject claim (creator_id)
        private_key: RSA private key for signing
        expires_delta: Time until expiration (default: 1 hour)
        additional_claims: Optional additional claims to include

    Returns:
        str: Encoded JWT token
    """
    payload = {
        "sub": user_id,
        "exp": int((datetime.now(UTC) + expires_delta).timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
        "email": f"{user_id}@example.com",
        "preferred_username": user_id,
    }

    if additional_claims:
        payload.update(additional_claims)

    return jwt.encode(payload, private_key, algorithm="RS256")


# ============================================================================
# TEST USER FIXTURES
# ============================================================================


@pytest.fixture
def user_a_token(rsa_key_pair: dict[str, str]) -> str:
    """Generate valid JWT token for test user A."""
    return create_jwt_token("user_a_id", rsa_key_pair["private"])


@pytest.fixture
def user_b_token(rsa_key_pair: dict[str, str]) -> str:
    """Generate valid JWT token for test user B."""
    return create_jwt_token("user_b_id", rsa_key_pair["private"])


@pytest.fixture
def admin_token(rsa_key_pair: dict[str, str]) -> str:
    """Generate valid JWT token for admin user with additional claims."""
    return create_jwt_token(
        "admin_user_id",
        rsa_key_pair["private"],
        additional_claims={"roles": ["admin", "user"], "permissions": ["read", "write", "delete"]},
    )


@pytest.fixture
def expired_token(rsa_key_pair: dict[str, str]) -> str:
    """Generate expired JWT token for testing expiration handling."""
    return create_jwt_token(
        "expired_user",
        rsa_key_pair["private"],
        expires_delta=timedelta(hours=-1),  # Expired 1 hour ago
    )


# ============================================================================
# ENVIRONMENT SETUP FIXTURES
# ============================================================================


@pytest.fixture
def clean_jwt_env() -> Generator[None]:
    """
    Clean JWT-related environment variables before and after tests.

    Ensures tests start with a clean environment and don't interfere
    with each other through shared environment state.
    """
    jwt_env_vars = [
        "JWT_PUBLIC_KEY",
        "JWT_PUBLIC_KEY_PATH",
        "JWT_ALGORITHM",
        "JWT_AUDIENCE",
        "JWT_ISSUER",
    ]

    # Store original values
    original_values = {key: os.environ.get(key) for key in jwt_env_vars}

    # Clear all JWT env vars
    for key in jwt_env_vars:
        os.environ.pop(key, None)

    yield

    # Restore original values
    for key, value in original_values.items():
        if value is not None:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)


@pytest.fixture
def setup_jwt_env(rsa_key_pair: dict[str, str], clean_jwt_env: None) -> Generator[dict[str, str]]:
    """
    Setup JWT environment with test configuration.

    Configures environment variables needed for JWT authentication
    using the test RSA key pair.

    Yields:
        dict: RSA key pair for use in tests
    """
    os.environ["JWT_PUBLIC_KEY"] = rsa_key_pair["public"]
    os.environ["JWT_ALGORITHM"] = "RS256"

    yield rsa_key_pair


# ============================================================================
# AUTH_TENANT_FALLBACK_MODE
# ============================================================================


@pytest.fixture
def tenant_fallback_mode(monkeypatch: pytest.MonkeyPatch):
    """Set ``AUTH_TENANT_FALLBACK_MODE`` on the live Settings for ONE test.

    The default is ``enforce`` (a header-less token-less request is 401
    ``TENANT_REQUIRED``). Only a test that is explicitly ABOUT the old
    absent-header fallback should call ``tenant_fallback_mode("observe")``;
    every other test sends ``X-Tenant-Id``. ``AuthMiddleware`` reads the mode
    from ``get_settings()`` per request, so patching the cached instance is
    enough and ``monkeypatch`` restores it afterwards.
    """
    from core.config import get_settings

    def _set(mode: str) -> None:
        monkeypatch.setattr(get_settings(), "auth_tenant_fallback_mode", mode)

    return _set


@pytest.fixture
def tenant_proof_mode(monkeypatch: pytest.MonkeyPatch):
    """Set ``AUTH_TENANT_PROOF_MODE`` on the live Settings for ONE test.

    Sibling of ``tenant_fallback_mode``; the default is ``observe``.
    """
    from core.config import get_settings

    def _set(mode: str) -> None:
        monkeypatch.setattr(get_settings(), "auth_tenant_proof_mode", mode)

    return _set


# ============================================================================
# AUTH HEADERS FIXTURES
# ============================================================================


@pytest.fixture
def auth_headers_user_a(user_a_token: str) -> dict[str, str]:
    """Authorization headers for user A."""
    return {"Authorization": f"Bearer {user_a_token}"}


@pytest.fixture
def auth_headers_admin(admin_token: str) -> dict[str, str]:
    """Authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================


def pytest_configure(config: pytest.Config) -> None:
    """
    Configure pytest with custom markers and settings.

    Registers custom markers for categorizing tests:
    - unit: Unit tests
    - integration: Integration tests
    - security: Security-focused tests
    - slow: Tests that take longer to run
    """
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "security: Security-focused tests")
    config.addinivalue_line("markers", "slow: Tests that take longer to run")
    config.addinivalue_line(
        "markers",
        "needs_pdf_backend: needs WeasyPrint's system libraries (pango); always runs in CI",
    )


def _pdf_backend_loads() -> bool:
    """True when WeasyPrint can load pango/gobject on this machine."""
    try:
        import weasyprint  # noqa: F401
    except OSError:
        return False
    return True


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Count how many collected tests want a live database.

    :func:`pytest_sessionfinish` compares that against how many actually got one.
    """
    global _DB_BACKED_COLLECTED
    _DB_BACKED_COLLECTED = sum(
        1 for item in items if _DB_FIXTURES.intersection(getattr(item, "fixturenames", ()))
    )

    # A laptop without pango skips the PDF tests; CI installs it (ci-cd.yaml extra_apt),
    # so there they always run and a missing library is a failure, never a skip.
    if not os.getenv("CI") and not _pdf_backend_loads():
        skip_pdf = pytest.mark.skip(
            reason="WeasyPrint system libraries (pango) not loadable locally"
        )
        for item in items:
            if item.get_closest_marker("needs_pdf_backend"):
                item.add_marker(skip_pdf)


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the ephemeral postgres container this session started, if any."""
    _remove_ephemeral_postgres()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """⛔ A session that collected DB-backed tests and ran NONE is a FAILURE.

    ``pg_engine`` fails on a connection error; this catches the other way a
    DB suite goes vacuous — the tests are never reached at all (a blanket skip,
    a ``-m`` that deselects them, a fixture that skips before it dials). Counted,
    not pinned to a number, so adding or removing tests never reds the build.
    """
    if _DB_BACKED_COLLECTED == 0 or _DB_BACKED_RAN > 0:
        return
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    message = (
        f"NON-VACUITY GUARD FAILED: {_DB_BACKED_COLLECTED} collected tests require a "
        f"live PostgreSQL and NONE of them reached one "
        f"(resolved DSN {_redact(TEST_DATABASE_URL)}). "
        "A DB-backed suite that reports green without connecting proves nothing. "
        "In CI set has_postgres: true so the archetype exports DATABASE_URL."
    )
    if reporter is not None:
        reporter.write_sep("=", "non-vacuity guard", red=True)
        reporter.write_line(message)
    else:  # pragma: no cover - terminalreporter is always present under pytest
        print(message)  # noqa: T201


# ============================================================================
# POSTGRESQL DATABASE FIXTURES
# ============================================================================
#
# Resolution (fleet standard, George 2026-10-21):
#   1. TEST_DATABASE_URL, if set — a developer pointing the suite somewhere;
#   2. DATABASE_URL, if set — what the CI archetype exports for its sidecar;
#   3. otherwise an ephemeral ``postgres:18`` container on a random loopback
#      port (tmpfs data dir), removed by id at session teardown;
#   4. no docker => the run FAILS. A DB-backed test is never skipped.


def _normalise_driver(url: str) -> str:
    """Force the psycopg3 async driver onto whatever scheme the env supplied.

    A bare ``postgresql://`` resolves to psycopg2 (not installed) and
    ``+asyncpg`` is not on this fleet, so ``create_async_engine`` would raise.
    """
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg2://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    return url


def _redact(url: str) -> str:
    """``scheme://user:***@host:port/db`` — the DSN is printed into CI logs."""
    scheme, _, rest = url.partition("://")
    creds, at, hostpart = rest.rpartition("@")
    if not at:
        return url
    user, _, _password = creds.partition(":")
    return f"{scheme}://{user}:***@{hostpart}"


def _resolve_test_database_url() -> str | None:
    """TEST_DATABASE_URL, else DATABASE_URL, else None (=> start a container)."""
    for name in ("TEST_DATABASE_URL", "DATABASE_URL"):
        value = os.getenv(name)
        if value:
            return _normalise_driver(value)
    return None


_PG_IMAGE = "postgres:18"
_PG_DB = "artifact_test"
_PG_PASSWORD = "artifact-test"  # pragma: allowlist secret
_PG_READY_TIMEOUT_S = 90
#: Name of the container THIS session started. A unique name chosen before
#: ``docker run`` means a run that times out (a busy daemon) can still be removed.
_ephemeral_container: str | None = None


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def _remove_ephemeral_postgres() -> None:
    """Remove ONLY the container this session started. Idempotent."""
    global _ephemeral_container
    name, _ephemeral_container = _ephemeral_container, None
    if name:
        _docker("rm", "-f", "-v", name, timeout=300)


def _start_ephemeral_postgres() -> str:
    """Start ``postgres:18`` on a random 127.0.0.1 port; return its async DSN."""
    global _ephemeral_container
    if shutil.which("docker") is None:
        raise RuntimeError(
            "No TEST_DATABASE_URL/DATABASE_URL and no `docker` on PATH: the DB-backed "
            "tests cannot get a PostgreSQL, and they are never skipped. Start docker "
            "or export TEST_DATABASE_URL."
        )
    _ephemeral_container = f"artifact-service-test-{os.getpid()}-{os.urandom(4).hex()}"
    atexit.register(_remove_ephemeral_postgres)
    try:
        run = _docker(
            "run", "--rm", "-d", "--name", _ephemeral_container,
            "--tmpfs", "/var/lib/postgresql",
            "-p", "127.0.0.1::5432",
            "-e", f"POSTGRES_PASSWORD={_PG_PASSWORD}",
            "-e", f"POSTGRES_DB={_PG_DB}",
            _PG_IMAGE,
            timeout=300,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        _remove_ephemeral_postgres()
        raise RuntimeError(f"docker run {_PG_IMAGE} timed out (is the docker daemon busy?)")
    if run.returncode != 0:
        _remove_ephemeral_postgres()
        raise RuntimeError(f"docker run {_PG_IMAGE} failed: {run.stderr.strip()}")

    port = _docker("port", _ephemeral_container, "5432/tcp").stdout.splitlines()[0]
    port = port.rsplit(":", 1)[1]
    # TCP, not the socket: the entrypoint's init server listens on the socket only,
    # so a socket probe answers "ready" before the real server is up.
    deadline = time.monotonic() + _PG_READY_TIMEOUT_S
    while True:
        probe = _docker(
            "exec", _ephemeral_container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"
        )
        if probe.returncode == 0:
            break
        if time.monotonic() > deadline:
            _remove_ephemeral_postgres()
            raise RuntimeError(f"ephemeral {_PG_IMAGE} not ready in {_PG_READY_TIMEOUT_S}s")
        time.sleep(0.5)
    return f"postgresql+psycopg://postgres:{_PG_PASSWORD}@127.0.0.1:{port}/{_PG_DB}"


TEST_DATABASE_URL = _resolve_test_database_url() or _start_ephemeral_postgres()
# Export it so subprocesses (alembic, child pytest runs) and the second
# ``tests.conftest`` module object resolve the SAME database instead of
# starting another container.
os.environ["TEST_DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)

# The DB-backed tests create and drop schema objects on TEST_DATABASE_URL. Refuse
# outright if it names a production host (tests/integration/target_guard.py),
# whatever the environment exported — ALLOW_PROD_INTEGRATION=1 is the only way past.
from tests.integration.target_guard import assert_not_prod  # noqa: E402

assert_not_prod("TEST_DATABASE_URL/DATABASE_URL", TEST_DATABASE_URL)

#: How many collected tests want a real database, and how many of them got one.
#: Compared in :func:`pytest_sessionfinish` — see the guard there.
_DB_BACKED_COLLECTED = 0
_DB_BACKED_RAN = 0

#: Names that mean "this test needs a live postgres". ``vis_client`` is
#: ``tests/test_visibility.py``'s own engine-building fixture.
_DB_FIXTURES = frozenset(
    {"pg_engine", "test_engine", "db_session", "real_app_client", "vis_client"}
)


def database_unreachable(exc: object) -> None:
    """⛔ The one place that handles an unreachable database: always a FAILURE.

    Public because ``tests/test_visibility.py`` builds its own engine. Never returns.
    """
    pytest.fail(
        f"PostgreSQL not available at {_redact(TEST_DATABASE_URL)}: {exc}\n"
        "A DB-backed test is never skipped. Resolution order is TEST_DATABASE_URL "
        "-> DATABASE_URL -> ephemeral docker postgres:18.",
        pytrace=False,
    )


def note_database_reached() -> None:
    """Record that a test actually opened a connection. See ``pytest_sessionfinish``.

    ⛔ IMPORT THIS AS ``import conftest``, NEVER ``from tests.conftest import …``.
    Measured: pytest loads the root conftest under the module name ``conftest``,
    while ``tests.conftest`` resolves to a SECOND, separate module object with
    its own copy of every global — ``conftest is tests.conftest`` -> ``False``.
    A counter incremented through the wrong one is invisible to the hook that
    reads it, and the guard would pass while proving nothing.
    """
    global _DB_BACKED_RAN
    _DB_BACKED_RAN += 1


@pytest_asyncio.fixture(scope="function")
async def pg_engine():
    """Create a PostgreSQL engine for unit tests."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from core.database import Base

    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        await engine.dispose()
        # Failing here (rather than only in sessionfinish) names the test and the
        # resolved DSN at the point of the fault.
        database_unreachable(e)

    note_database_reached()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
def test_engine(pg_engine):
    """Alias for pg_engine, used by test_database.py."""
    return pg_engine


@pytest.fixture
async def db_session(pg_engine):
    """Provide an async DB session backed by PostgreSQL.

    Truncates all tables after each test for isolation.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from core.database import Base

    factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as session:
        yield session

    async with pg_engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())


@pytest.fixture
def real_app_client(db_session):
    """FastAPI TestClient with real DB and mocked storage.

    Yields (client, mock_storage) tuple. The client uses a real database
    session for all requests, but storage operations are mocked since
    we're testing DB/API logic, not file storage.
    """
    import secrets

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.base import BaseHTTPMiddleware

    from core.database import get_db
    from routes.artifacts import cross_project_router, get_storage_service, router
    from routes.health import router as health_router

    app = FastAPI()
    app.include_router(router)
    app.include_router(cross_project_router)
    app.include_router(health_router)

    async def override_get_db():
        yield db_session

    mock_storage = MagicMock()
    # Return unique storage keys to avoid UNIQUE constraint violations
    mock_storage.generate_storage_key.side_effect = lambda **kw: (
        f"test/storage/{secrets.token_hex(8)}/v1/{kw.get('filename', 'file.txt')}"
    )
    mock_storage.upload_file.return_value = None
    mock_storage.download_file.return_value = b"test file content"
    mock_storage.delete_file.return_value = None

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_service] = lambda: mock_storage

    class FakeTenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            # Default tenant; tests can override via X-Test-Tenant header
            tenant = request.headers.get("X-Test-Tenant", TEST_TENANT_A)
            request.state.tenant_id = tenant
            request.state.user = {"user_id": tenant, "tenant_id": tenant}
            # subject_id from X-Subject-Id (empty string = tenant-only caller)
            request.state.subject_id = request.headers.get("X-Subject-Id", "")
            # tenant_name from X-Tenant-Name (empty = listener will backfill tenant_id)
            request.state.tenant_name = request.headers.get("X-Tenant-Name", "")
            return await call_next(request)

    app.add_middleware(FakeTenantMiddleware)

    with TestClient(app) as c:
        yield c, mock_storage


# ============================================================================
# HELPER: Create real Artifact in the database
# ============================================================================


async def create_test_artifact(
    db_session,
    *,
    tenant_id: str = TEST_TENANT_A,
    project_id: UUID = UUID("11111111-1111-1111-1111-111111111111"),
    filename: str = "test.txt",
    content_type: str = "text/plain",
    kind: str = "doc",
    sensitivity: str = "internal",
    size: int = 100,
    sha256: str = "abc123def456",
    storage_key: str | None = None,
    card_id: UUID | None = None,
    step: str | None = None,
    container_name: str | None = None,
    tags: list[str] | None = None,
):
    """Insert a real Artifact row into the test database. Returns the Artifact."""
    import secrets

    from models.artifact import Artifact, ArtifactTag

    artifact_id = UUID(int=secrets.randbits(128))
    if storage_key is None:
        storage_key = f"projects/{project_id}/test/{artifact_id}/v1/{filename}"

    artifact = Artifact(
        id=artifact_id,
        tenant_id=tenant_id,
        project_id=project_id,
        card_id=card_id,
        step=step,
        container_name=container_name,
        version=1,
        filename=filename,
        content_type=content_type,
        kind=kind,
        sensitivity=sensitivity,
        size=size,
        sha256=sha256,
        storage_key=storage_key,
        created_by=tenant_id,
    )

    db_session.add(artifact)

    if tags:
        for tag_name in tags:
            db_session.add(ArtifactTag(artifact_id=artifact.id, tag=tag_name))

    await db_session.commit()
    await db_session.refresh(artifact)
    return artifact
