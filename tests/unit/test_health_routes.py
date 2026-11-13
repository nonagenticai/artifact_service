"""Tests for health check routes.

Tests use real PostgreSQL DB for readiness/liveness probes and targeted mocks
only for external services (StorageService, VirusScanner) that we can't
instantiate without live infrastructure.
"""

import asyncio
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from routes.health import HealthResponse
from routes.health import router as health_router

# ---------------------------------------------------------------------------
# HealthResponse model tests
# ---------------------------------------------------------------------------


class TestHealthResponse:
    """Test HealthResponse Pydantic model."""

    def test_model_creation(self):
        resp = HealthResponse(
            status="healthy",
            service="artifact-service",
            version="0.1.0",
            timestamp=datetime.now(UTC),
            checks={"database": True, "storage": True},
        )
        assert resp.status == "healthy"
        assert resp.checks["database"] is True

    def test_model_serialization_roundtrip(self):
        now = datetime.now(UTC)
        resp = HealthResponse(
            status="unhealthy",
            service="test-svc",
            version="1.2.3",
            timestamp=now,
            checks={"database": False, "storage": True, "virus_scanner": False},
        )
        data = resp.model_dump()
        assert data["status"] == "unhealthy"
        assert data["checks"]["database"] is False
        assert data["checks"]["virus_scanner"] is False
        # JSON round-trip
        json_str = resp.model_dump_json()
        assert "unhealthy" in json_str
        assert "test-svc" in json_str


# ---------------------------------------------------------------------------
# Fixture: app backed by real PostgreSQL DB + mocked external services
# ---------------------------------------------------------------------------


@pytest.fixture
def health_client(pg_engine):
    """FastAPI TestClient with real PostgreSQL DB and mocked storage/scanner.

    Yields (client, mock_db_session_factory) so tests can manipulate DB state.
    """
    from core.database import get_db

    app = FastAPI()
    app.include_router(health_router)

    session_factory = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c, session_factory


# ---------------------------------------------------------------------------
# Liveness probe tests
# ---------------------------------------------------------------------------


class TestLivenessProbe:
    """GET /health/live — always returns 200 if the process is up."""

    def test_returns_alive(self, health_client):
        client, _ = health_client
        response = client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert list(data.keys()) == ["status"], "Liveness should only have 'status' key"


# ---------------------------------------------------------------------------
# Readiness probe tests (uses REAL database)
# ---------------------------------------------------------------------------


class TestReadinessProbe:
    """GET /health/ready — verifies database is reachable."""

    def test_ready_with_real_db(self, health_client):
        """Readiness probe hits the real PostgreSQL DB and returns 'ready'."""
        client, _ = health_client
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"

    def test_not_ready_on_db_exception(self, health_client):
        """When DB query raises, readiness probe reports not_ready with error details."""
        client, factory = health_client

        # Override get_db to yield a session whose execute() always fails
        from core.database import get_db

        # Patch the dependency override to inject a broken session
        async def broken_db():
            async with factory() as session:

                async def failing_execute(*a, **kw):
                    raise ConnectionError("Database connection lost")

                session.execute = failing_execute
                yield session

        client.app.dependency_overrides[get_db] = broken_db

        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert "Database connection lost" in data["error"]

    def test_not_ready_on_db_timeout(self, health_client):
        """When DB query times out, readiness probe reports not_ready."""
        client, factory = health_client
        from core.database import get_db

        async def slow_db():
            async with factory() as session:
                original_execute = session.execute

                async def slow_execute(*a, **kw):
                    await asyncio.sleep(10)
                    return await original_execute(*a, **kw)

                session.execute = slow_execute
                yield session

        client.app.dependency_overrides[get_db] = slow_db

        response = client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"


# ---------------------------------------------------------------------------
# Full health check tests
# ---------------------------------------------------------------------------


class TestFullHealthCheck:
    """GET /health — checks DB, storage, and virus scanner in parallel."""

    def test_all_healthy(self, health_client):
        """When all dependencies are up, status is 'healthy'."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        mock_scanner = MagicMock()
        mock_scanner.ping.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.VirusScanner", return_value=mock_scanner),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = True
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["service"] == "artifact-service"
            assert data["checks"]["database"] is True
            assert data["checks"]["storage"] is True
            assert data["checks"]["virus_scanner"] is True
            # Verify timestamp is a valid ISO datetime
            assert "timestamp" in data
            datetime.fromisoformat(data["timestamp"])

    def test_storage_down_reports_unhealthy(self, health_client):
        """When storage fails health check, status is 'unhealthy'."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = False

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["database"] is True  # DB is real and healthy
            assert data["checks"]["storage"] is False

    def test_storage_constructor_exception(self, health_client):
        """When StorageService() itself raises, storage reports False."""
        client, _ = health_client

        with (
            patch("routes.health.StorageService", side_effect=RuntimeError("Connection refused")),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["storage"] is False

    def test_db_failure_reports_unhealthy(self, health_client):
        """When DB fails, health check still returns 200 but status is unhealthy."""
        import sqlalchemy.exc

        client, factory = health_client
        from core.database import get_db

        async def broken_db():
            async with factory() as session:

                async def failing_execute(*a, **kw):
                    raise sqlalchemy.exc.OperationalError("SELECT 1", {}, Exception("DB is down"))

                session.execute = failing_execute
                yield session

        client.app.dependency_overrides[get_db] = broken_db

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["database"] is False

    def test_virus_scanner_disabled_reports_true(self, health_client):
        """When virus scanning is disabled, virus_scanner reports True (N/A)."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["checks"]["virus_scanner"] is True

    def test_virus_scanner_ping_failed(self, health_client):
        """When ClamAV ping fails, virus_scanner reports False."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        mock_scanner = MagicMock()
        mock_scanner.ping.return_value = False

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.VirusScanner", return_value=mock_scanner),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = True
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["checks"]["virus_scanner"] is False
            assert data["status"] == "unhealthy"

    def test_virus_scanner_exception(self, health_client):
        """When VirusScanner() raises, virus_scanner reports False."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.VirusScanner", side_effect=RuntimeError("ClamAV unreachable")),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = True
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["checks"]["virus_scanner"] is False
            assert data["status"] == "unhealthy"

    def test_storage_health_check_timeout(self, health_client):
        """When storage health check takes too long, storage reports False."""
        import time

        client, _ = health_client

        mock_storage = MagicMock()
        # 0.2s is enough to exceed 0.05s individual timeout but short enough
        # to not outlive test cleanup (avoids OperationalError on disposed pool)
        mock_storage.health_check.side_effect = lambda: time.sleep(0.2)

        original_wait_for = asyncio.wait_for

        async def fast_timeout_wait_for(coro, *, timeout):
            """Differentiate individual vs overall timeouts."""
            if timeout == 5.0:
                timeout = 0.05  # individual check — fires before 0.2s sleep
            elif timeout == 10.0:
                timeout = 2.0  # overall — give room so only storage triggers
            return await original_wait_for(coro, timeout=timeout)

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.asyncio.wait_for", side_effect=fast_timeout_wait_for),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["checks"]["storage"] is False
            assert data["status"] == "unhealthy"

    def test_overall_health_check_timeout(self, health_client):
        """When the overall 10s timeout fires, all checks report False."""
        client, factory = health_client
        import time

        from core.database import get_db

        # Make ALL checks slow — 0.5s is long enough to exceed 0.05s overall
        # but short enough to not outlive test cleanup
        async def slow_db():
            async with factory() as session:

                async def slow_execute(*a, **kw):
                    await asyncio.sleep(0.5)

                session.execute = slow_execute
                yield session

        client.app.dependency_overrides[get_db] = slow_db

        mock_storage = MagicMock()
        mock_storage.health_check.side_effect = lambda: time.sleep(0.5)

        mock_scanner = MagicMock()
        mock_scanner.ping.side_effect = lambda: time.sleep(0.5)

        original_wait_for = asyncio.wait_for

        async def fast_timeout_wait_for(coro, *, timeout):
            if timeout == 10.0:
                timeout = 0.05  # overall fires first before any 0.5s sleeps
            elif timeout == 5.0:
                timeout = 5.0  # individual timeouts stay, overall fires first
            return await original_wait_for(coro, timeout=timeout)

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.VirusScanner", return_value=mock_scanner),
            patch("routes.health.asyncio.wait_for", side_effect=fast_timeout_wait_for),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = True
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["database"] is False
            assert data["checks"]["storage"] is False
            assert data["checks"]["virus_scanner"] is False

    def test_health_response_has_all_fields(self, health_client):
        """Successful health check response contains all expected fields."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = False
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()

            # Top-level keys
            assert set(data.keys()) == {"status", "service", "version", "timestamp", "checks"}

            # Checks sub-keys
            assert set(data["checks"].keys()) == {"database", "storage", "virus_scanner"}

            # Timestamp is valid ISO 8601
            parsed = datetime.fromisoformat(data["timestamp"])
            assert parsed.tzinfo is not None or "Z" in data["timestamp"]

    def test_health_check_scanner_down_db_and_storage_up(self, health_client):
        """When scanner is down but DB and storage are up, status is unhealthy."""
        client, _ = health_client

        mock_storage = MagicMock()
        mock_storage.health_check.return_value = True

        mock_scanner = MagicMock()
        mock_scanner.ping.return_value = False

        with (
            patch("routes.health.StorageService", return_value=mock_storage),
            patch("routes.health.VirusScanner", return_value=mock_scanner),
            patch("routes.health.settings") as mock_settings,
        ):
            mock_settings.enable_virus_scanning = True
            mock_settings.service_name = "artifact-service"

            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["checks"]["database"] is True
            assert data["checks"]["storage"] is True
            assert data["checks"]["virus_scanner"] is False


# ---------------------------------------------------------------------------
# Main app endpoint tests (uses the real main.app)
# ---------------------------------------------------------------------------


class TestMainAppEndpoints:
    """Test endpoints through the main app (with auth disabled)."""

    @pytest.fixture
    def main_client(self):
        os.environ["ENABLE_AUTH"] = "false"
        from main import app

        return TestClient(app)

    def test_root(self, main_client):
        response = main_client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "artifact-service"
        assert data["version"] == "1.0.0"
        assert data["status"] == "running"
        assert data["environment"] in ("development", "staging", "production")

    def test_liveness(self, main_client):
        response = main_client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data == {"status": "alive"}
