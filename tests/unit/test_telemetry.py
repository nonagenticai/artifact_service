"""Tests for telemetry module.

Tests the OTEL initialization with proper mocking of external dependencies.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

import telemetry


@pytest.fixture(autouse=True)
def reset_telemetry():
    """Reset telemetry state between tests."""
    original = telemetry._initialized
    telemetry._initialized = False
    yield
    telemetry._initialized = original


class TestTestConnection:
    """Test OTLP endpoint connection testing."""

    def test_reachable_endpoint(self):
        with patch("telemetry.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            result = telemetry._test_connection("localhost", 4318)
            assert result is True
            mock_conn.assert_called_once_with(("localhost", 4318), timeout=2.0)
            mock_sock.close.assert_called_once()

    def test_unreachable_endpoint(self):
        with patch("telemetry.socket.create_connection", side_effect=ConnectionRefusedError):
            assert telemetry._test_connection("badhost", 4318) is False

    def test_timeout_endpoint(self):
        import socket

        with patch("telemetry.socket.create_connection", side_effect=socket.timeout):
            assert telemetry._test_connection("slowhost", 4318) is False

    def test_os_error(self):
        with patch("telemetry.socket.create_connection", side_effect=OSError("Network err")):
            assert telemetry._test_connection("host", 4318) is False

    def test_custom_timeout(self):
        with patch("telemetry.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            telemetry._test_connection("host", 4318, timeout=5.0)
            mock_conn.assert_called_once_with(("host", 4318), timeout=5.0)
            mock_sock.close.assert_called_once()


class TestSetupTelemetry:
    """Test telemetry initialization logic."""

    def test_already_initialized_returns_true(self):
        telemetry._initialized = True
        result = telemetry.setup_telemetry(MagicMock(), "test-service")
        assert result is True

    def test_disabled_via_env(self):
        with patch.dict(os.environ, {"OTEL_SDK_DISABLED": "true"}):
            result = telemetry.setup_telemetry(MagicMock(), "test-service")
            assert result is False
            assert telemetry._initialized is False

    def test_missing_otel_packages(self):
        """When opentelemetry is not installed, setup returns False gracefully."""
        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if "opentelemetry" in name:
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = telemetry.setup_telemetry(MagicMock(), "test-service")
            assert result is False

    def test_full_setup_with_reachable_endpoint(self):
        """When OTEL packages are available and endpoint is reachable, setup succeeds."""
        mock_app = MagicMock()

        with (
            patch.dict(
                os.environ,
                {
                    "OTEL_SDK_DISABLED": "false",
                    "OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                },
            ),
            patch("telemetry._test_connection", return_value=True),
            patch("telemetry.socket"),
        ):
            # We need to let the real imports work since OTEL is installed
            result = telemetry.setup_telemetry(mock_app, "test-service")
            assert result is True
            assert telemetry._initialized is True

    def test_setup_with_unreachable_endpoint(self):
        """When OTEL endpoint is unreachable, setup still succeeds but without exporter."""
        mock_app = MagicMock()

        with (
            patch.dict(
                os.environ,
                {
                    "OTEL_SDK_DISABLED": "false",
                    "OTLP_TRACES_ENDPOINT": "http://unreachable:4318/v1/traces",
                },
            ),
            patch("telemetry._test_connection", return_value=False),
        ):
            result = telemetry.setup_telemetry(mock_app, "test-service")
            assert result is True
            assert telemetry._initialized is True

    def test_setup_marks_initialized_on_success(self):
        """After successful setup, _initialized flag prevents re-initialization."""
        mock_app = MagicMock()

        with (
            patch.dict(
                os.environ,
                {
                    "OTEL_SDK_DISABLED": "false",
                    "OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                },
            ),
            patch("telemetry._test_connection", return_value=False),
        ):
            result1 = telemetry.setup_telemetry(mock_app, "test-service")
            assert result1 is True
            assert telemetry._initialized is True

            # Second call should short-circuit
            result2 = telemetry.setup_telemetry(mock_app, "test-service")
            assert result2 is True

    def test_setup_skipped_when_endpoint_missing(self):
        """When OTLP_TRACES_ENDPOINT is unset, setup is a no-op (returns False)."""
        mock_app = MagicMock()
        # Ensure the env var is absent for this test
        env = {k: v for k, v in os.environ.items() if k != "OTLP_TRACES_ENDPOINT"}
        with patch.dict(os.environ, env, clear=True):
            os.environ["OTEL_SDK_DISABLED"] = "false"
            result = telemetry.setup_telemetry(mock_app, "test-service")
            assert result is False
            assert telemetry._initialized is False

    def test_instrumentation_failure_is_not_fatal(self):
        """If FastAPI/HTTPX/SQLAlchemy instrumentation fails, setup still succeeds."""
        mock_app = MagicMock()

        with (
            patch.dict(
                os.environ,
                {
                    "OTEL_SDK_DISABLED": "false",
                    "OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
                },
            ),
            patch("telemetry._test_connection", return_value=False),
        ):
            # Let real OTEL imports work, but instrument_app will get a MagicMock app
            # which may cause issues internally — the point is it shouldn't crash
            result = telemetry.setup_telemetry(mock_app, "test-service")
            assert result is True
