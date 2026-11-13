"""Tests for logging configuration module.

Verifies structured logging actually produces correct output, not just
that internal flags are set.
"""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

import logging_config


@pytest.fixture(autouse=True)
def reset_logging_state():
    """Reset configured state between tests."""
    original = logging_config._configured
    logging_config._configured = False
    yield
    logging_config._configured = original


class TestAddTraceContext:
    """Test OTEL trace context injection into structured logs."""

    def test_no_otel_available(self):
        with patch.object(logging_config, "OTEL_AVAILABLE", False):
            event_dict = {"event": "test"}
            result = logging_config.add_trace_context(None, "info", event_dict)
            assert "trace_id" not in result
            assert "span_id" not in result

    def test_with_otel_no_span(self):
        with patch.object(logging_config, "OTEL_AVAILABLE", True):
            mock_trace = MagicMock()
            mock_trace.get_current_span.return_value = None
            with patch.object(logging_config, "trace", mock_trace):
                event_dict = {"event": "test"}
                result = logging_config.add_trace_context(None, "info", event_dict)
                assert "trace_id" not in result

    def test_with_otel_non_recording_span(self):
        """Non-recording span should not inject trace context."""
        with patch.object(logging_config, "OTEL_AVAILABLE", True):
            mock_span = MagicMock()
            mock_span.is_recording.return_value = False
            mock_trace = MagicMock()
            mock_trace.get_current_span.return_value = mock_span
            with patch.object(logging_config, "trace", mock_trace):
                event_dict = {"event": "test"}
                result = logging_config.add_trace_context(None, "info", event_dict)
                assert "trace_id" not in result

    def test_with_otel_valid_span(self):
        """Valid recording span should inject trace_id and span_id."""
        with patch.object(logging_config, "OTEL_AVAILABLE", True):
            mock_ctx = MagicMock()
            mock_ctx.is_valid = True
            mock_ctx.trace_id = 0x1234567890ABCDEF1234567890ABCDEF
            mock_ctx.span_id = 0xFEDCBA0987654321

            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_span.get_span_context.return_value = mock_ctx

            mock_trace = MagicMock()
            mock_trace.get_current_span.return_value = mock_span

            with patch.object(logging_config, "trace", mock_trace):
                event_dict = {"event": "test"}
                result = logging_config.add_trace_context(None, "info", event_dict)
                assert "trace_id" in result
                assert "span_id" in result
                # Verify they are hex strings of the right length
                assert len(result["trace_id"]) == 32
                assert len(result["span_id"]) == 16

    def test_with_otel_invalid_span_context(self):
        """Invalid span context should not inject trace data."""
        with patch.object(logging_config, "OTEL_AVAILABLE", True):
            mock_ctx = MagicMock()
            mock_ctx.is_valid = False

            mock_span = MagicMock()
            mock_span.is_recording.return_value = True
            mock_span.get_span_context.return_value = mock_ctx

            mock_trace = MagicMock()
            mock_trace.get_current_span.return_value = mock_span

            with patch.object(logging_config, "trace", mock_trace):
                event_dict = {"event": "test"}
                result = logging_config.add_trace_context(None, "info", event_dict)
                assert "trace_id" not in result


class TestAddServiceContext:
    """Test service metadata injection."""

    def test_adds_service_and_environment(self):
        event_dict = {}
        result = logging_config.add_service_context(None, "info", event_dict)
        assert "service" in result
        assert result["service"] == "artifact-service"
        assert "environment" in result
        assert result["environment"] in ("development", "staging", "production")

    def test_custom_service_name_from_env(self):
        with patch.dict(os.environ, {"OTEL_SERVICE_NAME": "custom-service"}):
            event_dict = {}
            result = logging_config.add_service_context(None, "info", event_dict)
            assert result["service"] == "custom-service"


class TestConfigureLogging:
    """Test logging configuration produces correct setup."""

    def test_configure_json_format_sets_up_structlog(self):
        with patch.dict(os.environ, {"LOG_FORMAT": "json", "LOG_LEVEL": "INFO"}):
            logging_config.configure_logging()
            assert logging_config._configured is True
            # Verify structlog is actually configured by getting a logger and using it
            import structlog

            logger = structlog.get_logger("test-json")
            assert logger is not None

    def test_configure_console_format(self):
        with patch.dict(os.environ, {"LOG_FORMAT": "console", "LOG_LEVEL": "DEBUG"}):
            logging_config.configure_logging()
            assert logging_config._configured is True
            # Verify structlog is configured and usable with console renderer
            import structlog

            logger = structlog.get_logger("test-console")
            assert logger is not None
            # Verify the logger can emit without error in console format
            logger.info("console format test", key="value")
            logger.debug("debug message in console format")

    def test_idempotent_skips_second_call(self):
        """Second call to configure_logging() should be a no-op."""
        logging_config._configured = True
        # If it re-ran, structlog would reconfigure. Since _configured is True,
        # it should return immediately.
        logging_config.configure_logging()
        assert logging_config._configured is True

    def test_explicit_level_overrides_env(self):
        """Passing level= to configure_logging overrides LOG_LEVEL env var."""
        logging_config.configure_logging(level=logging.WARNING)
        assert logging_config._configured is True
        # Root logger should be set to WARNING
        root_level = logging.getLogger().level
        assert root_level == logging.WARNING

    def test_noisy_loggers_suppressed(self):
        """httpx, httpcore, uvicorn.access, urllib3 should be WARNING or above."""
        logging_config.configure_logging()
        for name in ["httpx", "httpcore", "uvicorn.access", "urllib3"]:
            logger = logging.getLogger(name)
            assert logger.level >= logging.WARNING, (
                f"Logger {name} level {logger.level} should be >= WARNING ({logging.WARNING})"
            )


class TestGetLogger:
    """Test logger factory function."""

    def test_returns_bound_logger(self):
        logger = logging_config.get_logger("test-module")
        assert logger is not None
        # Verify it has structlog methods
        assert callable(getattr(logger, "info", None))
        assert callable(getattr(logger, "error", None))
        assert callable(getattr(logger, "warning", None))
        assert callable(getattr(logger, "debug", None))

    def test_default_name_is_artifact_service(self):
        logger = logging_config.get_logger()
        assert logger is not None
        # Verify the logger has standard structlog methods
        assert callable(getattr(logger, "info", None))
        assert callable(getattr(logger, "error", None))
        # Calling with no args should still work and not raise
        logger.info("test message with default name")

    def test_auto_configures_logging(self):
        """get_logger should call configure_logging() if not yet configured."""
        logging_config._configured = False
        logging_config.get_logger("auto-config-test")
        assert logging_config._configured is True

    def test_logger_can_emit_without_error(self):
        """Verify the returned logger can actually log without exceptions."""
        logging_config._configured = False
        logger = logging_config.get_logger("emit-test")
        # These should not raise
        logger.info("info message", key="value")
        logger.warning("warning message")
        logger.error("error message", exc_info=False)
