"""
Structured logging with OpenTelemetry trace correlation.
"""

import logging
import os
import sys
from collections.abc import MutableMapping
from types import ModuleType
from typing import Any, cast

import structlog

# Check if OTEL is available
OTEL_AVAILABLE = False
trace: ModuleType | None = None
try:
    from opentelemetry import trace as otel_trace

    trace = otel_trace
    OTEL_AVAILABLE = True
except ImportError:
    pass


def add_trace_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Inject OpenTelemetry trace context into structured logs."""
    if OTEL_AVAILABLE and trace:
        span = trace.get_current_span()
        if span and span.is_recording():
            ctx = span.get_span_context()
            if ctx.is_valid:
                event_dict["trace_id"] = format(ctx.trace_id, "032x")
                event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


def add_service_context(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Add service metadata to logs."""
    event_dict["service"] = os.getenv("OTEL_SERVICE_NAME", "artifact-service")
    event_dict["environment"] = os.getenv("ENVIRONMENT", "development")
    return event_dict


_configured: bool = False


def configure_logging(level: int | None = None, log_file: str | None = None) -> None:
    """Configure structured JSON logging with trace context.

    Args:
        level: Logging level (defaults to INFO or LOG_LEVEL env var)
        log_file: Optional file path for logging (ignored in structlog setup)
    """
    global _configured

    if _configured:
        return

    log_format = os.getenv("LOG_FORMAT", "json").lower()
    log_level: int = level or logging.getLevelNamesMapping().get(
        os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO
    )

    # Determine processors based on format
    if log_format == "json":
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            add_service_context,
            add_trace_context,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Human-readable console format for development
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            add_service_context,
            add_trace_context,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=log_level)

    # Suppress noisy loggers
    for logger_name in ["httpx", "httpcore", "uvicorn.access", "urllib3"]:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a module-level structured logger.

    Args:
        name: Logger name (defaults to "artifact_service")

    Returns:
        Configured structlog logger
    """
    configure_logging()
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name or "artifact_service"))
