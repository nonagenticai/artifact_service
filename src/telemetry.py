"""OpenTelemetry setup with graceful degradation.

This module provides OTEL tracing initialization that:
- Tests connection to OTLP endpoint before enabling
- Falls back gracefully if Grafana agent is unavailable
- Respects OTEL_SDK_DISABLED env var
"""

import logging
import os
import socket

from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Track initialization state
_initialized: bool = False


def _test_connection(host: str, port: int, timeout: float = 2.0) -> bool:
    """Test if OTLP endpoint is reachable."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except TimeoutError, ConnectionRefusedError, OSError:
        return False


def setup_telemetry(app: FastAPI, service_name: str = "artifact-service") -> bool:
    """Initialize OpenTelemetry with graceful degradation.

    Args:
        app: FastAPI application instance
        service_name: Name to identify this service in traces

    Returns:
        True if OTEL was successfully initialized, False otherwise
    """
    global _initialized

    if _initialized:
        return True

    if os.getenv("OTEL_SDK_DISABLED", "false").lower() == "true":
        logger.info("OTEL SDK disabled via environment variable")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        logger.warning(f"OTEL packages not available: {e}")
        return False

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    # Endpoint is provided via OTLP_TRACES_ENDPOINT env var (read into Settings).
    # If unset, OTEL is disabled outside production; the production validator in
    # core.config refuses to start without it.
    from core.config import get_settings

    otlp_endpoint = os.getenv("OTLP_TRACES_ENDPOINT", "") or get_settings().otlp_traces_endpoint
    if not otlp_endpoint:
        logger.info("OTLP_TRACES_ENDPOINT not set; OTEL traces disabled")
        return False

    # Extract host/port for connection test
    try:
        from urllib.parse import urlparse

        parsed = urlparse(otlp_endpoint.replace("/v1/traces", ""))
        host = parsed.hostname or "alloy"
        port = parsed.port or 4318

        if _test_connection(host, port):
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, timeout=5)
            processor = BatchSpanProcessor(
                exporter,
                max_queue_size=2048,
                schedule_delay_millis=5000,
                max_export_batch_size=512,
                export_timeout_millis=30000,
            )
            provider.add_span_processor(processor)
            logger.info(f"OTEL exporter configured: {otlp_endpoint}")
        else:
            logger.warning(f"OTLP endpoint not reachable: {host}:{port}, tracing disabled")
    except (ValueError, OSError) as e:
        logger.warning(f"Failed to configure OTEL exporter: {e}")

    trace.set_tracer_provider(provider)

    # Instrument frameworks
    try:
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumentation enabled")
    except (ImportError, RuntimeError) as e:
        logger.warning(f"FastAPI instrumentation failed: {e}")

    try:
        HTTPXClientInstrumentor().instrument()
        logger.info("HTTPX instrumentation enabled")
    except (ImportError, RuntimeError) as e:
        logger.warning(f"HTTPX instrumentation failed: {e}")

    try:
        SQLAlchemyInstrumentor().instrument()
        logger.info("SQLAlchemy instrumentation enabled")
    except (ImportError, RuntimeError) as e:
        logger.warning(f"SQLAlchemy instrumentation failed: {e}")

    _initialized = True
    return True
