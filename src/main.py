"""Main FastAPI application for Artifact Registry Service."""

import logging
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from auth.middleware import PROTECTED_PREFIXES, PUBLIC_ENDPOINTS, AuthMiddleware
from core.config import get_settings
from core.database import engine
from logging_config import configure_logging
from metrics_server import start_metrics_server, stop_metrics_server
from middleware.logging import RequestLoggingMiddleware
from middleware.request_id import RequestIdMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from routes import artifacts, health
from telemetry import setup_telemetry
from tenant_guc import rls_startup_check

# Configure structured logging
configure_logging()
logger = logging.getLogger(__name__)

settings = get_settings()

# Toggle for leaking exc.detail into 500 envelopes. Mirrors nlp_service.
LEAK_EXCEPTION_DETAILS = settings.environment == "development"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan manager."""
    # Startup
    #
    # The DEDICATED plaintext Prometheus listener on its OWN port, bound FIRST
    # and fail-soft. Deliberately NOT a /metrics route on the API port: the
    # scrape relax is port-scoped, see src/metrics_server.py.
    start_metrics_server(app, settings.metrics_port)
    logger.info(f"Starting {settings.service_name}")
    logger.info(f"Environment: {settings.environment}")

    # Setup OTEL telemetry
    otel_enabled = setup_telemetry(app, "artifact-service")
    logger.info(f"OTEL telemetry enabled: {otel_enabled}")

    # art#49: say loudly if the RLS posture would fail every request closed
    # (policies present, TENANT_RLS_MODE not 'enforce'). Fail-soft, log-only.
    await rls_startup_check(engine, logger)

    # Initialize services
    from services import StorageService

    try:
        _storage = StorageService()  # Initialized for side effects
        logger.info("Storage service initialized successfully")
    except (httpx.HTTPError, OSError, ValueError) as e:
        logger.error(f"Failed to initialize storage service: {e}")

    yield

    # Shutdown
    logger.info(f"Shutting down {settings.service_name}")
    await engine.dispose()
    stop_metrics_server(app)


# `/openapi.json` is ALWAYS served — it is the contract source-of-truth that the
# n8n code generator (n8n_separated_modules/scripts/generate-node.ts) fetches
# live from the running pod. Only the human-facing `/docs` and `/redoc` UIs are
# gated behind ENABLE_DOCS / development environment.
docs_enabled = (settings.environment == "development") or settings.enable_docs
app = FastAPI(
    title="Artifact Registry Service",
    description=(
        "Multi-tenant artifact storage service. "
        "Proxies file uploads/downloads through storage_service (which owns MinIO credentials). "
        "Auth: license token via Authorization or X-Tenant-Id Bearer header, validated against "
        "license introspection service. Trusted-network callers (RFC 1918) can skip the token. "
        "Optional ClamAV virus scanning on upload."
    ),
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False,
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json",
    swagger_ui_parameters={"persistAuthorization": True},
    # Fallback unique-ID generator. Every route still sets `operation_id=`
    # explicitly (pinned in tests/test_openapi.py); this exists so a forgotten ID
    # degrades to `<tag>_<func>` (readable) instead of FastAPI's default
    # `<func>_<path>_<method>` (garbage in generated clients).
    generate_unique_id_function=lambda route: (
        f"{route.tags[0] if route.tags else 'default'}_{route.name}"
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness, readiness, dependency probes."},
        {"name": "Artifacts", "description": "Multi-tenant artifact storage and retrieval."},
        {"name": "meta", "description": "Service metadata."},
    ],
)

# --- Middleware ---
# Starlette executes middleware in reverse-registration order: the last
# add_middleware() call is the outermost wrapper and runs first on the
# request path. Target request-side execution order:
#
#   RequestId → Auth → SecurityHeaders → RequestLogging → CORS → handler
#
# CORS middleware — allowed origins come from CORS_ALLOWED_ORIGINS env var
# (comma-separated), set by the deployment. Outside production, localhost dev
# origins are auto-added.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # X-Total-Count carries the pre-pagination match count for the paged list
    # routes; without it exposed a browser caller cannot detect truncation.
    expose_headers=["X-Request-ID", "X-Processing-Time", "X-Total-Count"],
)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Add authentication middleware (toggle with ENABLE_AUTH=false to disable)
if settings.enable_auth:
    app.add_middleware(AuthMiddleware)
    logger.info("Authentication middleware enabled")
else:
    logger.warning("Authentication middleware DISABLED (ENABLE_AUTH=false)")

app.add_middleware(RequestIdMiddleware)


# Operations whose request/response cannot be modeled cleanly by orval
# (multipart UploadFile, binary StreamingResponse). Marked so the n8n
# code generator skips them and hand-written handlers in
# n8n-nodes-artifacts/nodes/Artifacts/operations/index.ts stay in charge.
MANUAL_OPERATION_IDS: frozenset[str] = frozenset(
    {
        "upload_artifact",
        "download_artifact",
        # Binary (text/html | application/pdf) document renders, DOC-1.
        "render_artifact",
        "artifacts_render_cross_project",
    }
)


def _is_array_schema(schema: dict[str, Any]) -> bool:
    """Return True if a JSON-schema fragment describes an array (directly or
    via anyOf/oneOf — FastAPI emits `Optional[list[str]]` as
    `{"anyOf": [{"type": "array", ...}, {"type": "null"}]}`)."""
    if schema.get("type") == "array":
        return True
    for key in ("anyOf", "oneOf"):
        for sub in schema.get(key, []) or []:
            if isinstance(sub, dict) and sub.get("type") == "array":
                return True
    return False


# Custom OpenAPI to inject tenant header parameter and bearer scheme
def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes.setdefault(
        "BearerAuth",
        {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "License",
            "description": (
                "License token. Transport: `X-Tenant-Id: Bearer <token>` "
                "(not the Authorization header — that is reserved for caller-side auth)."
            ),
        },
    )

    parameters = components.setdefault("parameters", {})
    parameters.setdefault(
        "TenantIdHeader",
        {
            "name": "X-Tenant-Id",
            "in": "header",
            "required": False,
            # This document used to publish `n8n-dev` as the documented default,
            # i.e. documentation teaching callers to mint a tenant by naming one.
            # `settings.default_tenant_id` is validated as a uuid in core.config.
            # No `default`: in OpenAPI that means "the server assumes this when
            # absent", which stopped being true with AUTH_TENANT_FALLBACK_MODE=
            # enforce — an absent header is 401 TENANT_REQUIRED, not the default.
            "description": (
                "Tenant UUID. A non-uuid value is rejected with 400 INVALID_TENANT_ID; "
                "omitting the header is rejected with 401 TENANT_REQUIRED "
                "(AUTH_TENANT_FALLBACK_MODE=enforce, the default)."
            ),
            "schema": {
                "type": "string",
                "format": "uuid",
            },
            "example": settings.default_tenant_id,
        },
    )

    for path, path_item in openapi_schema.get("paths", {}).items():
        normalized = path.rstrip("/") or "/"
        is_public = normalized in PUBLIC_ENDPOINTS or normalized.startswith(
            ("/docs", "/redoc", "/static", "/openapi.json", "/favicon.ico", "/health")
        )
        is_protected = any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)

        for operation in list(path_item.values()):
            if not isinstance(operation, dict):
                continue

            if is_protected and not is_public:
                operation.setdefault("security", [{"BearerAuth": []}])
                # Every protected operation can now answer 400 INVALID_TENANT_ID
                # from the auth middleware, before the route is ever reached, so
                # it belongs on the operation regardless of what the route
                # declares. `setdefault` so a route's own 400 (e.g. "Invalid
                # request body") wins where it already documents one.
                op_responses = operation.setdefault("responses", {})
                if isinstance(op_responses, dict):
                    op_responses.setdefault(
                        "400",
                        {
                            "description": (
                                "Invalid request — X-Tenant-Id is not a tenant UUID "
                                "(code INVALID_TENANT_ID)"
                            ),
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                                }
                            },
                        },
                    )
            elif is_public:
                operation.pop("security", None)

            op_params = operation.setdefault("parameters", [])
            has_tenant = any(
                p.get("name", "").lower() == "x-tenant-id" and p.get("in") == "header"
                for p in op_params
            )
            if not has_tenant:
                op_params.append({"$ref": "#/components/parameters/TenantIdHeader"})

            # FastAPI omits `style`/`explode` from query params because they are
            # OpenAPI 3.0 implicit defaults (style=form, explode=true). Codegens
            # like orval need them explicit to serialize array params as repeated
            # `?tags=a&tags=b` instead of comma-joined `?tags=a,b`. Inject the
            # explicit defaults for any array-typed query parameter.
            for param in op_params:
                if not isinstance(param, dict):
                    continue
                if param.get("in") != "query":
                    continue
                schema = param.get("schema")
                if not isinstance(schema, dict):
                    continue
                if _is_array_schema(schema):
                    param.setdefault("style", "form")
                    param.setdefault("explode", True)

            op_id = operation.get("operationId")
            if op_id in MANUAL_OPERATION_IDS:
                operation["x-n8n-manual"] = True

    app.openapi_schema = openapi_schema
    return app.openapi_schema


setattr(app, "openapi", custom_openapi)  # FastAPI documented pattern for custom OpenAPI


# --- Error envelope ---
def _error_envelope(
    code: str,
    message: str,
    http_status: int,
    *,
    request_id: str,
    details: str | None = None,
) -> dict[str, Any]:
    """Build the standardized error envelope.

    Matches ``routes.responses.ErrorResponse``: a single ``error`` key with
    ``code``, ``message``, ``status`` (HTTP) plus the request-id and an
    ISO-8601 timestamp. ``details`` is only included when populated.
    """
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "status": http_status,
        "request_id": request_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if details is not None:
        payload["details"] = details
    return {"error": payload}


def _http_exception_to_response(exc: StarletteHTTPException, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(
            f"HTTP_{exc.status_code}", str(exc.detail), exc.status_code, request_id=request_id
        ),
        headers=exc.headers,
    )


def _find_http_exception(exc: BaseException) -> HTTPException | None:
    """Walk nested ExceptionGroups to find the first HTTPException."""
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _find_http_exception(sub)
            if found is not None:
                return found
    return None


def _request_id_from(request: Request) -> str:
    return request.state.request_id if hasattr(request.state, "request_id") else str(uuid.uuid7())


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Render HTTPException (incl. FastAPI's 404) into the envelope."""
    return _http_exception_to_response(exc, _request_id_from(request))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Render pydantic request-validation errors into the envelope (HTTP 422)."""
    request_id = _request_id_from(request)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_error_envelope(
            "VALIDATION_ERROR",
            "Request validation failed",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            request_id=request_id,
            details=str(exc.errors()) if LEAK_EXCEPTION_DETAILS else None,
        ),
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for uncaught exceptions; returns the standardized envelope."""
    request_id: str = _request_id_from(request)

    http_exc = _find_http_exception(exc)
    if http_exc is not None:
        return _http_exception_to_response(http_exc, request_id)

    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_error_envelope(
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id,
            details=str(exc) if LEAK_EXCEPTION_DETAILS else None,
        ),
    )


# Include routers
app.include_router(health.router)
app.include_router(artifacts.router)
app.include_router(artifacts.cross_project_router)


@app.get(
    "/",
    operation_id="root",
    summary="Service info",
    status_code=status.HTTP_200_OK,
    tags=["meta"],
)
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {
        "service": settings.service_name,
        "version": "1.0.0",
        "status": "running",
        "environment": settings.environment,
    }
