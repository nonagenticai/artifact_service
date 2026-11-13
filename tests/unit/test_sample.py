"""Unit tests for application routes, schemas, and enums.

These tests verify:
- All expected routes are registered in the FastAPI app
- Pydantic schemas serialize and deserialize correctly
- Enum values match the expected domain model
- Schema validators reject invalid input
- Root and OpenAPI endpoints return correct responses
"""

import os
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

# Disable auth and enable docs BEFORE importing the app
os.environ["ENABLE_AUTH"] = "false"
os.environ["ENABLE_DOCS"] = "true"

from fastapi.testclient import TestClient

from main import app
from models.schemas import (
    ArtifactIn,
    ArtifactKind,
    ArtifactOut,
    ArtifactSensitivity,
    Manifest,
    ManifestScope,
    UploadResponse,
)
from routes.health import HealthResponse
from tests.conftest import TEST_TENANT_A

client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# 1. Route registration
# ---------------------------------------------------------------------------

EXPECTED_ROUTES = {
    ("/", "GET"),
    ("/health", "GET"),
    ("/health/live", "GET"),
    ("/health/ready", "GET"),
    ("/projects/{project_id}/artifacts", "GET"),
    ("/projects/{project_id}/artifacts/upload", "POST"),
    ("/projects/{project_id}/artifacts/{artifact_id}", "GET"),
    ("/projects/{project_id}/artifacts/{artifact_id}/download", "GET"),
    ("/projects/{project_id}/artifacts/{artifact_id}", "DELETE"),
    ("/projects/{project_id}/artifacts/manifests/{scope}", "GET"),
}


@pytest.mark.unit
def test_all_routes_registered() -> None:
    """Every expected route+method pair must be present in the app."""
    registered: set[tuple[str, str]] = set()
    # Derive from the OpenAPI schema (stable across FastAPI versions; include_router
    # results are _IncludedRouter wrappers without .path on newer FastAPI).
    for path, path_item in app.openapi().get("paths", {}).items():
        for method in path_item:
            registered.add((path, method.upper()))
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path and methods:
            for method in methods:
                registered.add((path, method))

    for path, method in EXPECTED_ROUTES:
        assert (path, method) in registered, (
            f"Route {method} {path} not registered. Registered routes: {sorted(registered)}"
        )


# ---------------------------------------------------------------------------
# 2. Pydantic schema serialization
# ---------------------------------------------------------------------------

_PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")
_ARTIFACT_ID = UUID("22222222-2222-2222-2222-222222222222")
_CARD_ID = UUID("33333333-3333-3333-3333-333333333333")
_NOW = datetime.now(UTC)


@pytest.mark.unit
def test_pydantic_schemas_serialize() -> None:
    """All response models can be instantiated and round-tripped to JSON."""
    artifact_out = ArtifactOut(
        id=_ARTIFACT_ID,
        version=1,
        filename="report.pdf",
        content_type="application/pdf",
        kind=ArtifactKind.DOC,
        project_id=_PROJECT_ID,
        card_id=_CARD_ID,
        step="QA:validation",
        container_name="container-1",
        sensitivity=ArtifactSensitivity.INTERNAL,
        size=204800,
        sha256="a" * 64,
        storage_key="projects/111/card/333/222/v1/report.pdf",
        created_at=_NOW,
        created_by=TEST_TENANT_A,
        tags=["qa", "final"],
    )
    data = artifact_out.model_dump()
    assert data["id"] == _ARTIFACT_ID
    assert data["filename"] == "report.pdf"
    assert data["kind"] == ArtifactKind.DOC
    assert data["tags"] == ["qa", "final"]
    # JSON round-trip
    json_str = artifact_out.model_dump_json()
    assert "report.pdf" in json_str

    manifest = Manifest(
        project_id=_PROJECT_ID,
        scope=ManifestScope.CARD,
        scope_ref=str(_CARD_ID),
        artifacts=[artifact_out],
        total_count=1,
        total_size=204800,
        # Required, deliberately: an optional flag would default to False and a
        # truncated manifest would then claim to be complete.
        truncated=False,
    )
    manifest_data = manifest.model_dump()
    assert manifest_data["total_count"] == 1
    assert len(manifest_data["artifacts"]) == 1
    assert manifest_data["scope"] == ManifestScope.CARD
    assert manifest_data["truncated"] is False

    upload_resp = UploadResponse(
        artifact_id=_ARTIFACT_ID,
        version=1,
        storage_key="projects/111/card/333/222/v1/report.pdf",
        size=204800,
        sha256="a" * 64,
    )
    upload_data = upload_resp.model_dump()
    assert upload_data["artifact_id"] == _ARTIFACT_ID
    assert upload_data["version"] == 1
    assert upload_data["size"] == 204800

    health = HealthResponse(
        status="healthy",
        service="artifact-service",
        version="0.1.0",
        timestamp=_NOW,
        checks={"database": True, "storage": True, "virus_scanner": True},
    )
    health_data = health.model_dump()
    assert health_data["status"] == "healthy"
    assert health_data["checks"]["database"] is True
    assert health_data["checks"]["storage"] is True
    assert health_data["checks"]["virus_scanner"] is True


# ---------------------------------------------------------------------------
# 3. Enum value tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_artifact_kind_enum_values() -> None:
    """ArtifactKind must contain exactly the expected domain values."""
    expected = {"doc", "presentation", "image", "dataset", "json", "graph", "other"}
    actual = {member.value for member in ArtifactKind}
    assert actual == expected


@pytest.mark.unit
def test_artifact_sensitivity_enum_values() -> None:
    """ArtifactSensitivity must contain exactly the expected levels."""
    expected = {"public", "internal", "secret"}
    actual = {member.value for member in ArtifactSensitivity}
    assert actual == expected


@pytest.mark.unit
def test_manifest_scope_enum_values() -> None:
    """ManifestScope must contain exactly the expected scope types."""
    expected = {"project", "card", "step"}
    actual = {member.value for member in ManifestScope}
    assert actual == expected


# ---------------------------------------------------------------------------
# 4. Schema validation
# ---------------------------------------------------------------------------


def _valid_artifact_in_kwargs() -> dict:
    """Return minimal valid kwargs for ArtifactIn."""
    return {
        "filename": "test.pdf",
        "content_type": "application/pdf",
        "kind": ArtifactKind.DOC,
        "project_id": _PROJECT_ID,
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_filename",
    [
        "../etc/passwd",
        "foo/bar.txt",
        "foo\\bar.txt",
        "..hidden",
    ],
)
def test_filename_validation_in_schema(bad_filename: str) -> None:
    """ArtifactIn must reject filenames containing path traversal characters."""
    kwargs = _valid_artifact_in_kwargs()
    kwargs["filename"] = bad_filename
    with pytest.raises(ValidationError) as exc_info:
        ArtifactIn(**kwargs)
    errors = exc_info.value.errors()
    assert any("path traversal" in str(e["msg"]).lower() for e in errors)


@pytest.mark.unit
def test_tags_validation_max_20() -> None:
    """ArtifactIn must reject more than 20 tags."""
    kwargs = _valid_artifact_in_kwargs()
    kwargs["tags"] = [f"tag-{i}" for i in range(21)]
    with pytest.raises(ValidationError) as exc_info:
        ArtifactIn(**kwargs)
    errors = exc_info.value.errors()
    assert any("20" in str(e["msg"]) for e in errors)


# ---------------------------------------------------------------------------
# 5. HTTP endpoint tests (TestClient, no DB)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_root_endpoint_response() -> None:
    """GET / must return service info with the correct keys and values."""
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "artifact-service"
    assert body["version"] == "1.0.0"
    assert body["status"] == "running"
    assert "environment" in body


@pytest.mark.unit
def test_openapi_schema_generated() -> None:
    """The app must be able to produce a valid OpenAPI schema.

    Note: the /openapi.json HTTP endpoint may be disabled depending on
    test-collection order (Settings singleton caching). We call
    app.openapi() directly which always works regardless of the
    ``openapi_url`` flag.
    """
    # Reset any previously cached schema so our custom_openapi runs fresh
    app.openapi_schema = None
    schema = app.openapi()

    assert "openapi" in schema
    assert schema["openapi"].startswith("3.")
    assert "info" in schema
    assert schema["info"]["title"] == "Artifact Registry Service"
    assert "paths" in schema
    # Spot-check that a known path is documented
    assert "/projects/{project_id}/artifacts" in schema["paths"]


# ---------------------------------------------------------------------------
# 6. Custom OpenAPI schema enrichment
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_openapi_schema_has_bearer_auth() -> None:
    """Custom OpenAPI must include BearerAuth security scheme."""
    app.openapi_schema = None
    schema = app.openapi()
    security_schemes = schema.get("components", {}).get("securitySchemes", {})
    assert "BearerAuth" in security_schemes
    assert security_schemes["BearerAuth"]["type"] == "http"
    assert security_schemes["BearerAuth"]["scheme"] == "bearer"


@pytest.mark.unit
def test_openapi_schema_has_tenant_header_parameter() -> None:
    """Custom OpenAPI must include X-Tenant-Id header parameter on all operations."""
    app.openapi_schema = None
    schema = app.openapi()

    # Check the parameter is defined in components
    parameters = schema.get("components", {}).get("parameters", {})
    assert "TenantIdHeader" in parameters
    assert parameters["TenantIdHeader"]["name"] == "X-Tenant-Id"
    assert parameters["TenantIdHeader"]["in"] == "header"

    # Check that at least one path operation references it
    paths = schema.get("paths", {})
    found_ref = False
    for path_item in paths.values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if param.get("$ref") == "#/components/parameters/TenantIdHeader":
                    found_ref = True
                    break
    assert found_ref, "No operation references TenantIdHeader parameter"


@pytest.mark.unit
def test_openapi_schema_caching() -> None:
    """Second call to app.openapi() should return the same cached object."""
    app.openapi_schema = None
    schema1 = app.openapi()
    schema2 = app.openapi()
    assert schema1 is schema2


# ---------------------------------------------------------------------------
# 7. Exception handler tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_unhandled_exception_returns_500() -> None:
    """Global exception handler returns 500 for non-HTTP exceptions, in canonical envelope."""
    import json
    from unittest.mock import MagicMock

    from main import global_exception_handler

    mock_request = MagicMock()
    # request.state.request_id needs to be a real str for the JSONResponse encoder.
    mock_request.state.request_id = "01900000-0000-7000-8000-000000000000"
    exc = ValueError("something broke")

    response = await global_exception_handler(mock_request, exc)
    assert response.status_code == 500
    body = json.loads(bytes(response.body))
    assert set(body.keys()) == {"error"}
    err = body["error"]
    assert err["code"] == "INTERNAL_SERVER_ERROR"
    assert err["status"] == 500
    assert err["message"] == "An unexpected error occurred"
    assert err["request_id"] == "01900000-0000-7000-8000-000000000000"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_http_exception_reraised() -> None:
    """Global exception handler converts HTTPException into the canonical envelope.

    Previously the handler re-raised; the canonical pattern now routes
    HTTPException through ``_http_exception_to_response`` so the 404 also
    carries the standard ``{error: {code, message, status, request_id, …}}``
    shape — see ``main.global_exception_handler``.
    """
    import json
    from unittest.mock import MagicMock

    from fastapi import HTTPException as FastAPIHTTPException

    from main import global_exception_handler

    mock_request = MagicMock()
    mock_request.state.request_id = "01900000-0000-7000-8000-000000000001"
    exc = FastAPIHTTPException(status_code=404, detail="Not found")

    response = await global_exception_handler(mock_request, exc)
    assert response.status_code == 404
    body = json.loads(bytes(response.body))
    assert body["error"]["code"] == "HTTP_404"
    assert body["error"]["status"] == 404
    assert body["error"]["message"] == "Not found"


# ---------------------------------------------------------------------------
# 8. Lifespan manager tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_lifespan_startup_and_shutdown() -> None:
    """Lifespan manager should complete startup and shutdown without errors."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from main import lifespan

    mock_storage_cls = MagicMock()

    with (
        patch("main.setup_telemetry", return_value=False) as mock_telemetry,
        patch("main.engine") as mock_engine,
        patch("services.StorageService", mock_storage_cls),
    ):
        mock_engine.dispose = AsyncMock()
        async with lifespan(app):
            # Verify startup completed: telemetry was called and storage was instantiated
            mock_telemetry.assert_called_once_with(app, "artifact-service")
            mock_storage_cls.assert_called_once()
        # Verify shutdown: engine was disposed
        mock_engine.dispose.assert_awaited_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_lifespan_storage_init_failure() -> None:
    """Lifespan should handle StorageService init failure gracefully (log, don't crash)."""
    from unittest.mock import AsyncMock, patch

    from main import lifespan

    with (
        patch("main.setup_telemetry", return_value=False),
        patch("main.engine") as mock_engine,
        patch(
            "services.storage_service.StorageService.__init__",
            side_effect=OSError("MinIO unreachable"),
        ),
    ):
        mock_engine.dispose = AsyncMock()
        async with lifespan(app):
            pass  # Should not crash even if storage init fails
        # Verify shutdown still completes even after startup failure
        mock_engine.dispose.assert_awaited_once()
