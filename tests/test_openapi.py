"""Guardrail tests for the OpenAPI surface.

Asserts that every route has an explicit ``operation_id`` from
``EXPECTED_OPERATION_IDS`` below and that the OpenAPI schema exposes the standard
metadata (security scheme, tag groups, error-envelope component).

If a new route is added or renamed, update ``EXPECTED_OPERATION_IDS``.
"""

from __future__ import annotations

import pytest

from main import app

# Source of truth for the operation ids.
EXPECTED_OPERATION_IDS: frozenset[str] = frozenset(
    {
        # Root + health
        "root",
        "health_check",
        "health_live",
        "health_ready",
        # Project-scoped artifact operations
        "upload_artifact",
        "list_artifacts",
        "get_artifact",
        "download_artifact",
        "delete_artifact",
        "get_manifest",
        # Review workflow
        "submit_artifact_review",
        "list_artifact_reviews",
        # System-tenant inheritance: own-tenant publish toggle
        "set_artifact_publish_status",
        # Cross-project listing
        "artifacts_list_cross_project",
        "artifacts_list_by_card_cross_project",
        "artifacts_get_cross_project",
        # Document metadata + render (DOC-1)
        "update_artifact_metadata",
        "render_artifact",
        "artifacts_render_cross_project",
    }
)


@pytest.fixture(scope="module")
def openapi_schema() -> dict:
    """Build the OpenAPI schema once per module."""
    app.openapi_schema = None
    return app.openapi()


def test_every_route_has_explicit_operation_id(openapi_schema: dict) -> None:
    """No path/method should rely on FastAPI's auto-generated operationId."""
    auto_generated_pattern_suffixes = ("_post", "_get", "_put", "_delete", "_patch")
    offenders: list[tuple[str, str, str]] = []
    for path, item in openapi_schema.get("paths", {}).items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            op_id: str = op.get("operationId", "")
            if (
                op_id.endswith(auto_generated_pattern_suffixes)
                and op_id not in EXPECTED_OPERATION_IDS
            ):
                offenders.append((method.upper(), path, op_id))
    assert not offenders, f"Routes without explicit operation_id (auto-generated): {offenders}"


def test_operation_ids_match_plan(openapi_schema: dict) -> None:
    """The set of operationIds in the schema must equal the plan."""
    actual: set[str] = set()
    for item in openapi_schema.get("paths", {}).values():
        for op in item.values():
            if isinstance(op, dict) and op.get("operationId"):
                actual.add(op["operationId"])

    missing = EXPECTED_OPERATION_IDS - actual
    unexpected = actual - EXPECTED_OPERATION_IDS
    assert not missing and not unexpected, (
        f"operationId drift — missing: {sorted(missing)}, unexpected: {sorted(unexpected)}"
    )


def test_operation_ids_are_unique(openapi_schema: dict) -> None:
    """Every operationId must be unique across the whole schema."""
    seen: dict[str, tuple[str, str]] = {}
    duplicates: list[tuple[str, tuple[str, str], tuple[str, str]]] = []
    for path, item in openapi_schema.get("paths", {}).items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            op_id = op.get("operationId")
            if not op_id:
                continue
            if op_id in seen:
                duplicates.append((op_id, seen[op_id], (method.upper(), path)))
            else:
                seen[op_id] = (method.upper(), path)
    assert not duplicates, f"Duplicate operationIds: {duplicates}"


def test_bearer_auth_scheme_is_declared(openapi_schema: dict) -> None:
    """BearerAuth security scheme must be present (license-token transport)."""
    schemes = openapi_schema.get("components", {}).get("securitySchemes", {})
    assert "BearerAuth" in schemes, "BearerAuth scheme missing from OpenAPI"
    scheme = schemes["BearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"


def test_tenant_id_header_parameter_is_declared(openapi_schema: dict) -> None:
    """The reusable TenantIdHeader parameter must be in components.parameters."""
    parameters = openapi_schema.get("components", {}).get("parameters", {})
    assert "TenantIdHeader" in parameters, "TenantIdHeader parameter missing"
    param = parameters["TenantIdHeader"]
    assert param["in"] == "header"
    assert param["name"].lower() == "x-tenant-id"


def test_tag_groups_are_defined(openapi_schema: dict) -> None:
    """``openapi_tags`` must declare at least Health and Artifacts."""
    tag_names = {t["name"] for t in openapi_schema.get("tags", [])}
    assert {"Health", "Artifacts"} <= tag_names, (
        f"Missing required tag groups; have {sorted(tag_names)}"
    )


def test_protected_routes_have_security_requirement(openapi_schema: dict) -> None:
    """Every /projects/* and /api/artifacts/* operation must require BearerAuth."""
    protected_paths = [
        p
        for p in openapi_schema.get("paths", {})
        if p.startswith("/projects") or p.startswith("/api/artifacts")
    ]
    assert protected_paths, "No protected paths found in schema"
    for path in protected_paths:
        for method, op in openapi_schema["paths"][path].items():
            if not isinstance(op, dict):
                continue
            security = op.get("security", [])
            assert any("BearerAuth" in entry for entry in security), (
                f"{method.upper()} {path} is missing BearerAuth security requirement"
            )


def test_public_routes_have_no_security_requirement(openapi_schema: dict) -> None:
    """Health + root paths must not require auth in the schema."""
    public_paths = {"/", "/health", "/health/ready", "/health/live"}
    for path in public_paths:
        item = openapi_schema.get("paths", {}).get(path)
        if item is None:
            continue
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            security = op.get("security", [])
            assert not security, (
                f"Public route {method.upper()} {path} unexpectedly has security={security}"
            )


# ----------------------------------------------------------------------
# Pagination contract
# ----------------------------------------------------------------------


def _param(openapi_schema: dict, path: str, name: str) -> dict:
    for p in openapi_schema["paths"][path]["get"]["parameters"]:
        if p.get("name") == name:
            return p
    raise AssertionError(f"{path} has no `{name}` query parameter — the read is unbounded")


def test_every_list_route_is_bounded(openapi_schema: dict) -> None:
    """Each list-shaped GET publishes limit+offset capped at 1000.

    A route missing `limit` here is a route that materialises every matching
    row: the defect this contract exists to make impossible to reintroduce.
    """
    paths = [
        "/projects/{project_id}/artifacts",
        "/projects/{project_id}/artifacts/manifests/{scope}",
        "/projects/{project_id}/artifacts/{artifact_id}/reviews",
        "/api/artifacts",
        "/api/artifacts/by-card/{card_id}",
    ]
    for path in paths:
        limit = _param(openapi_schema, path, "limit")["schema"]
        assert limit["maximum"] == 1000, f"{path}: limit is not capped at 1000"
        assert limit["minimum"] == 1
        _param(openapi_schema, path, "offset")


def test_manifest_default_limit_stays_at_the_cap(openapi_schema: dict) -> None:
    """The manifest's 1000 default is deliberate — do not "harmonise" it to 100.

    MEASURED 2026-09-08 in production: one project holds 55,036 artifacts, and
    the live `n8n-nodes-artifacts` `getManifest` sends no `limit`/`offset` and
    drops response headers. Lowering this default to match the list endpoints
    silently truncates that consumer by another factor of ten. Change it only
    once the client pages (then this test should be updated deliberately, with
    the client fix, not to make a red run go green).
    """
    manifest_limit = _param(
        openapi_schema, "/projects/{project_id}/artifacts/manifests/{scope}", "limit"
    )["schema"]
    assert manifest_limit["default"] == 1000

    by_card_limit = _param(openapi_schema, "/api/artifacts/by-card/{card_id}", "limit")["schema"]
    assert by_card_limit["default"] == 100, (
        "by-card keeps the 100 default: card_id is NULL on all 55,057 production "
        "rows, so the route matches nothing and cannot truncate a live caller"
    )


def test_manifest_publishes_the_truncated_flag(openapi_schema: dict) -> None:
    """`truncated` is part of the Manifest contract, not an incidental field."""
    manifest = openapi_schema["components"]["schemas"]["Manifest"]
    assert "truncated" in manifest["properties"]
    assert manifest["properties"]["truncated"]["type"] == "boolean"
    assert "truncated" in manifest["required"], (
        "an optional truncation flag can be absent, and an absent flag reads as false"
    )
