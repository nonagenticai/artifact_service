"""Tests for OpenAPI invariants emitted by ``custom_openapi``.

These guard the contract that downstream consumers rely on:
- the n8n code generator skips operations marked with ``x-n8n-manual``
- every operation has a unique, non-empty ``operationId``
- every operation is tagged with one of the known tag groups

The live ``/openapi.json`` endpoint on the running pod is the source of truth
for downstream codegen (n8n_separated_modules/scripts/generate-node.ts fetches
it via download-openapi.sh) — there is no committed snapshot to keep in sync.

Each test resets ``app.openapi_schema`` to ``None`` so the cached schema
from a previous test does not leak into the next one.
"""

from __future__ import annotations

import os
from typing import Any

# Ensure required env vars are set before importing the app.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("ENABLE_AUTH", "false")
os.environ.setdefault("ENABLE_VIRUS_SCANNING", "false")

from main import app  # noqa: E402


def _fresh_schema() -> dict[str, Any]:
    """Force-regenerate the OpenAPI schema, bypassing the module-level cache."""
    app.openapi_schema = None
    return app.openapi()


def _iter_operations(schema: dict[str, Any]):
    """Yield ``(path, method, operation)`` for every HTTP op in the spec."""
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    for path, path_item in schema.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in http_methods and isinstance(operation, dict):
                yield path, method.lower(), operation


class TestOPENAPICustomization:
    """OpenAPI invariants for the artifact_service FastAPI app."""

    def test_x_n8n_manual_on_binary_ops(self) -> None:
        """Only the multipart upload + the binary download/render ops carry ``x-n8n-manual``."""
        schema = _fresh_schema()
        paths = schema["paths"]

        upload_op = paths["/projects/{project_id}/artifacts/upload"]["post"]
        download_op = paths["/projects/{project_id}/artifacts/{artifact_id}/download"]["get"]
        list_op = paths["/projects/{project_id}/artifacts"]["get"]

        assert upload_op.get("x-n8n-manual") is True, (
            "upload_artifact must be marked x-n8n-manual: True (multipart UploadFile)"
        )
        assert download_op.get("x-n8n-manual") is True, (
            "download_artifact must be marked x-n8n-manual: True (binary StreamingResponse)"
        )
        assert "x-n8n-manual" not in list_op, (
            "list_artifacts is fully orval-modelable and must NOT carry x-n8n-manual"
        )

        manual_ops = [
            (path, method, operation.get("operationId"))
            for path, method, operation in _iter_operations(schema)
            if operation.get("x-n8n-manual") is True
        ]
        assert len(manual_ops) == 4, (
            f"Exactly four operations must carry x-n8n-manual: True, got {manual_ops}"
        )
        manual_ids = {op_id for _, _, op_id in manual_ops}
        assert manual_ids == {
            "upload_artifact",
            "download_artifact",
            "render_artifact",
            "artifacts_render_cross_project",
        }, f"Unexpected x-n8n-manual operationIds: {manual_ids}"

    def test_all_operation_ids_unique_and_nonempty(self) -> None:
        """Every operation has a non-empty unique operationId; expected set present."""
        schema = _fresh_schema()
        ids = [operation.get("operationId") for _, _, operation in _iter_operations(schema)]

        assert all(isinstance(i, str) and i for i in ids), (
            f"Every operation must have a non-empty string operationId, got {ids}"
        )
        assert len(ids) == len(set(ids)), f"operationIds must be unique; duplicates in {ids}"

        # The plan documents 10 routes. Accept >= 10 in case FastAPI ever emits
        # an extra op for HEAD/OPTIONS, but flag if the count drops below 10.
        assert len(ids) >= 10, f"Expected at least 10 operations, got {len(ids)}: {ids}"

        expected = {
            "upload_artifact",
            "list_artifacts",
            "get_artifact",
            "download_artifact",
            "delete_artifact",
            "get_manifest",
            "health_check",
            "health_live",
            "health_ready",
            "root",
        }
        missing = expected - set(ids)
        assert not missing, f"Missing expected operationIds: {missing}"

    def test_every_operation_has_a_tag(self) -> None:
        """Every operation has a non-empty tags list; tag set is exactly known three."""
        schema = _fresh_schema()
        allowed_tags = {"artifacts", "health", "meta"}
        seen_tags: set[str] = set()

        for path, method, operation in _iter_operations(schema):
            op_id = operation.get("operationId")
            tags = operation.get("tags")
            assert isinstance(tags, list) and len(tags) > 0, (
                f"Operation {op_id!r} ({method.upper()} {path}) must have a non-empty tags list"
            )
            for tag in tags:
                assert tag in allowed_tags, (
                    f"Operation {op_id!r} ({method.upper()} {path}) uses unexpected tag "
                    f"{tag!r}; allowed: {sorted(allowed_tags)}"
                )
                seen_tags.add(tag)

        assert seen_tags == allowed_tags, (
            f"Tag set must be exactly {sorted(allowed_tags)}, got {sorted(seen_tags)}"
        )
