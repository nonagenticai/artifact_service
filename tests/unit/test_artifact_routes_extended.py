"""Extended tests for artifact routes covering edge cases and error paths.

These tests complement the basic CRUD coverage in test_artifact_routes.py
by exercising tag limits, storage failures, virus scanning edge cases,
pagination boundaries, cascade deletes, manifest scoping, and download errors.
"""

import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")

from unittest.mock import MagicMock, patch
from uuid import UUID

import httpx
from sqlalchemy import select

from models.artifact import ArtifactTag
from tests.conftest import TEST_TENANT_A, create_test_artifact

PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _upload(
    client,
    *,
    filename="test.txt",
    content_type="text/plain",
    kind="doc",
    sensitivity="internal",
    tags="",
    content=b"hello world",
    card_id=None,
    step=None,
    container_name=None,
    headers=None,
):
    """Upload helper reusable across test classes."""
    data = {
        "filename": filename,
        "content_type": content_type,
        "kind": kind,
        "sensitivity": sensitivity,
        "tags": tags,
    }
    if card_id is not None:
        data["card_id"] = str(card_id)
    if step is not None:
        data["step"] = step
    if container_name is not None:
        data["container_name"] = container_name

    return client.post(
        f"/projects/{PROJECT_ID}/artifacts/upload",
        data=data,
        files={"file": (filename, content, content_type)},
        headers=headers or {},
    )


class TestUploadEdgeCases:
    """Edge-case tests for the upload endpoint: tag limits, storage errors,
    virus scanning failures, empty files, and content-type validation."""

    async def test_upload_tag_limit_enforcement(self, real_app_client, db_session):
        """Upload with 25 tags should persist only the first 20 (line 223 cap)."""
        client, _storage = real_app_client
        tag_names = [f"tag{i}" for i in range(1, 26)]
        tags_csv = ",".join(tag_names)

        resp = _upload(client, filename="many_tags.txt", tags=tags_csv)
        assert resp.status_code == 200, resp.json()

        artifact_id = UUID(resp.json()["artifact_id"])

        # Fetch the artifact and verify exactly 20 tags stored
        get_resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{artifact_id}")
        assert get_resp.status_code == 200
        stored_tags = get_resp.json()["tags"]
        assert len(stored_tags) == 20
        # The first 20 should be kept
        assert sorted(stored_tags) == sorted(tag_names[:20])

    def test_upload_storage_failure_returns_500(self, real_app_client):
        """When storage.upload_file raises httpx.HTTPError, expect 500."""
        client, mock_storage = real_app_client
        mock_storage.upload_file.side_effect = httpx.HTTPError("connection lost")

        resp = _upload(client, filename="will_fail.txt")
        assert resp.status_code == 500
        assert "Failed to upload file" in resp.json()["detail"]

    def test_upload_virus_scan_failure_quarantine(self):
        """When virus scanning is enabled + quarantine on, a ConnectionError
        from the scanner should yield 500 'Virus scan failed'."""
        import secrets
        from unittest.mock import AsyncMock

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from starlette.middleware.base import BaseHTTPMiddleware

        from core.database import get_db
        from routes.artifacts import get_storage_service, router

        app = FastAPI()
        app.include_router(router)

        # Mock DB session
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        async def override_db():
            yield mock_session

        # Mock storage
        mock_storage = MagicMock()
        mock_storage.generate_storage_key.side_effect = lambda **kw: (
            f"test/storage/{secrets.token_hex(8)}/v1/{kw.get('filename', 'file.txt')}"
        )
        mock_storage.upload_file.return_value = None

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_storage_service] = lambda: mock_storage

        class FakeTenant(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                request.state.tenant_id = TEST_TENANT_A
                request.state.user = {"user_id": TEST_TENANT_A, "tenant_id": TEST_TENANT_A}
                return await call_next(request)

        app.add_middleware(FakeTenant)

        # Patch settings to enable virus scanning + quarantine, and
        # patch VirusScanner so scan_stream raises ConnectionError.
        mock_scanner = MagicMock()
        mock_scanner.scan_stream.side_effect = ConnectionError("ClamAV unreachable")

        with (
            patch("routes.artifacts.settings") as mock_settings,
            patch("routes.artifacts.VirusScanner", return_value=mock_scanner),
        ):
            mock_settings.allowed_mimes = ["text/plain"]
            mock_settings.max_file_size_bytes = 10 * 1024 * 1024
            mock_settings.enable_virus_scanning = True
            mock_settings.quarantine_infected_files = True

            with TestClient(app) as tc:
                resp = _upload(tc, filename="scan_fail.txt")
                assert resp.status_code == 500
                assert "Virus scan failed" in resp.json()["detail"]

    def test_upload_empty_file(self, real_app_client):
        """Uploading a zero-byte file should succeed -- no minimum size check."""
        client, _storage = real_app_client
        resp = _upload(client, filename="empty.txt", content=b"")
        assert resp.status_code == 200
        data = resp.json()
        assert data["size"] == 0

    def test_content_type_with_params_rejected(self, real_app_client):
        """content_type='application/pdf;charset=utf-8' is not in the
        allowed_mimes whitelist (exact match), so expect 415."""
        client, _storage = real_app_client
        resp = _upload(
            client,
            filename="report.pdf",
            content_type="application/pdf;charset=utf-8",
            content=b"%PDF-fake",
        )
        assert resp.status_code == 415


class TestDeleteEdgeCases:
    """Edge-case tests for the delete endpoint: cascade behaviour for tags."""

    async def test_delete_cascades_tags(self, real_app_client, db_session):
        """Deleting an artifact must also remove its ArtifactTag rows (CASCADE)."""
        client, _storage = real_app_client

        artifact = await create_test_artifact(
            db_session,
            tags=["alpha", "beta", "gamma"],
            project_id=PROJECT_ID,
        )

        # Verify tags exist before delete
        result = await db_session.execute(
            select(ArtifactTag).where(ArtifactTag.artifact_id == artifact.id)
        )
        assert len(result.scalars().all()) == 3

        # Delete the artifact via API
        resp = client.delete(
            f"/projects/{PROJECT_ID}/artifacts/{artifact.id}",
            headers={"X-Test-Tenant": TEST_TENANT_A},
        )
        assert resp.status_code == 204

        # Tags must be gone
        result = await db_session.execute(
            select(ArtifactTag).where(ArtifactTag.artifact_id == artifact.id)
        )
        remaining = result.scalars().all()
        assert remaining == []


class TestManifestEdgeCases:
    """Edge-case tests for the manifest endpoint: step scope filtering."""

    async def test_manifest_step_scope(self, real_app_client, db_session):
        """Manifest with scope=step and scope_ref=QA should return only QA artifacts."""
        client, _storage = real_app_client

        await create_test_artifact(db_session, step="QA", filename="qa1.txt", project_id=PROJECT_ID)
        await create_test_artifact(db_session, step="QA", filename="qa2.txt", project_id=PROJECT_ID)
        await create_test_artifact(
            db_session, step="DEV", filename="dev1.txt", project_id=PROJECT_ID
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/step?scope_ref=QA")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_count"] == 2
        assert data["scope"] == "step"
        filenames = sorted(a["filename"] for a in data["artifacts"])
        assert filenames == ["qa1.txt", "qa2.txt"]


class TestListEdgeCases:
    """Edge-case tests for the list endpoint: pagination limits, offset beyond
    total, and sensitivity filtering."""

    def test_list_pagination_limit_exceeds_max(self, real_app_client):
        """Requesting limit=1001 should fail with 422 (Query param le=1000)."""
        client, _storage = real_app_client
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?limit=1001")
        assert resp.status_code == 422

    async def test_list_offset_beyond_total(self, real_app_client, db_session):
        """Offset past the total count should return an empty list, not an error."""
        client, _storage = real_app_client

        await create_test_artifact(db_session, filename="a.txt", project_id=PROJECT_ID)
        await create_test_artifact(db_session, filename="b.txt", project_id=PROJECT_ID)

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?offset=100")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_sensitivity_filter(self, real_app_client, db_session):
        """Filtering by sensitivity=secret should return only secret artifacts."""
        client, _storage = real_app_client

        await create_test_artifact(
            db_session, sensitivity="secret", filename="classified.txt", project_id=PROJECT_ID
        )
        await create_test_artifact(
            db_session, sensitivity="internal", filename="normal.txt", project_id=PROJECT_ID
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?sensitivity=secret")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["sensitivity"] == "secret"
        assert data[0]["filename"] == "classified.txt"


class TestDownloadEdgeCases:
    """Edge-case tests for the download endpoint: storage errors during streaming."""

    async def test_download_storage_error(self, real_app_client, db_session):
        """When storage.download_file raises httpx.HTTPError,
        the response should surface an error."""
        client, mock_storage = real_app_client

        artifact = await create_test_artifact(
            db_session, filename="download_fail.txt", project_id=PROJECT_ID
        )

        mock_storage.download_file.side_effect = httpx.HTTPError("storage down")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{artifact.id}/download")
        # Storage error is caught before headers are sent, so we get a clean 500.
        assert resp.status_code == 500
