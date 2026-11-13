"""Tests for artifact routes using FastAPI TestClient with mocked DB sessions."""

import hashlib
import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid7

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

# Ensure env vars set before imports
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("ENABLE_AUTH", "false")
os.environ.setdefault("ENABLE_VIRUS_SCANNING", "false")

from models.artifact import Artifact, ArtifactTag
from models.schemas import ArtifactKind, ArtifactSensitivity
from routes.artifacts import cross_project_router, get_storage_service, router
from routes.health import router as health_router
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B  # noqa: E402


def make_mock_artifact(
    artifact_id=None,
    project_id=None,
    tenant_id=TEST_TENANT_A,
    filename="test.txt",
    content_type="text/plain",
    kind=ArtifactKind.DOC,
    sensitivity=ArtifactSensitivity.INTERNAL,
    size=100,
    version=1,
    sha256="abc123",
    storage_key="projects/test/v1/test.txt",
    card_id=None,
    step=None,
    container_name=None,
    created_by=TEST_TENANT_A,
    subject_id=TEST_TENANT_A,
    visibility="tenant",
    status="pending",
    review_callback_url=None,
    origin_kind="tenant",
    origin_project_id=None,
    origin_workflow_run_id=None,
    created_by_user_id="",
    publish_status="draft",
    title=None,
    doc_type=None,
    phase=None,
    summary=None,
    planka_card_id=None,
):
    """Create a mock artifact object.

    ⚠️ Every column ArtifactOut reads must be set EXPLICITLY here. A MagicMock
    auto-creates any attribute it is asked for, so an unset column does not
    fail loudly — it hands Pydantic a MagicMock. The four provenance columns
    were added to the model in 20260519_0002 and never added here, which is
    consistent with their having been unreadable through the API until now.
    """
    art = MagicMock()
    art.id = artifact_id or uuid7()
    art.tenant_id = tenant_id
    art.subject_id = subject_id
    art.visibility = visibility
    art.project_id = project_id or UUID("11111111-1111-1111-1111-111111111111")
    art.card_id = card_id
    art.step = step
    art.container_name = container_name
    art.version = version
    art.filename = filename
    art.content_type = content_type
    art.kind = kind
    art.sensitivity = sensitivity
    art.size = size
    art.sha256 = sha256
    art.storage_key = storage_key
    art.created_at = datetime.now(UTC)
    art.created_by = created_by
    art.status = status
    art.review_callback_url = review_callback_url
    art.origin_kind = origin_kind
    art.origin_project_id = origin_project_id
    art.origin_workflow_run_id = origin_workflow_run_id
    art.created_by_user_id = created_by_user_id
    art.publish_status = publish_status
    art.title = title
    art.doc_type = doc_type
    art.phase = phase
    art.summary = summary
    art.planka_card_id = planka_card_id
    art.tags = []
    return art


def make_mock_storage():
    """Create a mock storage service."""
    mock = MagicMock()
    mock.generate_storage_key.return_value = "projects/test/card/ref/aid/v1/file.txt"
    mock.upload_file.return_value = None
    mock.download_file.return_value = b"file content here"
    mock.delete_file.return_value = None
    return mock


def make_mock_db(artifacts=None):
    """Create a mock AsyncSession."""
    db = AsyncMock()

    # Default: execute returns empty result
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = artifacts or []
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar_one_or_none.return_value = artifacts[0] if artifacts else None
    # `.first()` answers the (count, sum(size)) aggregate the paged list/manifest
    # routes run BEFORE their page query. One mock result serves every execute()
    # here, so it has to be consistent with the row list above: a mock that said
    # 1/1 (MagicMock's default __int__) would make a manifest test assert on the
    # harness rather than on the route.
    mock_result.first.return_value = (
        len(artifacts or []),
        sum(a.size for a in (artifacts or [])),
    )
    db.execute.return_value = mock_result

    # session.add() is synchronous, so use MagicMock to avoid unawaited coroutine warnings
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    return db


@pytest.fixture
def mock_storage():
    return make_mock_storage()


@pytest.fixture
def mock_db():
    return make_mock_db()


@pytest.fixture
def client(mock_storage, mock_db):
    """Create FastAPI test client with overridden dependencies."""
    from core.database import get_db

    app = FastAPI()
    app.include_router(router)
    app.include_router(cross_project_router)
    app.include_router(health_router)

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage_service] = lambda: mock_storage

    # Add middleware to set tenant state
    from starlette.middleware.base import BaseHTTPMiddleware

    class FakeTenantMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.tenant_id = TEST_TENANT_A
            request.state.user = {"user_id": TEST_TENANT_A, "tenant_id": TEST_TENANT_A}
            return await call_next(request)

    app.add_middleware(FakeTenantMiddleware)

    with TestClient(app) as c:
        yield c


PROJECT_ID = "11111111-1111-1111-1111-111111111111"


class TestUploadArtifact:
    """Test artifact upload endpoint."""

    def test_upload_success(self, client, mock_storage, mock_db):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "test.pdf",
                "content_type": "application/pdf",
                "kind": "doc",
                "sensitivity": "internal",
                "tags": "tag1,tag2",
            },
            files={"file": ("test.pdf", b"pdf content", "application/pdf")},
        )
        assert response.status_code == 200, response.json()
        data = response.json()
        assert "artifact_id" in data
        assert data["version"] == 1
        assert data["size"] == len(b"pdf content")
        assert "sha256" in data
        mock_storage.upload_file.assert_called_once()
        mock_db.commit.assert_awaited()

    def test_upload_with_card_id(self, client, mock_storage):
        card_id = str(uuid7())
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "test.txt",
                "content_type": "text/plain",
                "kind": "doc",
                "card_id": card_id,
            },
            files={"file": ("test.txt", b"hello", "text/plain")},
        )
        assert response.status_code == 200
        # Verify storage key was generated with card scope
        mock_storage.generate_storage_key.assert_called_once()
        call_kwargs = mock_storage.generate_storage_key.call_args
        assert call_kwargs[1]["scope"] == "card" or call_kwargs.kwargs.get("scope") == "card"

    def test_upload_with_step(self, client, mock_storage):
        content = b"{}"
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "result.json",
                "content_type": "application/json",
                "kind": "json",
                "step": "QA-validation",
            },
            files={"file": ("result.json", content, "application/json")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "artifact_id" in data
        assert data["version"] == 1
        assert data["size"] == len(content)
        assert "sha256" in data
        mock_storage.upload_file.assert_called_once()

    def test_upload_project_scope(self, client, mock_storage):
        content = b"hello"
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "readme.txt",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("readme.txt", content, "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "artifact_id" in data
        assert data["version"] == 1
        assert data["size"] == len(content)
        assert "sha256" in data
        mock_storage.generate_storage_key.assert_called_once()
        call_kwargs = mock_storage.generate_storage_key.call_args
        assert call_kwargs[1]["scope"] == "project" or call_kwargs.kwargs.get("scope") == "project"

    def test_upload_invalid_content_type(self, client, mock_storage):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "test.exe",
                "content_type": "application/x-executable",
                "kind": "other",
            },
            files={"file": ("test.exe", b"binary", "application/x-executable")},
        )
        assert response.status_code == 415

    def test_upload_path_traversal_filename(self, client, mock_storage):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "../etc/passwd",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("test.txt", b"data", "text/plain")},
        )
        assert response.status_code == 400
        assert "traversal" in response.json()["detail"].lower()

    def test_upload_null_byte_filename(self, client, mock_storage):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "test\x00.txt",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("test.txt", b"data", "text/plain")},
        )
        assert response.status_code == 400
        assert "null" in response.json()["detail"].lower()

    def test_upload_backslash_filename(self, client, mock_storage):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "path\\file.txt",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("file.txt", b"data", "text/plain")},
        )
        assert response.status_code == 400
        assert "traversal" in response.json()["detail"].lower()

    def test_upload_encoded_traversal_filename(self, client, mock_storage):
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "%2e%2e%2fpasswd",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("f.txt", b"data", "text/plain")},
        )
        assert response.status_code == 400
        assert "traversal" in response.json()["detail"].lower()

    def test_upload_file_too_large(self, client, mock_storage):
        with patch("routes.artifacts.settings") as mock_settings:
            mock_settings.allowed_mimes = ["text/plain"]
            mock_settings.max_file_size_bytes = 10
            mock_settings.max_file_size_mb = 0
            mock_settings.enable_virus_scanning = False

            response = client.post(
                f"/projects/{PROJECT_ID}/artifacts/upload",
                data={
                    "filename": "big.txt",
                    "content_type": "text/plain",
                    "kind": "doc",
                },
                files={"file": ("big.txt", b"x" * 100, "text/plain")},
            )
            assert response.status_code == 413

    def test_upload_storage_failure(self, client, mock_storage):
        mock_storage.upload_file.side_effect = OSError("Storage down")
        response = client.post(
            f"/projects/{PROJECT_ID}/artifacts/upload",
            data={
                "filename": "test.txt",
                "content_type": "text/plain",
                "kind": "doc",
            },
            files={"file": ("test.txt", b"data", "text/plain")},
        )
        assert response.status_code == 500
        assert "detail" in response.json()

    def test_upload_method_not_allowed_get(self, client):
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/upload")
        assert response.status_code == 405

    def test_upload_method_not_allowed_put(self, client):
        response = client.put(f"/projects/{PROJECT_ID}/artifacts/upload")
        assert response.status_code == 405

    def test_upload_method_not_allowed_delete(self, client):
        response = client.delete(f"/projects/{PROJECT_ID}/artifacts/upload")
        assert response.status_code == 405

    def test_upload_virus_scan_infected(self, client, mock_storage):
        """Test virus scanning rejects infected file."""
        from services.virus_scanner import ScanResult

        mock_scanner = MagicMock()
        mock_scanner.scan_stream.return_value = ScanResult(is_clean=False, virus_name="TestVirus")

        with (
            patch("routes.artifacts.settings") as mock_settings,
            patch("routes.artifacts.VirusScanner", return_value=mock_scanner),
        ):
            mock_settings.allowed_mimes = ["text/plain"]
            mock_settings.max_file_size_bytes = 10 * 1024 * 1024
            mock_settings.enable_virus_scanning = True
            mock_settings.quarantine_infected_files = True

            response = client.post(
                f"/projects/{PROJECT_ID}/artifacts/upload",
                data={
                    "filename": "evil.txt",
                    "content_type": "text/plain",
                    "kind": "doc",
                },
                files={"file": ("evil.txt", b"virus", "text/plain")},
            )
            assert response.status_code == 403

    def test_upload_virus_scan_error_quarantine(self, client, mock_storage):
        """Test virus scan error with quarantine rejects upload."""
        with (
            patch("routes.artifacts.settings") as mock_settings,
            patch("routes.artifacts.VirusScanner", side_effect=RuntimeError("ClamAV down")),
        ):
            mock_settings.allowed_mimes = ["text/plain"]
            mock_settings.max_file_size_bytes = 10 * 1024 * 1024
            mock_settings.enable_virus_scanning = True
            mock_settings.quarantine_infected_files = True

            response = client.post(
                f"/projects/{PROJECT_ID}/artifacts/upload",
                data={
                    "filename": "file.txt",
                    "content_type": "text/plain",
                    "kind": "doc",
                },
                files={"file": ("file.txt", b"data", "text/plain")},
            )
            assert response.status_code == 500

    def test_upload_virus_scan_error_fails_closed_without_quarantine(self, client, mock_storage):
        """A BROKEN scanner rejects the upload even with quarantine disabled.

        `quarantine_infected_files` decides what to do with a file the scanner
        CONVICTED. It must not decide what happens when the scanner itself is
        unreachable: a scan that never ran is not a clean scan, and swallowing
        the error stored the file UNSCANNED while telling the caller 200.
        """
        with (
            patch("routes.artifacts.settings") as mock_settings,
            patch("routes.artifacts.VirusScanner", side_effect=ConnectionError("ClamAV down")),
        ):
            mock_settings.allowed_mimes = ["text/plain"]
            mock_settings.max_file_size_bytes = 10 * 1024 * 1024
            mock_settings.enable_virus_scanning = True
            mock_settings.quarantine_infected_files = False

            response = client.post(
                f"/projects/{PROJECT_ID}/artifacts/upload",
                data={
                    "filename": "unscanned.txt",
                    "content_type": "text/plain",
                    "kind": "doc",
                },
                files={"file": ("unscanned.txt", b"data", "text/plain")},
            )
            assert response.status_code == 500, (
                "an unreachable scanner must fail closed regardless of the quarantine flag"
            )
            mock_storage.upload_file.assert_not_called()


class TestListArtifacts:
    """Test listing artifacts (mock-based for HTTP behavior)."""

    def test_list_empty(self, client, mock_db):
        response = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_with_artifacts(self, client, mock_db):
        art = make_mock_artifact()
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [art]
        mock_result.scalars.return_value = mock_scalars
        mock_db.execute.return_value = mock_result

        response = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["filename"] == "test.txt"


class TestGetArtifact:
    """Test getting a single artifact."""

    def test_get_found(self, client, mock_db):
        art = make_mock_artifact()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = art
        mock_db.execute.return_value = mock_result

        response = client.get(f"/projects/{PROJECT_ID}/artifacts/{art.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "test.txt"

    def test_get_not_found(self, client, mock_db):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        fake_id = str(uuid7())
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/{fake_id}")
        assert response.status_code == 404


class TestDownloadArtifact:
    """Test downloading artifacts."""

    def test_download_success(self, client, mock_db, mock_storage):
        art = make_mock_artifact()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = art
        mock_db.execute.return_value = mock_result

        response = client.get(f"/projects/{PROJECT_ID}/artifacts/{art.id}/download")
        assert response.status_code == 200
        assert response.content == b"file content here"
        assert "attachment" in response.headers.get("content-disposition", "")

    def test_download_not_found(self, client, mock_db, mock_storage):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        fake_id = str(uuid7())
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/{fake_id}/download")
        assert response.status_code == 404


class TestDeleteArtifact:
    """Test deleting artifacts."""

    def test_delete_success(self, client, mock_db, mock_storage):
        art = make_mock_artifact()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = art
        mock_db.execute.return_value = mock_result

        response = client.delete(f"/projects/{PROJECT_ID}/artifacts/{art.id}")
        assert response.status_code == 204
        # The stored object first, then its two derived renders (html, pdf).
        deleted = [c.args[0] for c in mock_storage.delete_file.call_args_list]
        assert deleted[0] == str(art.storage_key)
        assert len(deleted) == 3
        assert all(k.startswith(f"derived/{art.id}/v1/render-") for k in deleted[1:])
        mock_db.commit.assert_awaited()

    def test_delete_not_found(self, client, mock_db, mock_storage):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        fake_id = str(uuid7())
        response = client.delete(f"/projects/{PROJECT_ID}/artifacts/{fake_id}")
        assert response.status_code == 404

    def test_delete_storage_failure_still_commits(self, client, mock_db, mock_storage):
        art = make_mock_artifact()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = art
        mock_db.execute.return_value = mock_result

        mock_storage.delete_file.side_effect = OSError("Storage error")
        response = client.delete(f"/projects/{PROJECT_ID}/artifacts/{art.id}")
        assert response.status_code == 204
        mock_db.commit.assert_awaited()


class TestGetManifest:
    """Test manifest endpoint."""

    def test_project_manifest_empty(self, client, mock_db):
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 0
        assert data["scope"] == "project"

    def test_project_manifest_with_artifacts(self, client, mock_db):
        art1 = make_mock_artifact(size=100)
        art2 = make_mock_artifact(size=200, filename="b.txt")
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [art1, art2]
        mock_result.scalars.return_value = mock_scalars
        # (count, sum(size)) for the scope aggregate, consistent with the rows.
        mock_result.first.return_value = (2, 300)
        mock_db.execute.return_value = mock_result

        response = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project")
        assert response.status_code == 200
        data = response.json()
        assert data["total_count"] == 2
        assert data["total_size"] == 300

    def test_card_manifest(self, client, mock_db):
        card = str(uuid7())
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/card?scope_ref={card}")
        assert response.status_code == 200
        data = response.json()
        assert data["scope"] == "card"

    def test_step_manifest(self, client, mock_db):
        response = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/step?scope_ref=QA")
        assert response.status_code == 200
        data = response.json()
        assert data["scope"] == "step"

    def test_card_manifest_invalid_uuid(self, client, mock_db):
        response = client.get(
            f"/projects/{PROJECT_ID}/artifacts/manifests/card?scope_ref=not-a-uuid"
        )
        assert response.status_code == 400


# ============================================================================
# REAL DATABASE TESTS
# ============================================================================
# These test classes use real_app_client and db_session fixtures.
# They run against the session database (conftest: env URL or docker postgres:18).
# ============================================================================


class TestRealDbCrud:
    """CRUD tests against a real database -- no mocks for DB operations."""

    def _upload(
        self,
        client,
        filename="test.txt",
        content_type="text/plain",
        kind="doc",
        sensitivity="internal",
        tags="",
        card_id=None,
        step=None,
        container_name=None,
        content=b"hello world",
        headers=None,
    ):
        """Helper: upload a file via the API and return the response."""
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

    # ------------------------------------------------------------------
    # Upload tests
    # ------------------------------------------------------------------

    async def test_upload_creates_artifact_in_db(self, real_app_client, db_session):
        client, _storage = real_app_client
        content = b"database test content"
        resp = self._upload(client, filename="db_test.txt", content=content)
        assert resp.status_code == 200, resp.json()

        artifact_id = UUID(resp.json()["artifact_id"])

        # Verify the artifact exists in the real database
        result = await db_session.execute(select(Artifact).where(Artifact.id == artifact_id))
        artifact = result.scalar_one_or_none()
        assert artifact is not None
        assert artifact.filename == "db_test.txt"
        assert artifact.content_type == "text/plain"
        assert artifact.kind == ArtifactKind.DOC
        assert artifact.sensitivity == ArtifactSensitivity.INTERNAL
        assert artifact.size == len(content)
        assert artifact.tenant_id == TEST_TENANT_A
        assert artifact.project_id == UUID(PROJECT_ID)
        assert artifact.version == 1

    async def test_upload_sha256_is_correct(self, real_app_client, db_session):
        client, _storage = real_app_client
        content = b"known content for sha256 verification"
        expected_hash = hashlib.sha256(content).hexdigest()

        resp = self._upload(client, filename="hash_test.txt", content=content)
        assert resp.status_code == 200

        # Verify hash in response
        assert resp.json()["sha256"] == expected_hash

        # Verify hash in database
        artifact_id = UUID(resp.json()["artifact_id"])
        result = await db_session.execute(select(Artifact).where(Artifact.id == artifact_id))
        artifact = result.scalar_one_or_none()
        assert artifact is not None
        assert artifact.sha256 == expected_hash

    async def test_upload_with_tags(self, real_app_client, db_session):
        client, _storage = real_app_client
        resp = self._upload(client, filename="tagged.txt", tags="alpha,beta,gamma")
        assert resp.status_code == 200

        artifact_id = UUID(resp.json()["artifact_id"])
        result = await db_session.execute(
            select(ArtifactTag).where(ArtifactTag.artifact_id == artifact_id)
        )
        tags = result.scalars().all()
        tag_names = sorted(t.tag for t in tags)
        assert tag_names == ["alpha", "beta", "gamma"]

    # ------------------------------------------------------------------
    # List / filter tests
    # ------------------------------------------------------------------

    async def test_list_returns_uploaded_artifacts(self, real_app_client, db_session):
        client, _storage = real_app_client
        for i in range(3):
            resp = self._upload(client, filename=f"file_{i}.txt", content=f"content {i}".encode())
            assert resp.status_code == 200

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        returned_names = sorted(a["filename"] for a in data)
        assert returned_names == ["file_0.txt", "file_1.txt", "file_2.txt"]

    async def test_list_kind_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        self._upload(client, filename="doc1.txt", kind="doc", content=b"a")
        self._upload(
            client,
            filename="data.json",
            kind="json",
            content_type="application/json",
            content=b"{}",
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?kind=doc")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "doc1.txt"
        assert data[0]["kind"] == "doc"

    async def test_list_sensitivity_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        self._upload(client, filename="internal.txt", sensitivity="internal", content=b"a")
        self._upload(client, filename="secret.txt", sensitivity="secret", content=b"b")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?sensitivity=secret")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "secret.txt"
        assert data[0]["sensitivity"] == "secret"

    async def test_list_card_id_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        target_card = uuid7()
        other_card = uuid7()
        self._upload(client, filename="card_a.txt", card_id=target_card, content=b"a")
        self._upload(client, filename="card_b.txt", card_id=other_card, content=b"b")
        self._upload(client, filename="no_card.txt", content=b"c")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?card_id={target_card}")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "card_a.txt"

    async def test_list_step_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        self._upload(client, filename="qa.txt", step="QA", content=b"a")
        self._upload(client, filename="dev.txt", step="DEV", content=b"b")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?step=QA")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "qa.txt"

    async def test_list_name_prefix_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        self._upload(client, filename="common-alpha.txt", content=b"a")
        self._upload(client, filename="common-beta.txt", content=b"b")
        self._upload(client, filename="other-gamma.txt", content=b"c")

        # With prefix: only matching rows
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?name_prefix=common-")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        returned_names = sorted(a["filename"] for a in data)
        assert returned_names == ["common-alpha.txt", "common-beta.txt"]

        # Without prefix: all rows return
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    async def test_list_tags_filter_works(self, real_app_client, db_session):
        client, _storage = real_app_client
        self._upload(client, filename="urgent.txt", tags="urgent,important", content=b"a")
        self._upload(client, filename="boring.txt", tags="routine", content=b"b")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?tags=urgent")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "urgent.txt"

    async def test_list_pagination(self, real_app_client, db_session):
        client, _storage = real_app_client
        for i in range(5):
            resp = self._upload(client, filename=f"page_{i}.txt", content=f"p{i}".encode())
            assert resp.status_code == 200

        # First page: 2 items
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?limit=2&offset=0")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

        # Second page: 2 items
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?limit=2&offset=2")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

        # Third page: 1 item
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts?limit=2&offset=4")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    # ------------------------------------------------------------------
    # Get single artifact
    # ------------------------------------------------------------------

    async def test_get_artifact_by_id(self, real_app_client, db_session):
        client, _storage = real_app_client
        content = b"single artifact content"
        resp = self._upload(
            client,
            filename="single.txt",
            kind="doc",
            sensitivity="secret",
            tags="x,y",
            content=content,
        )
        assert resp.status_code == 200
        artifact_id = resp.json()["artifact_id"]

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{artifact_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == artifact_id
        assert data["filename"] == "single.txt"
        assert data["kind"] == "doc"
        assert data["sensitivity"] == "secret"
        assert data["size"] == len(content)
        assert data["sha256"] == hashlib.sha256(content).hexdigest()
        assert sorted(data["tags"]) == ["x", "y"]

    async def test_get_artifact_not_found(self, real_app_client, db_session):
        client, _storage = real_app_client
        fake_id = uuid7()
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{fake_id}")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def test_delete_artifact(self, real_app_client, db_session):
        client, _storage = real_app_client
        resp = self._upload(client, filename="doomed.txt", content=b"bye")
        assert resp.status_code == 200
        artifact_id = resp.json()["artifact_id"]

        # Delete it
        del_resp = client.delete(f"/projects/{PROJECT_ID}/artifacts/{artifact_id}")
        assert del_resp.status_code == 204

        # Verify it's gone from the database
        result = await db_session.execute(select(Artifact).where(Artifact.id == UUID(artifact_id)))
        assert result.scalar_one_or_none() is None

        # Verify listing is empty
        list_resp = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert list_resp.status_code == 200
        assert list_resp.json() == []

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    async def test_manifest_project_scope(self, real_app_client, db_session):
        client, _storage = real_app_client
        sizes = [100, 200, 300]
        for i, size in enumerate(sizes):
            content = b"x" * size
            resp = self._upload(client, filename=f"m_{i}.txt", content=content)
            assert resp.status_code == 200

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scope"] == "project"
        assert data["total_count"] == 3
        assert data["total_size"] == sum(sizes)

    async def test_manifest_card_scope(self, real_app_client, db_session):
        client, _storage = real_app_client
        card_a = uuid7()
        card_b = uuid7()
        self._upload(client, filename="ca1.txt", card_id=card_a, content=b"aa")
        self._upload(client, filename="ca2.txt", card_id=card_a, content=b"bb")
        self._upload(client, filename="cb1.txt", card_id=card_b, content=b"cc")

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/card?scope_ref={card_a}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scope"] == "card"
        assert data["total_count"] == 2
        filenames = sorted(a["filename"] for a in data["artifacts"])
        assert filenames == ["ca1.txt", "ca2.txt"]

    async def test_manifest_pages_artifacts_but_totals_cover_the_whole_scope(
        self, real_app_client, db_session
    ):
        """`limit` pages `artifacts`; `total_count`/`total_size` stay scope-wide.

        Before the bound existed the manifest materialised EVERY row in the
        scope, and `total_count` was `len(artifacts)` — so the two readings
        were indistinguishable and a truncation could not have been detected.
        This asserts both halves at once: the page is short AND the aggregates
        still describe the whole scope, which is the only thing that makes the
        short page safe.
        """
        client, _storage = real_app_client
        sizes = [11, 22, 33]
        for i, size in enumerate(sizes):
            resp = self._upload(client, filename=f"page_{i}.txt", content=b"x" * size)
            assert resp.status_code == 200

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project?limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["artifacts"]) == 2, "limit=2 must bound the manifest page"
        assert data["total_count"] == 3, "total_count must count the SCOPE, not the page"
        assert data["total_size"] == sum(sizes), "total_size must sum the SCOPE, not the page"

        # The second page is reachable and disjoint from the first.
        page2 = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project?limit=2&offset=2")
        assert page2.status_code == 200
        assert len(page2.json()["artifacts"]) == 1
        first_ids = {a["id"] for a in data["artifacts"]}
        assert first_ids.isdisjoint({a["id"] for a in page2.json()["artifacts"]})

    async def test_manifest_truncated_flag_is_true_only_when_rows_are_missing(
        self, real_app_client, db_session
    ):
        """`truncated` states the comparison outright, in BOTH directions.

        `total_count` alone leaves the client to notice a number it never
        asked for; the live n8n `getManifest` sends no pagination and reads
        neither headers nor totals. A boolean named `truncated` cannot be
        misread, so it has to be right in both directions — a flag that is
        always true, or always false, would pass a one-sided test.
        """
        client, _storage = real_app_client
        for i in range(3):
            assert self._upload(client, filename=f"trunc_{i}.txt", content=b"xy").status_code == 200

        short = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project?limit=2").json()
        assert short["truncated"] is True, "a page that misses rows must say so"
        assert 0 + len(short["artifacts"]) < short["total_count"]

        # Last page: shorter than `limit`, but it REACHES the end of the scope.
        tail = client.get(
            f"/projects/{PROJECT_ID}/artifacts/manifests/project?limit=2&offset=2"
        ).json()
        assert len(tail["artifacts"]) == 1
        assert tail["truncated"] is False, "a page that reaches the end is not truncated"

        # Default page covers this scope entirely.
        whole = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project").json()
        assert len(whole["artifacts"]) == 3
        assert whole["truncated"] is False

        # An empty scope is not truncated either.
        empty = client.get(
            f"/projects/{PROJECT_ID}/artifacts/manifests/step?scope_ref=nothing-here"
        ).json()
        assert empty["total_count"] == 0
        assert empty["truncated"] is False


class TestTenantIsolation:
    """Verify that tenant boundaries are enforced at the database query level."""

    async def test_cannot_list_other_tenant_artifacts(self, real_app_client, db_session):
        """Artifacts created by tenant-B must not appear in tenant-A's listing."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        # Create artifact directly in DB for a different tenant
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="secret_other.txt",
            project_id=UUID(PROJECT_ID),
        )

        # Default client is test-tenant -- should see nothing
        resp = client.get(f"/projects/{PROJECT_ID}/artifacts")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_cannot_get_other_tenant_artifact(self, real_app_client, db_session):
        """GET by ID must return 404 when artifact belongs to another tenant."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        other_art = await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="hidden.txt",
            project_id=UUID(PROJECT_ID),
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{other_art.id}")
        assert resp.status_code == 404

    async def test_cannot_delete_other_tenant_artifact(self, real_app_client, db_session):
        """DELETE must return 404 and leave the artifact intact for another tenant."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        other_art = await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="undeletable.txt",
            project_id=UUID(PROJECT_ID),
        )

        resp = client.delete(f"/projects/{PROJECT_ID}/artifacts/{other_art.id}")
        assert resp.status_code == 404

        # Artifact must still exist in DB
        result = await db_session.execute(select(Artifact).where(Artifact.id == other_art.id))
        assert result.scalar_one_or_none() is not None

    async def test_cannot_download_other_tenant_artifact(self, real_app_client, db_session):
        """Download must return 404 when artifact belongs to another tenant."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        other_art = await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="no_download.txt",
            project_id=UUID(PROJECT_ID),
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{other_art.id}/download")
        assert resp.status_code == 404

    async def test_own_tenant_can_access_own_artifacts(self, real_app_client, db_session):
        """Sanity check: test-tenant CAN access its own artifacts."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        own_art = await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            filename="mine.txt",
            project_id=UUID(PROJECT_ID),
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/{own_art.id}")
        assert resp.status_code == 200
        assert resp.json()["filename"] == "mine.txt"

    async def test_manifest_excludes_other_tenant(self, real_app_client, db_session):
        """Project manifest must only count artifacts for the requesting tenant."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        # Create 2 artifacts for other-tenant, 1 for test-tenant
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="other1.txt",
            project_id=UUID(PROJECT_ID),
            size=500,
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            filename="other2.txt",
            project_id=UUID(PROJECT_ID),
            size=600,
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            filename="mine.txt",
            project_id=UUID(PROJECT_ID),
            size=42,
        )

        resp = client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_count"] == 1
        assert data["total_size"] == 42


class TestListByCardCrossProject:
    """Tests for GET /api/artifacts/by-card/{card_id} — cross-project lookup."""

    async def test_returns_artifacts_from_multiple_projects(self, real_app_client, db_session):
        """Same card_id across two different projects returns BOTH artifacts."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client
        card_id = uuid7()
        project_a = uuid7()
        project_b = uuid7()

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=project_a,
            card_id=card_id,
            filename="from_a.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=project_b,
            card_id=card_id,
            filename="from_b.txt",
        )
        # Decoy: same tenant + project but different card_id, must NOT appear
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=project_a,
            card_id=uuid7(),
            filename="other_card.txt",
        )

        resp = client.get(f"/api/artifacts/by-card/{card_id}")
        assert resp.status_code == 200, resp.json()
        data = resp.json()
        assert len(data) == 2
        returned = sorted(a["filename"] for a in data)
        assert returned == ["from_a.txt", "from_b.txt"]
        # Confirm both projects are represented in the response
        returned_projects = {a["project_id"] for a in data}
        assert returned_projects == {str(project_a), str(project_b)}

    async def test_excludes_other_tenant(self, real_app_client, db_session):
        """An artifact with the same card_id but a different tenant is NOT returned."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client
        card_id = uuid7()

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            card_id=card_id,
            filename="mine.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            project_id=uuid7(),
            card_id=card_id,
            filename="theirs.txt",
        )

        resp = client.get(f"/api/artifacts/by-card/{card_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "mine.txt"

    async def test_name_prefix_filter(self, real_app_client, db_session):
        """name_prefix filters by Artifact.filename.startswith(name_prefix)."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client
        card_id = uuid7()

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            card_id=card_id,
            filename="report-2026-q1.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            card_id=card_id,
            filename="report-2026-q2.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            card_id=card_id,
            filename="other-file.txt",
        )

        # With prefix
        resp = client.get(f"/api/artifacts/by-card/{card_id}?name_prefix=report-")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        names = sorted(a["filename"] for a in data)
        assert names == ["report-2026-q1.txt", "report-2026-q2.txt"]

        # Without prefix — all 3 returned
        resp = client.get(f"/api/artifacts/by-card/{card_id}")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    async def test_no_match_returns_empty_list(self, real_app_client, db_session):
        """A card_id with no matching artifacts returns an empty list (200)."""
        client, _storage = real_app_client
        unknown_card = uuid7()

        resp = client.get(f"/api/artifacts/by-card/{unknown_card}")
        assert resp.status_code == 200
        assert resp.json() == []

    # ------------------------------------------------------------------
    # The read is BOUNDED.
    #
    # This route used to run `select(Artifact)` with no LIMIT and then
    # materialise every row, so one card with tens of thousands of artifacts
    # was a self-inflicted DoS. Its siblings (`list_artifacts`,
    # `list_artifacts_cross_project`) have always capped at `le=1000`.
    # ------------------------------------------------------------------

    async def _seed_card(self, db_session, card_id, n, size=100):
        from tests.conftest import create_test_artifact

        for i in range(n):
            await create_test_artifact(
                db_session,
                tenant_id=TEST_TENANT_A,
                project_id=uuid7(),
                card_id=card_id,
                filename=f"bulk_{i:03d}.txt",
                size=size,
            )

    async def test_limit_bounds_the_page(self, real_app_client, db_session):
        """`limit` caps the rows returned; `offset` reaches the rest."""
        client, _storage = real_app_client
        card_id = uuid7()
        await self._seed_card(db_session, card_id, 7)

        resp = client.get(f"/api/artifacts/by-card/{card_id}?limit=3")
        assert resp.status_code == 200, resp.json()
        assert len(resp.json()) == 3, "limit=3 must bound the response"

        rest = client.get(f"/api/artifacts/by-card/{card_id}?limit=3&offset=3")
        assert rest.status_code == 200
        assert len(rest.json()) == 3
        page1 = {a["id"] for a in resp.json()}
        assert page1.isdisjoint({a["id"] for a in rest.json()}), "pages must not overlap"

        tail = client.get(f"/api/artifacts/by-card/{card_id}?limit=3&offset=6")
        assert len(tail.json()) == 1

    async def test_truncation_is_not_silent(self, real_app_client, db_session):
        """A truncated page reports the FULL match count in X-Total-Count.

        Capping an endpoint that used to return everything is only honest if
        the caller can tell it was capped. Without this header a caller that
        used to receive 7 rows would receive 3 and have no way to know.
        """
        client, _storage = real_app_client
        card_id = uuid7()
        await self._seed_card(db_session, card_id, 7)

        resp = client.get(f"/api/artifacts/by-card/{card_id}?limit=3")
        assert resp.status_code == 200
        assert resp.headers.get("X-Total-Count") == "7"
        # truncated <=> offset + len(page) < total
        assert 0 + len(resp.json()) < int(resp.headers["X-Total-Count"])

        full = client.get(f"/api/artifacts/by-card/{card_id}?limit=1000")
        assert full.headers.get("X-Total-Count") == "7"
        assert len(full.json()) == 7, "an untruncated page must NOT be capped short"

    async def test_limit_is_applied_by_the_database_not_in_python(
        self, real_app_client, db_session, pg_engine
    ):
        """The LIMIT must reach SQL — a Python slice is not a bound.

        Slicing `artifacts[:limit]` after `.scalars().all()` produces exactly
        the same JSON as this fix while still scanning and hydrating every
        row, i.e. it fixes nothing. So assert on the statement postgres was
        actually asked to run.
        """
        from sqlalchemy import event

        client, _storage = real_app_client
        card_id = uuid7()
        await self._seed_card(db_session, card_id, 5)

        statements: list[str] = []

        def _capture(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(pg_engine.sync_engine, "before_cursor_execute", _capture)
        try:
            resp = client.get(f"/api/artifacts/by-card/{card_id}?limit=2")
        finally:
            event.remove(pg_engine.sync_engine, "before_cursor_execute", _capture)

        assert resp.status_code == 200
        assert len(resp.json()) == 2
        selects = [s for s in statements if "FROM artifacts" in s and "SELECT" in s]
        assert selects, f"no artifact SELECT was captured; got {statements}"
        assert any("LIMIT" in s for s in selects), (
            "the bound was not pushed into SQL — every matching row was still "
            f"fetched. Statements: {selects}"
        )

    async def test_limit_over_the_cap_is_rejected(self, real_app_client):
        """`limit=1001` is a 422, matching the sibling list endpoints' le=1000."""
        client, _storage = real_app_client
        resp = client.get(f"/api/artifacts/by-card/{uuid7()}?limit=1001")
        assert resp.status_code == 422


class TestListCrossProject:
    """Tests for GET /api/artifacts — tenant-wide cross-project list."""

    async def test_returns_all_tenant_artifacts(self, real_app_client, db_session):
        """Lists artifacts across all projects in the caller's tenant."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client
        project_a = uuid7()
        project_b = uuid7()

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=project_a,
            filename="a.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=project_b,
            filename="b.txt",
        )

        resp = client.get("/api/artifacts")
        assert resp.status_code == 200, resp.json()
        data = resp.json()
        assert len(data) == 2
        assert {a["filename"] for a in data} == {"a.txt", "b.txt"}

    async def test_excludes_other_tenant(self, real_app_client, db_session):
        """Artifacts owned by a different tenant are NOT returned."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            filename="mine.txt",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_B,
            project_id=uuid7(),
            filename="theirs.txt",
        )

        resp = client.get("/api/artifacts")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "mine.txt"

    async def test_filters_apply(self, real_app_client, db_session):
        """kind/name_prefix filters apply across the cross-project surface."""
        from tests.conftest import create_test_artifact

        client, _storage = real_app_client

        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            kind="json",
            filename="data-1.json",
        )
        await create_test_artifact(
            db_session,
            tenant_id=TEST_TENANT_A,
            project_id=uuid7(),
            kind="doc",
            filename="readme.md",
        )

        resp = client.get("/api/artifacts?kind=json")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["filename"] == "data-1.json"

        resp = client.get("/api/artifacts?name_prefix=data-")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    async def test_empty_when_no_artifacts(self, real_app_client, db_session):
        """Empty tenant returns []."""
        client, _storage = real_app_client

        resp = client.get("/api/artifacts")
        assert resp.status_code == 200
        assert resp.json() == []


class TestPlankaCardIdFromTags:
    def test_any_format_first_match_and_length_cap(self):
        from routes.artifacts import planka_card_id_from_tags

        assert planka_card_id_from_tags(["a", "planka_card:1885787636753237021"]) == (
            "1885787636753237021"
        )
        assert planka_card_id_from_tags(["planka_card:", "planka_card:abc"]) == "abc"
        assert planka_card_id_from_tags(["planka_card:" + "9" * 65]) is None
        assert planka_card_id_from_tags(["planka_card:" + "9" * 64]) == "9" * 64
        assert planka_card_id_from_tags(["run:7"]) is None
