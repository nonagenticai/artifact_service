"""Tests for StorageService HTTP client."""

import io
from unittest.mock import MagicMock, patch
from uuid import UUID

import httpx
import pytest

from services.storage_service import StorageService


@pytest.fixture
def mock_settings():
    """Provide mock settings for StorageService."""
    with patch("services.storage_service.get_settings") as mock:
        settings = MagicMock()
        settings.storage_service_url = "http://test-storage:8391"
        settings.storage_bucket = "test-bucket"
        mock.return_value = settings
        yield settings


@pytest.fixture
def storage(mock_settings):
    """Create StorageService with mocked settings."""
    return StorageService()


class TestStorageServiceInit:
    """Test StorageService initialization."""

    def test_init_strips_trailing_slash(self, mock_settings):
        mock_settings.storage_service_url = "http://test-storage:8391/"
        svc = StorageService()
        assert svc.base_url == "http://test-storage:8391"

    def test_init_stores_bucket(self, mock_settings):
        svc = StorageService()
        assert svc.bucket == "test-bucket"

    def test_client_starts_none(self, storage):
        assert storage._client is None


class TestGetClient:
    """Test lazy HTTP client creation."""

    def test_creates_client_on_first_call(self, storage):
        client = storage._get_client()
        assert isinstance(client, httpx.Client)

    def test_returns_same_client_on_subsequent_calls(self, storage):
        client1 = storage._get_client()
        client2 = storage._get_client()
        assert client1 is client2


class TestGenerateStorageKey:
    """Test storage key generation."""

    def test_valid_card_scope(self, storage):
        key = storage.generate_storage_key(
            project_id=UUID("12345678-1234-1234-1234-123456789abc"),
            scope="card",
            scope_ref="ref123",
            artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
            version=1,
            filename="test.pdf",
        )
        assert (
            key
            == "projects/12345678-1234-1234-1234-123456789abc/card/ref123/abcdef01-2345-6789-abcd-ef0123456789/v1/test.pdf"
        )

    def test_valid_step_scope(self, storage):
        key = storage.generate_storage_key(
            project_id=UUID("12345678-1234-1234-1234-123456789abc"),
            scope="step",
            scope_ref="QA-validation",
            artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
            version=2,
            filename="report.json",
        )
        assert "step/QA-validation" in key
        assert "/v2/" in key

    def test_valid_project_scope(self, storage):
        key = storage.generate_storage_key(
            project_id=UUID("12345678-1234-1234-1234-123456789abc"),
            scope="project",
            scope_ref="_",
            artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
            version=1,
            filename="data.csv",
        )
        assert "project/_" in key

    def test_invalid_scope_raises(self, storage):
        with pytest.raises(ValueError, match="Invalid scope"):
            storage.generate_storage_key(
                project_id=UUID("12345678-1234-1234-1234-123456789abc"),
                scope="invalid",
                scope_ref="ref",
                artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
                version=1,
                filename="f.txt",
            )

    def test_traversal_in_scope_ref_raises(self, storage):
        with pytest.raises(ValueError, match="invalid characters"):
            storage.generate_storage_key(
                project_id=UUID("12345678-1234-1234-1234-123456789abc"),
                scope="card",
                scope_ref="../etc",
                artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
                version=1,
                filename="f.txt",
            )

    def test_null_byte_in_scope_ref_raises(self, storage):
        with pytest.raises(ValueError, match="invalid characters"):
            storage.generate_storage_key(
                project_id=UUID("12345678-1234-1234-1234-123456789abc"),
                scope="card",
                scope_ref="ref\x00bad",
                artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
                version=1,
                filename="f.txt",
            )

    def test_non_alphanumeric_scope_ref_raises(self, storage):
        with pytest.raises(ValueError, match="alphanumeric"):
            storage.generate_storage_key(
                project_id=UUID("12345678-1234-1234-1234-123456789abc"),
                scope="card",
                scope_ref="ref with spaces",
                artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
                version=1,
                filename="f.txt",
            )

    def test_too_long_scope_ref_raises(self, storage):
        with pytest.raises(ValueError, match="too long"):
            storage.generate_storage_key(
                project_id=UUID("12345678-1234-1234-1234-123456789abc"),
                scope="card",
                scope_ref="a" * 101,
                artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
                version=1,
                filename="f.txt",
            )

    def test_filename_path_stripped(self, storage):
        key = storage.generate_storage_key(
            project_id=UUID("12345678-1234-1234-1234-123456789abc"),
            scope="card",
            scope_ref="ref123",
            artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
            version=1,
            filename="/etc/passwd",
        )
        assert key.endswith("passwd")
        assert "/etc/" not in key

    def test_filename_spaces_replaced(self, storage):
        key = storage.generate_storage_key(
            project_id=UUID("12345678-1234-1234-1234-123456789abc"),
            scope="card",
            scope_ref="ref123",
            artifact_id=UUID("abcdef01-2345-6789-abcd-ef0123456789"),
            version=1,
            filename="my file.pdf",
        )
        assert "my_file.pdf" in key


class TestUploadFile:
    """Test file upload via HTTP."""

    def test_upload_success(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        storage._client = mock_client

        storage.upload_file(
            storage_key="projects/test/v1/file.txt",
            file_data=io.BytesIO(b"hello"),
            size=5,
            content_type="text/plain",
        )

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/api/files/upload"

    def test_upload_with_raw_bytes(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        storage._client = mock_client

        storage.upload_file(
            storage_key="key",
            file_data=b"raw bytes",
            size=9,
            content_type="application/octet-stream",
        )

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/api/files/upload"
        # Verify form data contains the correct bucket and object_key
        post_data = call_args[1]["data"]
        assert post_data["bucket"] == "test-bucket"
        assert post_data["object_key"] == "key"
        assert post_data["content_type"] == "application/octet-stream"

    def test_upload_raises_on_http_error(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=MagicMock()
        )

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response
        storage._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            storage.upload_file(
                storage_key="key",
                file_data=io.BytesIO(b"data"),
                size=4,
                content_type="text/plain",
            )


class TestDownloadFile:
    """Test file download via HTTP."""

    def test_download_success(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.content = b"file contents"

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        result = storage.download_file("some/key")
        assert result == b"file contents"
        mock_client.get.assert_called_once_with("/api/files/test-bucket/some/key")


class TestDeleteFile:
    """Test file deletion via HTTP."""

    def test_delete_success_204(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 204

        mock_client = MagicMock()
        mock_client.delete.return_value = mock_response
        storage._client = mock_client

        storage.delete_file("some/key")
        mock_client.delete.assert_called_once_with("/api/files/test-bucket/some/key")

    def test_delete_success_404(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = MagicMock()
        mock_client.delete.return_value = mock_response
        storage._client = mock_client

        storage.delete_file("some/key")  # Should not raise
        mock_client.delete.assert_called_once_with("/api/files/test-bucket/some/key")
        # Verify raise_for_status was NOT called (404 is acceptable for delete)
        mock_response.raise_for_status.assert_not_called()

    def test_delete_raises_on_500(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=MagicMock()
        )

        mock_client = MagicMock()
        mock_client.delete.return_value = mock_response
        storage._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            storage.delete_file("some/key")


class TestFileExists:
    """Test file existence check via HTTP."""

    def test_exists_true(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"exists": True}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.file_exists("some/key") is True

    def test_exists_false_from_json(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"exists": False}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.file_exists("some/key") is False

    def test_exists_false_on_404(self, storage):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 404
        error = httpx.HTTPStatusError("Not Found", request=MagicMock(), response=mock_resp)

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = error

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.file_exists("some/key") is False

    def test_exists_raises_on_500(self, storage):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 500
        error = httpx.HTTPStatusError("Server Error", request=MagicMock(), response=mock_resp)

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = error

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            storage.file_exists("some/key")


class TestGetFileInfo:
    """Test file info retrieval."""

    def test_get_file_info(self, storage):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "size": 1024,
            "etag": "abc",
            "content_type": "text/plain",
            "last_modified": "2024-01-01",
            "metadata": {"key": "val"},
        }

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        result = storage.get_file_info("some/key")
        assert result["size"] == 1024
        assert result["etag"] == "abc"
        assert result["content_type"] == "text/plain"
        assert result["metadata"] == {"key": "val"}


class TestHealthCheck:
    """Test health check."""

    def test_healthy(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.health_check() is True

    def test_degraded_is_healthy(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "degraded"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.health_check() is True

    def test_unhealthy_status(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "unhealthy"}

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.health_check() is False

    def test_non_200_returns_false(self, storage):
        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        storage._client = mock_client

        assert storage.health_check() is False

    def test_exception_returns_false(self, storage):
        mock_client = MagicMock()
        mock_client.get.side_effect = OSError("Connection refused")
        storage._client = mock_client

        assert storage.health_check() is False


class TestCleanup:
    """Test HTTP client cleanup."""

    def test_cleanup_closes_client(self, storage):
        mock_client = MagicMock()
        storage._client = mock_client

        storage.cleanup()
        mock_client.close.assert_called_once()
        assert storage._client is None

    def test_cleanup_noop_when_no_client(self, storage):
        assert storage._client is None
        storage.cleanup()  # Should not raise
        assert storage._client is None  # Still None after cleanup
