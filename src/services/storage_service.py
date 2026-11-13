"""
Storage service client for artifact management.

Calls the storage_service API instead of connecting directly to MinIO.
All file operations are proxied through storage_service which handles
MinIO credentials and virus scanning.
"""

import io
import logging
import re
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote
from uuid import UUID

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)


class StorageService:
    """
    HTTP client for storage_service API.

    All storage operations go through the storage_service API which:
    - Is the ONLY service with MinIO credentials
    - Handles virus scanning on uploads
    - Proxies all file operations
    """

    def __init__(self) -> None:
        """Initialize storage service client."""
        settings = get_settings()
        self.base_url = settings.storage_service_url.rstrip("/")
        self.bucket = settings.storage_bucket
        self._client: httpx.Client | None = None

        logger.info(f"StorageService initialized: {self.base_url}, bucket={self.bucket}")

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=httpx.Timeout(120.0),
            )
        return self._client

    def generate_storage_key(
        self,
        project_id: UUID,
        scope: str,
        scope_ref: str,
        artifact_id: UUID,
        version: int,
        filename: str,
    ) -> str:
        """
        Generate storage key for artifact.

        Format: projects/{project_id}/{scope}/{scope_ref}/{artifact_id}/v{version}/{filename}
        """
        # Validate scope
        allowed_scopes = {"project", "card", "step"}
        if scope not in allowed_scopes:
            raise ValueError(f"Invalid scope: {scope}")

        # Sanitize scope_ref - prevent injection attacks
        decoded_ref = unquote(unquote(scope_ref))
        if any(p in decoded_ref.lower() for p in ["..", "/", "\\", "\x00"]):
            raise ValueError("scope_ref contains invalid characters")
        if not re.match(r"^[a-zA-Z0-9_-]+$", decoded_ref):
            raise ValueError("scope_ref must be alphanumeric with hyphens/underscores only")
        if len(decoded_ref) > 100:
            raise ValueError("scope_ref too long")

        # Sanitize filename - strip ALL path components to prevent traversal
        safe_filename = Path(filename).name.replace(" ", "_")
        return (
            f"projects/{project_id}/{scope}/{decoded_ref}/{artifact_id}/v{version}/{safe_filename}"
        )

    def upload_file(
        self,
        storage_key: str,
        file_data: BinaryIO,
        size: int,
        content_type: str,
    ) -> None:
        """Upload a file to storage via storage_service API."""
        client = self._get_client()

        # Read the file data
        if hasattr(file_data, "read"):
            data = file_data.read()
        else:
            data = file_data

        files = {"file": ("upload", io.BytesIO(data), content_type)}
        form_data = {
            "bucket": self.bucket,
            "object_key": storage_key,
            "content_type": content_type,
        }

        response = client.post("/api/files/upload", files=files, data=form_data)
        response.raise_for_status()

        logger.info(f"Uploaded file to: {storage_key}")

    def download_file(self, storage_key: str) -> bytes:
        """Download a file from storage via storage_service API."""
        client = self._get_client()

        response = client.get(f"/api/files/{self.bucket}/{storage_key}")
        response.raise_for_status()

        logger.debug(f"Downloaded file from: {storage_key}")
        return response.content

    def delete_file(self, storage_key: str) -> None:
        """Delete a file from storage via storage_service API."""
        client = self._get_client()

        response = client.delete(f"/api/files/{self.bucket}/{storage_key}")
        if response.status_code not in (204, 404):
            response.raise_for_status()

        logger.info(f"Deleted file: {storage_key}")

    def file_exists(self, storage_key: str) -> bool:
        """Check if a file exists in storage."""
        client = self._get_client()

        try:
            response = client.get(f"/api/files/{self.bucket}/{storage_key}/exists")
            response.raise_for_status()
            result: bool = response.json().get("exists", False)
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return False
            raise

    def get_file_info(self, storage_key: str) -> dict[str, Any]:
        """Get metadata about a file in storage."""
        client = self._get_client()

        response = client.get(f"/api/files/{self.bucket}/{storage_key}/metadata")
        response.raise_for_status()

        data = response.json()
        return {
            "size": data.get("size"),
            "etag": data.get("etag"),
            "content_type": data.get("content_type"),
            "last_modified": data.get("last_modified"),
            "metadata": data.get("metadata", {}),
        }

    def health_check(self) -> bool:
        """Check storage service health."""
        client = self._get_client()

        try:
            response = client.get("/health")
            if response.status_code == 200:
                data = response.json()
                return data.get("status") in ("healthy", "degraded")
            return False
        except (httpx.HTTPError, OSError) as e:
            logger.error(f"Storage health check failed: {e}")
            return False

    def cleanup(self) -> None:
        """Cleanup HTTP client resources."""
        if self._client:
            self._client.close()
            self._client = None
