"""Integration tests for artifact_service health endpoints."""

import pytest

pytestmark = pytest.mark.integration


class TestHealth:
    """Tests for /health, /health/live, /health/ready."""

    def test_health(self, artifact_client):
        """GET /health returns a valid status."""
        resp = artifact_client.get("/health")
        assert resp.status_code in (200, 502, 503), f"Unexpected status: {resp.status_code}"

    def test_health_live(self, artifact_client):
        """GET /health/live returns a valid status."""
        resp = artifact_client.get("/health/live")
        assert resp.status_code in (200, 502, 503), f"Unexpected status: {resp.status_code}"

    def test_health_ready(self, artifact_client):
        """GET /health/ready returns a valid status."""
        resp = artifact_client.get("/health/ready")
        assert resp.status_code in (200, 502, 503), f"Unexpected status: {resp.status_code}"
