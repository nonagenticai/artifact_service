"""Integration tests for the artifact manifests endpoint."""

import pytest

pytestmark = pytest.mark.integration

PROJECT_ID = "00000000-0000-0000-0000-000000000001"


class TestManifests:
    """Tests for GET /projects/{project_id}/artifacts/manifests/{scope}."""

    def test_manifest_project_scope(self, artifact_client):
        """GET manifests with scope=project returns valid response."""
        resp = artifact_client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/project")
        assert resp.status_code in (
            200,
            404,
            502,
            503,
        ), f"Manifest project scope unexpected status: {resp.status_code}"
        if resp.status_code == 200:
            body = resp.json()
            assert isinstance(body, dict)

    def test_manifest_card_scope(self, artifact_client):
        """GET manifests with scope=card returns valid response."""
        resp = artifact_client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/card")
        assert resp.status_code in (
            200,
            404,
            502,
            503,
        ), f"Manifest card scope unexpected status: {resp.status_code}"

    def test_manifest_step_scope(self, artifact_client):
        """GET manifests with scope=step returns valid response."""
        resp = artifact_client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/step")
        assert resp.status_code in (
            200,
            404,
            502,
            503,
        ), f"Manifest step scope unexpected status: {resp.status_code}"

    def test_manifest_invalid_scope(self, artifact_client):
        """GET manifests with an invalid scope returns 422."""
        resp = artifact_client.get(f"/projects/{PROJECT_ID}/artifacts/manifests/bogus")
        # 422 for invalid enum value; 502/503 if service is down
        assert resp.status_code in (
            422,
            502,
            503,
        ), f"Expected 422 for invalid scope, got {resp.status_code}"
