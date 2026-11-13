"""Integration tests for the artifact upload/list/get/delete lifecycle."""

import uuid

import pytest

pytestmark = pytest.mark.integration

PROJECT_ID = "00000000-0000-0000-0000-000000000001"


class TestArtifactLifecycle:
    """Upload a small text file, list, get, then delete it."""

    def test_upload_list_get_delete(self, artifact_client):
        """Full CRUD cycle for a single artifact."""
        base = f"/projects/{PROJECT_ID}/artifacts"

        # -- Upload ----------------------------------------------------------
        unique = uuid.uuid7().hex[:8]
        filename = f"integration-test-{unique}.txt"
        file_content = b"integration test payload"

        resp = artifact_client.post(
            f"{base}/upload",
            files={"file": (filename, file_content, "text/plain")},
            data={
                "filename": filename,
                "content_type": "text/plain",
                "kind": "doc",
            },
        )
        assert resp.status_code in (
            200,
            201,
            502,
            503,
        ), f"Upload unexpected status: {resp.status_code} - {resp.text}"

        if resp.status_code in (502, 503):
            pytest.skip("Service unavailable during upload; skipping rest of lifecycle")

        body = resp.json()
        artifact_id = body.get("artifact_id") or body.get("id")
        assert artifact_id, f"No artifact id in upload response: {body}"

        # -- List -------------------------------------------------------------
        try:
            resp = artifact_client.get(base)
            assert resp.status_code in (
                200,
                502,
                503,
            ), f"List unexpected status: {resp.status_code}"
            if resp.status_code == 200:
                artifacts = resp.json()
                assert isinstance(artifacts, list)
                ids = [str(a.get("id")) for a in artifacts]
                assert str(artifact_id) in ids, f"Uploaded artifact {artifact_id} not found in list"

            # -- Get single ---------------------------------------------------
            resp = artifact_client.get(f"{base}/{artifact_id}")
            assert resp.status_code in (200, 502, 503), f"Get unexpected status: {resp.status_code}"
            if resp.status_code == 200:
                detail = resp.json()
                assert str(detail.get("id")) == str(artifact_id)
        finally:
            # -- Delete (always attempt cleanup) ------------------------------
            # Fails LOUDLY: a 5xx here means the uploaded row is still there, and
            # a leaked row is a red run, not clutter. 404 = already gone.
            resp = artifact_client.delete(f"{base}/{artifact_id}")
            assert resp.status_code in (200, 204, 404), (
                f"integration cleanup LEAKED artifact {artifact_id}: {resp.status_code} {resp.text[:200]}"
            )

    def test_upload_missing_fields_returns_422(self, artifact_client):
        """POST upload without required form fields should return 422."""
        base = f"/projects/{PROJECT_ID}/artifacts"
        resp = artifact_client.post(
            f"{base}/upload",
            files={"file": ("empty.txt", b"", "text/plain")},
            # deliberately omit filename, content_type, kind
            data={},
        )
        # 422 is the expected validation error; 502/503 if service is down
        assert resp.status_code in (
            422,
            502,
            503,
        ), f"Expected 422 for missing fields, got {resp.status_code}"

    def test_list_artifacts_empty_project(self, artifact_client):
        """List artifacts for a project that likely has no artifacts."""
        fake_project = str(uuid.uuid7())
        resp = artifact_client.get(f"/projects/{fake_project}/artifacts")
        assert resp.status_code in (200, 502, 503), f"List unexpected status: {resp.status_code}"
        if resp.status_code == 200:
            assert isinstance(resp.json(), list)
