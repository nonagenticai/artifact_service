"""The deliverable contract: an artifact must be able to say which card produced it.

⛔ WHAT THIS FILE PINS, and why it is not decoration.

MEASURED on the production database (worker4, `artifact_registry`) on
2026-09-23::

    SELECT count(*), count(card_id),
           count(*) FILTER (WHERE origin_kind <> 'tenant'),
           count(*) FILTER (WHERE created_by_user_id <> ''),
           count(*) FILTER (WHERE origin_project_id IS NOT NULL),
           count(*) FILTER (WHERE origin_workflow_run_id IS NOT NULL)
      FROM artifacts;
    -->  58573 | 0 | 0 | 0 | 0 | 0

Two DIFFERENT defects hide behind that one row of zeros, and conflating them
gets the fix wrong:

1. ``card_id`` is accepted as a form field and IS persisted by the upload route
   (it has been since the route was written). It is NULL on every row because no
   CALLER supplies it, not because the service drops it. The tests here pin that
   round trip — upload with a card, read it back by card — so that a future
   refactor cannot quietly break the one half that already works.

2. The four provenance columns added by alembic ``20260519_0002``
   (``origin_kind``, ``origin_project_id``, ``origin_workflow_run_id``,
   ``created_by_user_id``) were dead in BOTH directions. No write path could
   set them, and — worse — every ``ArtifactOut`` was constructed field by field
   in six separate places, none of which mentioned them, so a read returned the
   Pydantic DEFAULTS ('tenant', null, null, '') regardless of what the row held.
   That is not an absent value, it is a WRONG one: a caller reading
   ``origin_kind == "tenant"`` off a workflow-emitted artifact is being told
   something false, with no way to tell.

Every assertion below is written so that it can FAIL. The read-side assertions
deliberately use values that differ from the schema defaults; asserting
``origin_kind == "tenant"`` on a row inserted as 'tenant' would pass against the
broken code too, which is how this went unnoticed for four months.
"""

import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")

from uuid import UUID, uuid7

import pytest
from sqlalchemy import select

from models.artifact import Artifact
from tests.conftest import TEST_TENANT_A

PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")
ORIGIN_PROJECT_ID = UUID("22222222-2222-2222-2222-222222222222")
SUBJECT_ID = "0198c2d4-7a10-70aa-bb11-000000000001"


def _upload(client, *, filename="deliverable.txt", headers=None, **extra):
    """POST the multipart upload. `extra` goes straight onto the form."""
    data = {
        "filename": filename,
        "content_type": "text/plain",
        "kind": "doc",
        "sensitivity": "internal",
        "tags": "",
    }
    for key, value in extra.items():
        if value is not None:
            data[key] = str(value)
    return client.post(
        f"/projects/{PROJECT_ID}/artifacts/upload",
        data=data,
        files={"file": (filename, b"the deliverable", "text/plain")},
        headers=headers or {},
    )


class TestCardAssociation:
    """upload(card) -> row.card_id -> /api/artifacts/by-card/{card} finds it."""

    async def test_upload_with_a_card_persists_card_id(self, real_app_client, db_session):
        client, _storage = real_app_client
        card_id = uuid7()

        resp = _upload(client, card_id=card_id)
        assert resp.status_code == 200, resp.json()

        artifact_id = UUID(resp.json()["artifact_id"])
        row = (
            await db_session.execute(select(Artifact).where(Artifact.id == artifact_id))
        ).scalar_one()
        assert row.card_id == card_id, "the card association was not persisted"

    async def test_the_upload_response_echoes_the_persisted_card(self, real_app_client):
        """A producer must be able to tell 'recorded' from 'silently dropped'.

        Without the echo the only way to know whether the association landed is
        a second request — which is exactly why nobody noticed it was never
        being sent. Asserted against the REFRESHED ROW's value, not the input.
        """
        client, _storage = real_app_client
        card_id = uuid7()

        body = _upload(client, card_id=card_id).json()
        assert body["card_id"] == str(card_id)

    async def test_by_card_read_returns_the_artifact_just_uploaded(self, real_app_client):
        """The whole contract end to end, through the baked cross-project route."""
        client, _storage = real_app_client
        card_id = uuid7()

        mine = UUID(_upload(client, filename="mine.txt", card_id=card_id).json()["artifact_id"])
        # A second artifact on a DIFFERENT card. Without it a by-card route that
        # ignored its filter entirely would still pass this test.
        other = UUID(_upload(client, filename="other.txt", card_id=uuid7()).json()["artifact_id"])

        resp = client.get(f"/api/artifacts/by-card/{card_id}")
        assert resp.status_code == 200, resp.json()
        returned = {UUID(a["id"]) for a in resp.json()}
        assert mine in returned
        assert other not in returned, "by-card returned an artifact from another card"
        assert resp.json()[0]["card_id"] == str(card_id)

    async def test_an_upload_with_no_card_stays_null_explicitly(self, real_app_client, db_session):
        """Human library uploads and system artefacts have NO card.

        NULL is the correct answer for them; this pins that the route does not
        invent an association (e.g. defaulting card_id to the project) to make
        the column look populated.
        """
        client, _storage = real_app_client

        resp = _upload(client, filename="library.txt")
        assert resp.status_code == 200, resp.json()
        assert resp.json()["card_id"] is None

        artifact_id = UUID(resp.json()["artifact_id"])
        row = (
            await db_session.execute(select(Artifact).where(Artifact.id == artifact_id))
        ).scalar_one()
        assert row.card_id is None


class TestProvenanceIsWritten:
    """The four columns from alembic 20260519_0002, which nothing ever wrote."""

    async def test_workflow_origin_is_persisted(self, real_app_client, db_session):
        client, _storage = real_app_client

        resp = _upload(
            client,
            card_id=uuid7(),
            origin_kind="workflow",
            origin_workflow_run_id="n8n:exec:481922",
            created_by_user_id=SUBJECT_ID,
        )
        assert resp.status_code == 200, resp.json()

        row = (
            await db_session.execute(
                select(Artifact).where(Artifact.id == UUID(resp.json()["artifact_id"]))
            )
        ).scalar_one()
        # Every one of these differs from the column default, so the assertion
        # can actually fail.
        assert row.origin_kind == "workflow"
        assert row.origin_workflow_run_id == "n8n:exec:481922"
        assert row.origin_project_id is None
        assert row.created_by_user_id == SUBJECT_ID

    async def test_project_origin_is_persisted(self, real_app_client, db_session):
        client, _storage = real_app_client

        resp = _upload(
            client,
            origin_kind="project",
            origin_project_id=ORIGIN_PROJECT_ID,
        )
        assert resp.status_code == 200, resp.json()

        row = (
            await db_session.execute(
                select(Artifact).where(Artifact.id == UUID(resp.json()["artifact_id"]))
            )
        ).scalar_one()
        assert row.origin_kind == "project"
        assert row.origin_project_id == ORIGIN_PROJECT_ID
        assert row.origin_workflow_run_id is None

    async def test_created_by_user_id_defaults_to_the_authenticated_subject(
        self, real_app_client, db_session
    ):
        """Omitted != empty. An omitted field inherits X-Subject-Id."""
        client, _storage = real_app_client

        resp = _upload(client, headers={"X-Subject-Id": SUBJECT_ID})
        assert resp.status_code == 200, resp.json()

        row = (
            await db_session.execute(
                select(Artifact).where(Artifact.id == UUID(resp.json()["artifact_id"]))
            )
        ).scalar_one()
        assert row.created_by_user_id == SUBJECT_ID

    async def test_an_empty_creator_on_the_wire_is_indistinguishable_from_omitted(
        self, real_app_client, db_session
    ):
        """⚠️ MEASURED BEHAVIOUR, pinned so nobody documents the opposite.

        A multipart field sent with an EMPTY value is genuinely on the wire
        (``Content-Disposition: name="created_by_user_id"`` with an empty body),
        but FastAPI's form parser reports it as ABSENT — a required
        ``str = Form(...)`` 422s against it with ``type: "missing"``. So this
        endpoint CANNOT offer an empty-vs-omitted distinction, and an empty
        value inherits the subject exactly as an omitted one does.

        Asserted rather than left implicit because the natural comment to write
        here ("None means omitted, '' stays empty") is FALSE, and a false
        comment about a provenance field is how a provenance field goes wrong.
        """
        client, _storage = real_app_client

        resp = _upload(client, created_by_user_id="", headers={"X-Subject-Id": SUBJECT_ID})
        assert resp.status_code == 200, resp.json()

        row = (
            await db_session.execute(
                select(Artifact).where(Artifact.id == UUID(resp.json()["artifact_id"]))
            )
        ).scalar_one()
        assert row.created_by_user_id == SUBJECT_ID

    async def test_a_tenant_only_caller_records_an_empty_creator(self, real_app_client, db_session):
        """No X-Subject-Id at all -> '' (the column's documented legacy value).

        The negative control for the default-to-subject test: if the route
        hard-coded a creator, or fell back to tenant_id the way `created_by`
        does, this would not be ''.
        """
        client, _storage = real_app_client

        resp = _upload(client)
        assert resp.status_code == 200, resp.json()

        row = (
            await db_session.execute(
                select(Artifact).where(Artifact.id == UUID(resp.json()["artifact_id"]))
            )
        ).scalar_one()
        assert row.created_by_user_id == ""


class TestProvenanceIsReadBack:
    """A write nobody can observe is not a contract. Three read paths."""

    async def test_get_artifact_returns_the_real_provenance(self, real_app_client):
        client, _storage = real_app_client

        artifact_id = _upload(
            client,
            origin_kind="workflow",
            origin_workflow_run_id="n8n:exec:7",
            created_by_user_id=SUBJECT_ID,
        ).json()["artifact_id"]

        body = client.get(f"/projects/{PROJECT_ID}/artifacts/{artifact_id}").json()
        assert body["origin_kind"] == "workflow"
        assert body["origin_workflow_run_id"] == "n8n:exec:7"
        assert body["created_by_user_id"] == SUBJECT_ID

    async def test_list_artifacts_returns_the_real_provenance(self, real_app_client):
        client, _storage = real_app_client

        _upload(
            client,
            filename="listed.txt",
            origin_kind="project",
            origin_project_id=ORIGIN_PROJECT_ID,
        )

        body = client.get(f"/projects/{PROJECT_ID}/artifacts").json()
        assert len(body) == 1
        assert body[0]["origin_kind"] == "project"
        assert body[0]["origin_project_id"] == str(ORIGIN_PROJECT_ID)

    async def test_by_card_read_returns_the_real_provenance(self, real_app_client):
        """The route the improvement loop actually calls."""
        client, _storage = real_app_client
        card_id = uuid7()

        _upload(
            client,
            card_id=card_id,
            origin_kind="workflow",
            origin_workflow_run_id="n8n:exec:99",
            created_by_user_id=SUBJECT_ID,
        )

        body = client.get(f"/api/artifacts/by-card/{card_id}").json()
        assert len(body) == 1
        assert body[0]["card_id"] == str(card_id)
        assert body[0]["origin_kind"] == "workflow"
        assert body[0]["origin_workflow_run_id"] == "n8n:exec:99"
        assert body[0]["created_by_user_id"] == SUBJECT_ID

    async def test_manifest_returns_the_real_provenance(self, real_app_client):
        client, _storage = real_app_client
        card_id = uuid7()

        _upload(
            client,
            card_id=card_id,
            origin_kind="workflow",
            origin_workflow_run_id="n8n:exec:manifest",
        )

        body = client.get(
            f"/projects/{PROJECT_ID}/artifacts/manifests/card",
            params={"scope_ref": str(card_id)},
        ).json()
        assert body["total_count"] == 1
        assert body["artifacts"][0]["origin_workflow_run_id"] == "n8n:exec:manifest"


class TestInconsistentProvenanceIsRefusedAtTheBoundary:
    """The DB holds the same rule as a CHECK. A 400 beats a 500 on COMMIT."""

    @pytest.mark.parametrize(
        ("form", "needle"),
        [
            ({"origin_kind": "project"}, "requires origin_project_id"),
            (
                {"origin_kind": "workflow"},
                "requires origin_workflow_run_id",
            ),
            (
                {
                    "origin_kind": "tenant",
                    "origin_workflow_run_id": "n8n:exec:1",
                },
                "to be null",
            ),
            (
                {
                    "origin_kind": "project",
                    "origin_project_id": str(ORIGIN_PROJECT_ID),
                    "origin_workflow_run_id": "n8n:exec:1",
                },
                "must not carry origin_workflow_run_id",
            ),
            ({"origin_kind": "nonsense"}, "origin_kind must be one of"),
        ],
    )
    async def test_inconsistent_origin_is_400(self, real_app_client, form, needle):
        client, _storage = real_app_client

        resp = _upload(client, **form)
        assert resp.status_code == 400, resp.text
        assert needle in resp.json()["detail"]

    async def test_nothing_is_stored_when_provenance_is_refused(self, real_app_client, db_session):
        """The refusal happens BEFORE the file is read or pushed to storage."""
        client, storage = real_app_client

        resp = _upload(client, origin_kind="project")
        assert resp.status_code == 400
        assert storage.upload_file.call_count == 0

        rows = (await db_session.execute(select(Artifact))).scalars().all()
        assert len(rows) == 0

    async def test_an_over_long_workflow_run_id_is_400_not_500(self, real_app_client):
        client, _storage = real_app_client

        resp = _upload(client, origin_kind="workflow", origin_workflow_run_id="x" * 201)
        assert resp.status_code == 400, resp.text
        assert "200 characters" in resp.json()["detail"]


class TestTenantScopingStillHolds:
    """Provenance must not become a way around tenant isolation."""

    async def test_by_card_does_not_cross_tenants(self, real_app_client):
        from tests.conftest import TEST_TENANT_B

        client, _storage = real_app_client
        card_id = uuid7()

        _upload(client, card_id=card_id, headers={"X-Test-Tenant": TEST_TENANT_A})

        same_tenant = client.get(
            f"/api/artifacts/by-card/{card_id}", headers={"X-Test-Tenant": TEST_TENANT_A}
        )
        other_tenant = client.get(
            f"/api/artifacts/by-card/{card_id}", headers={"X-Test-Tenant": TEST_TENANT_B}
        )
        assert len(same_tenant.json()) == 1
        assert other_tenant.json() == []
