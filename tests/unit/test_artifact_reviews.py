"""Tests for the artifact review workflow.

Covers:
- POST /projects/{p}/artifacts/{id}/review with approve / reject / revise
- Artifact.status reflects the latest review
- Review history is preserved in order
- GET /projects/{p}/artifacts/{id}/reviews returns the history
- Cross-tenant submitter is rejected (404 — visibility scoping)
- Unknown artifact returns 404
- Invalid decision rejected at validation (422)
- Comment longer than 4000 chars is rejected (422)
"""

import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("ENABLE_AUTH", "false")
os.environ.setdefault("ENABLE_VIRUS_SCANNING", "false")

import pytest  # noqa: E402

from tests.conftest import TEST_TENANT_A, TEST_TENANT_B, create_test_artifact  # noqa: E402

PROJECT_A = "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_approve_sets_status_and_records_review(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))

    resp = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "approve", "comment": "looks good"},
        headers={"X-Subject-Id": "reviewer-1"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["artifact"]["status"] == "approved"
    assert body["review"]["decision"] == "approve"
    assert body["review"]["comment"] == "looks good"
    assert body["review"]["reviewer_id"] == "reviewer-1"


@pytest.mark.asyncio
async def test_revise_then_reject_updates_to_latest(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))

    r1 = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "revise", "comment": "fix typo on slide 3"},
        headers={"X-Subject-Id": "reviewer-1"},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["artifact"]["status"] == "needs_revision"

    r2 = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "reject"},
        headers={"X-Subject-Id": "reviewer-2"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["artifact"]["status"] == "rejected"

    # History should now have 2 rows, in submission order.
    hist = client.get(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews",
        headers={"X-Subject-Id": "reviewer-1"},
    )
    assert hist.status_code == 200, hist.text
    rows = hist.json()
    assert [r["decision"] for r in rows] == ["revise", "reject"]
    assert rows[0]["comment"] == "fix typo on slide 3"
    assert rows[1]["comment"] is None


@pytest.mark.asyncio
async def test_review_unknown_artifact_404(real_app_client, db_session):
    client, _ = real_app_client
    bogus = "99999999-9999-9999-9999-999999999999"
    resp = client.post(
        f"/projects/{PROJECT_A}/artifacts/{bogus}/review",
        json={"decision": "approve"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_review_returns_404(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(
        db_session,
        project_id=__import__("uuid").UUID(PROJECT_A),
        tenant_id=TEST_TENANT_A,
    )

    # Caller is in a different tenant — visibility_scope drops the row,
    # endpoint must return 404 (not 403) to avoid leaking existence.
    resp = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "approve"},
        headers={"X-Test-Tenant": TEST_TENANT_B},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_decision_422(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    resp = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "rubber-stamp"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_comment_too_long_422(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    resp = client.post(
        f"/projects/{PROJECT_A}/artifacts/{art.id}/review",
        json={"decision": "approve", "comment": "x" * 4001},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_reviews_list_unknown_artifact_404(real_app_client, db_session):
    client, _ = real_app_client
    bogus = "99999999-9999-9999-9999-999999999999"
    resp = client.get(f"/projects/{PROJECT_A}/artifacts/{bogus}/reviews")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reviews_list_empty_for_unreviewed_artifact(real_app_client, db_session):
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    resp = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews")
    assert resp.status_code == 200
    assert resp.json() == []


# ----------------------------------------------------------------------
# The review history read is BOUNDED.
#
# `list_artifact_reviews` was the third unbounded `scalars().all()` in
# src/routes/artifacts.py: every review row for an artifact, no LIMIT, on a
# table that only ever grows. Same defect, same fix as the by-card and
# manifest routes.
# ----------------------------------------------------------------------


def _submit_reviews(client, artifact_id, n):
    """Submit `n` reviews so the history has something to page over."""
    for i in range(n):
        resp = client.post(
            f"/projects/{PROJECT_A}/artifacts/{artifact_id}/review",
            json={"decision": "revise", "comment": f"round {i}"},
            headers={"X-Subject-Id": f"reviewer-{i}"},
        )
        assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_reviews_list_limit_bounds_the_page(real_app_client, db_session):
    """`limit` caps the history page and `offset` reaches the rest."""
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    _submit_reviews(client, art.id, 5)

    resp = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews?limit=2")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) == 2, "limit=2 must bound the review history"
    # Oldest-first ordering is preserved by the bound.
    assert [r["comment"] for r in resp.json()] == ["round 0", "round 1"]

    rest = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews?limit=2&offset=2")
    assert [r["comment"] for r in rest.json()] == ["round 2", "round 3"]


@pytest.mark.asyncio
async def test_reviews_list_truncation_is_not_silent(real_app_client, db_session):
    """A truncated history page reports the full count in X-Total-Count."""
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    _submit_reviews(client, art.id, 5)

    resp = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews?limit=2")
    assert resp.headers.get("X-Total-Count") == "5"
    assert 0 + len(resp.json()) < int(resp.headers["X-Total-Count"])

    full = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews")
    assert full.headers.get("X-Total-Count") == "5"
    assert len(full.json()) == 5, "the default page must not truncate 5 rows"


@pytest.mark.asyncio
async def test_reviews_list_limit_is_applied_by_the_database(
    real_app_client, db_session, pg_engine
):
    """The LIMIT must reach SQL — a Python slice is not a bound."""
    from sqlalchemy import event

    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    _submit_reviews(client, art.id, 4)

    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(pg_engine.sync_engine, "before_cursor_execute", _capture)
    try:
        resp = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews?limit=2")
    finally:
        event.remove(pg_engine.sync_engine, "before_cursor_execute", _capture)

    assert resp.status_code == 200
    assert len(resp.json()) == 2
    selects = [s for s in statements if "FROM artifact_reviews" in s and "SELECT" in s]
    assert selects, f"no review SELECT was captured; got {statements}"
    assert any("LIMIT" in s for s in selects), (
        f"the bound was not pushed into SQL. Statements: {selects}"
    )


@pytest.mark.asyncio
async def test_reviews_list_limit_over_the_cap_is_rejected(real_app_client, db_session):
    """`limit=1001` is a 422, matching every other list route's le=1000."""
    client, _ = real_app_client
    art = await create_test_artifact(db_session, project_id=__import__("uuid").UUID(PROJECT_A))
    resp = client.get(f"/projects/{PROJECT_A}/artifacts/{art.id}/reviews?limit=1001")
    assert resp.status_code == 422
