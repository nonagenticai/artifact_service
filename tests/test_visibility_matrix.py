"""TENANCY_AND_IMPROVEMENT.md §4.4 visibility matrix, artifacts service.

One table-driven test per cell, at the HTTP layer (same layer and fixtures as
``tests/test_system_inheritance.py``), plus the §4.4 mutant: make the system
inheritance clause ignore ``publish_status`` and require a hidden cell to leak.

Rule under test (George, §4.4, as narrowed by the owner's 2026-09-30 ruling):
PUBLISHED system assets are readable by every PLATFORM tenant; a CUSTOMER
tenant never inherits system rows, published or not (system/improvement data
must never be visible to a customer tenant). Every tenant-owned asset is
private to its tenant. A hidden row is a 404, never a 403, so its existence
does not leak.

``stream_own_kind``, ``stream_other_kind`` and ``execution`` are made PLATFORM
tenants by this module's autouse fixture (mirroring
``test_system_inheritance.py``'s own fixture); ``customer`` is deliberately
left out, so it is the one cell in this matrix that exercises the non-platform
(deny) path.

Artifacts carries two lifecycle states only (``ck_artifacts_publish_status``:
draft | published), so the CANARY / DISCARDED columns of the spec table have no
artifact representation. "Own kind" is not an artifact concept either (stream
tenants own workflows / prompts / procedures); the two stream readers are two
distinct test tenants so both spec rows are exercised.

Cells the spec requires but this service has not built are strict xfails, so the
day one is built the XPASS reds and the marker must be removed:
  * stream own-kind on a system DRAFT (R W) — stream write-back, §4.4 / §16.

SYSTEM reading another tenant's row is DENY, like every other cross-tenant pair
(owner's ruling 2026-10-02: the system tenant must never read customer data;
the earlier G-B "super-admin cross-tenant read" is cancelled).
"""

import secrets
import uuid
from unittest.mock import patch

import pytest

from tests.conftest import TEST_TENANT_B
from tests.test_system_inheritance import (
    SYSTEM,
    _FakeFallbackTagMiddleware,
    _h,
    _upload,
)
from tests.test_visibility import PROJECT_ID, _make_client

# Fictional stand-ins for the §4.4 tenants. Never a production tenant id.
STREAM_OWN_KIND = "0198c2d4-7a10-7a00-9c00-5157e1a00002"
STREAM_OTHER_KIND = "0198c2d4-7a10-7a00-9c00-5157e1a00004"
EXECUTION = "0198c2d4-7a10-7a00-9c00-5157e1a00003"
CUSTOMER = TEST_TENANT_B

TENANTS = {
    "system": SYSTEM,
    "stream_own_kind": STREAM_OWN_KIND,
    "stream_other_kind": STREAM_OTHER_KIND,
    "execution": EXECUTION,
    "customer": CUSTOMER,
}
assert len(set(TENANTS.values())) == len(TENANTS), "every reader must be a distinct tenant"

STATES = ("draft", "published")

ALLOW = "allow"
DENY = "deny"
XFAIL_STREAM = pytest.mark.xfail(strict=True, reason="stream write-back not built (TENANCY §4.4)")


def _read_expectation(reader: str, owner: str, state: str) -> tuple[str, list]:
    """(ALLOW|DENY, marks) for `reader` reading a row owned by `owner` in `state`."""
    if reader == owner:
        return ALLOW, []
    if owner == "system":
        if reader == "customer":
            # Owner's ruling 2026-09-30: system/improvement data is NEVER
            # visible to a customer tenant — published or not. This is the
            # one place in the matrix where CUSTOMER's answer no longer
            # matches a platform reader's.
            return DENY, []
        if state == "published":
            return ALLOW, []
        if reader == "stream_own_kind":
            return ALLOW, [XFAIL_STREAM]
        return DENY, []
    # Row owned by a non-system tenant X: no lifecycle state applies.
    # Owner's ruling 2026-10-02: the system tenant is NOT a super-admin; it never
    # reads another tenant's row, whatever the state.
    return DENY, []


def _write_expectation(writer: str, owner: str, state: str) -> tuple[str, list]:
    """(ALLOW|DENY, marks) for `writer` mutating a row owned by `owner` in `state`."""
    if writer == owner:
        return ALLOW, []
    if owner == "system" and writer == "stream_own_kind" and state == "draft":
        return ALLOW, [XFAIL_STREAM]
    # Everything else is refused, including SYSTEM writing X's row: §4.4 allows
    # that only as an explicit super-admin action inside X's workspace (§2.5),
    # which no artifacts route offers.
    return DENY, []


def _cells(expect_fn) -> list:
    cells = []
    for reader in TENANTS:
        for owner in TENANTS:
            for state in STATES:
                expected, marks = expect_fn(reader, owner, state)
                cells.append(
                    pytest.param(
                        reader,
                        owner,
                        state,
                        expected,
                        marks=marks,
                        id=f"{reader}->{owner}:{state}",
                    )
                )
    return cells


READ_CELLS = _cells(_read_expectation)
WRITE_CELLS = _cells(_write_expectation)

# Non-vacuity: 5 readers x 5 owners x 2 states. A matrix that silently shrinks
# would still go green, so pin its size.
assert len(READ_CELLS) == len(WRITE_CELLS) == 50
assert sum(1 for c in READ_CELLS if c.values[3] == DENY) >= 10


@pytest.fixture(scope="class")
def matrix_client():
    client, _mock = _make_client()
    client.app.add_middleware(_FakeFallbackTagMiddleware)
    with client:
        yield client


@pytest.fixture(autouse=True)
def _system_tenant_is_the_test_uuid():
    """Point the routes' system tenant at SYSTEM, and make stream_own_kind,
    stream_other_kind and execution PLATFORM tenants (owner's ruling
    2026-09-30) — CUSTOMER is deliberately left out so it exercises the
    non-platform (deny) path throughout this matrix."""
    import routes.artifacts as routes_mod
    from core.config import get_settings

    # may_inherit_system() reads get_settings() at call time; a migration test
    # calls get_settings.cache_clear(), so patch the live object as well.
    live = get_settings()
    platform = [
        *routes_mod.settings.artifacts_platform_tenant_ids,
        STREAM_OWN_KIND,
        STREAM_OTHER_KIND,
        EXECUTION,
    ]
    with (
        patch.object(routes_mod.settings, "system_tenant_id", SYSTEM),
        patch.object(routes_mod.settings, "artifacts_platform_tenant_ids", platform),
        patch.object(live, "artifacts_platform_tenant_ids", platform),
    ):
        yield


def _seed(client, owner: str, state: str) -> tuple[str, str]:
    """Upload one tenant-visible row owned by `owner` in `state`; (id, card_id)."""
    card = str(uuid.uuid4())
    art = _upload(
        client,
        tenant=TENANTS[owner],
        subject=f"owner-{secrets.token_hex(3)}",
        publish_status=state,
        card_id=card,
    )
    assert art["publish_status"] == state
    return art["id"], card


def _url(art_id: str) -> str:
    return f"/projects/{PROJECT_ID}/artifacts/{art_id}"


def _observe_read(client, reader: str, art_id: str, card: str) -> tuple[int, bool]:
    """(GET status, row present in the card-scoped project list) for `reader`."""
    headers = _h(TENANTS[reader])
    status = client.get(_url(art_id), headers=headers).status_code
    listed = client.get(
        f"/projects/{PROJECT_ID}/artifacts", params={"card_id": card}, headers=headers
    )
    assert listed.status_code == 200, listed.text
    return status, art_id in {str(r["id"]) for r in listed.json()}


def _assert_owner_view(client, owner: str, art_id: str, state: str) -> None:
    r = client.get(_url(art_id), headers=_h(TENANTS[owner]))
    assert r.status_code == 200, f"row vanished for its owner: {r.status_code}"
    assert r.json()["publish_status"] == state, "a refused write changed the row"


class TestVisibilityMatrix:
    @pytest.mark.parametrize(("reader", "owner", "state", "expected"), READ_CELLS)
    def test_read_cell(self, matrix_client, reader, owner, state, expected):
        art_id, card = _seed(matrix_client, owner, state)
        status, listed = _observe_read(matrix_client, reader, art_id, card)
        if expected == ALLOW:
            assert status == 200, f"{reader} must read {owner}'s {state} row, got {status}"
            assert listed, f"{reader} can GET but the list hides the row"
        else:
            assert status != 403, "hidden row answered 403: existence leaks"
            assert status == 404, f"{reader} must not see {owner}'s {state} row, got {status}"
            assert not listed, f"{owner}'s {state} row leaked into {reader}'s list"

    @pytest.mark.parametrize(("writer", "owner", "state", "expected"), WRITE_CELLS)
    def test_write_cell(self, matrix_client, writer, owner, state, expected):
        art_id, _card = _seed(matrix_client, owner, state)
        headers = _h(TENANTS[writer])
        if expected == ALLOW:
            # Idempotent write (same value) so an allowed cell changes nothing.
            r = matrix_client.patch(
                f"{_url(art_id)}/publish-status", json={"publish_status": state}, headers=headers
            )
            assert r.status_code == 200, f"{writer} must write {owner}'s {state} row: {r.text}"
            assert r.json()["publish_status"] == state
            return
        flipped = "draft" if state == "published" else "published"
        patched = matrix_client.patch(
            f"{_url(art_id)}/publish-status", json={"publish_status": flipped}, headers=headers
        ).status_code
        deleted = matrix_client.delete(_url(art_id), headers=headers).status_code
        for verb, code in (("PATCH", patched), ("DELETE", deleted)):
            assert code != 403, f"refused {verb} answered 403: existence leaks"
            assert code == 404, f"{writer} {verb} on {owner}'s {state} row: {code}"
        _assert_owner_view(matrix_client, owner, art_id, state)


def _is_publish_gated(cell) -> bool:
    _reader, owner, state, expected = cell.values
    return owner == "system" and state == "draft" and expected == DENY and not cell.marks


class TestMatrixMutant:
    """§4.4: a mutant whose `include_system` ignores state must turn the matrix red."""

    def test_publish_gate_ignored_leaks_a_hidden_cell(self, matrix_client, monkeypatch):
        from sqlalchemy import select

        import routes.artifacts as routes_mod
        from models.artifact import Artifact

        # The hidden cells the publish gate alone is responsible for, taken from
        # the matrix table itself (not re-stated): system DRAFT, denied, no xfail.
        hidden = [c.values[0] for c in READ_CELLS if _is_publish_gated(c)]
        assert hidden, "matrix has no hidden system-draft cell to mutate against"

        art_id, card = _seed(matrix_client, "system", "draft")
        for reader in hidden:
            assert _observe_read(matrix_client, reader, art_id, card) == (404, False), (
                f"control: {reader} already sees the system draft on UNMUTATED code"
            )

        # Mutate the function the routes actually call, via its own globals, so
        # the mutant cannot land on a different module object than the one in use.
        scope_globals = routes_mod.visibility_scope.__globals__
        real_and = scope_globals["and_"]

        def and_ignoring_publish_status(*clauses):
            return real_and(*[c for c in clauses if "publish_status" not in str(c)])

        monkeypatch.setitem(scope_globals, "and_", and_ignoring_publish_status)

        # ⚠️ Sanity check against a PLATFORM reader (EXECUTION), NOT CUSTOMER:
        # since owner's ruling 2026-09-30, CUSTOMER never enters the system
        # branch at all (`may_inherit_system(CUSTOMER)` is False), so
        # "publish_status" would be absent from CUSTOMER's SQL regardless of
        # whether this mutation is live — that assertion would prove nothing.
        # EXECUTION is a platform tenant (this module's autouse fixture), so
        # it DOES reach the system branch, and only the mutation removes the
        # publish_status clause from its SQL.
        sql = str(
            routes_mod.visibility_scope(
                select(Artifact.id),
                Artifact,
                tenant_id=EXECUTION,
                subject_id="s",
                include_system=True,
                system_tenant_id=SYSTEM,
            ).compile(compile_kwargs={"literal_binds": True})
        )
        assert "publish_status" not in sql, "mutant not live: the publish gate is still compiled"

        leaks = [
            reader
            for reader in hidden
            if _observe_read(matrix_client, reader, art_id, card) != (404, False)
        ]
        assert leaks, "mutant (include_system ignores state) left every hidden cell hidden"
