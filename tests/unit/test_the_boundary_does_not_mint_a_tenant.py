"""The HTTP boundary must not be able to CREATE a tenant by being told one exists.

``tests/unit/test_tenant_id_canonical.py`` covers the value type. This file
covers what ``AuthMiddleware`` DOES with it: which requests reach a route, which
get 400, what lands on ``request.state``, and what the 400 body says.

THE DEFECT, in one sentence: ``X-Tenant-Id`` used to accept any string a header
could carry, so any peer inside ``TRUSTED_CIDRS`` (in production the whole pod
CIDR ``10.0.0.0/8``) could mint a tenant by naming one — which is how the
literal ``n8n-dev`` came to own 284 rows in this database.

Two controls in here are load-bearing and are marked ⛔ where they sit:

* ``test_a_valid_uuid_header_still_reaches_the_route_with_200`` — the ONLY test
  in this file that fails if ``canonical_tenant_id`` is hard-coded to return
  ``None``. Every other test here is a rejection test and an over-rejecting gate
  would satisfy all of them. Over-rejection is the failure mode a paranoid gate
  actually has.
* ``test_trusted_branch_still_takes_X_Subject_Id_from_the_wire`` — pins a
  DELIBERATE asymmetry. Read its docstring before "fixing" it.

Transport note: these use ``httpx.ASGITransport``, whose default client address
is ``127.0.0.1``, so the trusted-network branch is genuinely exercised. Starlette's
``TestClient`` reports the peer as the non-IP string ``"testclient"``, which is
NOT trusted — that is why sibling files have to patch ``_is_trusted_network``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response as StarletteResponse

import core.config as core_config
from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware, _license_cache

#: A tenant that exists only in this test file.
TENANT = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

#: Repo root, used to load ``auth/middleware.py`` a SECOND time under a private
#: module name. ``importlib.reload`` is deliberately not used: a reload that
#: raises leaves the real ``auth.middleware`` in ``sys.modules`` half-initialised
#: and poisons every later test in the session.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MIDDLEWARE_PATH = _REPO_ROOT / "src" / "auth" / "middleware.py"


# ---------------------------------------------------------------------------
# App / client helpers
# ---------------------------------------------------------------------------


def _make_app(*, bypass_auth: bool = False) -> tuple[FastAPI, dict[str, Any]]:
    """One protected route that RECORDS that it ran, plus the state it saw.

    The ``reached`` flag matters: a test that only checks a status code cannot
    tell "the route ran and returned 200" from "the middleware short-circuited
    with something that happens to be 200".
    """
    seen: dict[str, Any] = {"reached": False}

    app = FastAPI()
    app.add_middleware(AuthMiddleware, bypass_auth=bypass_auth)

    @app.get("/artifacts/echo")
    async def _echo(request: Request) -> JSONResponse:
        seen["reached"] = True
        seen["tenant_id"] = getattr(request.state, "tenant_id", None)
        seen["subject_id"] = getattr(request.state, "subject_id", None)
        seen["user"] = getattr(request.state, "user", None)
        return JSONResponse(
            {
                "tenant_id": seen["tenant_id"],
                "subject_id": seen["subject_id"],
                "user": seen["user"],
            }
        )

    return app, seen


@pytest.fixture(autouse=True)
def _clear_license_cache() -> None:
    _license_cache.clear()


@pytest.fixture
async def trusted() -> AsyncGenerator[tuple[httpx.AsyncClient, dict[str, Any]]]:
    """Client whose peer address (127.0.0.1) is inside TRUSTED_CIDRS."""
    app, seen = _make_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, seen


# ---------------------------------------------------------------------------
# THE defect
# ---------------------------------------------------------------------------


async def test_bare_n8n_dev_header_is_400_not_a_new_tenant(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """``X-Tenant-Id: n8n-dev`` from a trusted peer: 400, and the route never runs.

    This exact request returned 200 before the change and scoped every row it
    wrote to the string ``n8n-dev``. Externally nothing regresses — the gateway
    already 401s such requests — so an in-mesh caller is the only thing that can
    observe the difference, which is precisely the caller that could mint.

    Asserting ``reached is False`` is the half that matters. A 400 that still ran
    the route would mean the handler had already touched the database under a
    minted tenant before the response was assembled.
    """
    client, seen = trusted
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": "n8n-dev"})

    assert resp.status_code == 400, resp.text
    assert seen["reached"] is False, "the route ran despite the 400 — the gate is not a gate"

    body = resp.json()
    assert body["error"]["code"] == "INVALID_TENANT_ID"
    assert body["error"]["status"] == 400
    # 400, not 401: the caller's trusted-network position was fine. Offering a
    # re-auth challenge would send them down the wrong road.
    assert "WWW-Authenticate" not in resp.headers


async def test_the_400_body_does_not_echo_the_rejected_value(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """The message is FIXED text. Reflecting the input is how a header becomes a payload.

    The probe value is a marker no legitimate part of the envelope could contain,
    so a hit is unambiguous rather than a coincidence of shared vocabulary.
    """
    client, _seen = trusted
    marker = "zz-reflect-me-9f3a2b-zz"
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": marker})

    assert resp.status_code == 400
    assert marker not in resp.text
    assert marker not in json.dumps(dict(resp.headers))


async def test_bypass_branch_no_longer_mints_test_user(
    monkeypatch: pytest.MonkeyPatch,
    tenant_fallback_mode,
) -> None:
    """With auth disabled and no header, the tenant is the CONFIGURED default.

    The old code substituted the literal ``"test_user"`` here. That is not a
    hypothetical: bypass mode writes into the same tables production uses, so a
    bypassed run could mint exactly the kind of non-uuid tenant the gate now
    refuses — and ``test_user`` cannot even be stored since alembic
    ``20260826_0003`` made ``artifacts.tenant_id`` a native ``uuid``.

    Driven through the ``AUTH_ENABLED=false`` ENV path rather than the
    ``bypass_auth=True`` constructor flag, because the env var is the one a
    deployment can actually set by mistake.

    Under the observe break-glass only: enforce (the default) refuses the
    header-less request outright — see
    ``test_bypass_branch_refuses_a_header_less_request_under_enforce``.
    """
    tenant_fallback_mode("observe")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    app, seen = _make_app(bypass_auth=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/artifacts/echo")

    assert resp.status_code == 200, resp.text
    assert seen["reached"] is True
    assert seen["tenant_id"] == DEFAULT_TENANT_ID
    assert seen["user"]["tenant_id"] == DEFAULT_TENANT_ID
    assert seen["user"]["user_id"] == DEFAULT_TENANT_ID

    # The literal is gone from BOTH the wire and the resolved state — checking
    # only the response body would miss a value stashed on request.state and
    # never serialised.
    assert "test_user" not in resp.text
    assert "test_user" not in json.dumps(seen)


async def test_bypass_branch_refuses_a_header_less_request_under_enforce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default mode: AUTH_ENABLED=false is not a way round tenant separation.

    No header -> 401 TENANT_REQUIRED and the route never runs, exactly as on the
    trusted branch.
    """
    monkeypatch.setenv("AUTH_ENABLED", "false")
    app, seen = _make_app(bypass_auth=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/artifacts/echo")

    assert resp.status_code == 401, resp.text
    assert seen["reached"] is False
    assert resp.json()["error"]["code"] == "TENANT_REQUIRED"
    assert DEFAULT_TENANT_ID not in resp.text


async def test_bypass_branch_still_rejects_a_non_uuid_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bypass mode is not a hole: a header that IS present must still be a uuid.

    Without this, "auth disabled" would remain a supported way to mint, and the
    test above (which sends no header at all) would not notice.
    """
    monkeypatch.setenv("AUTH_ENABLED", "false")
    app, seen = _make_app(bypass_auth=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/artifacts/echo", headers={"X-Tenant-Id": "n8n-dev"})

    assert resp.status_code == 400, resp.text
    assert seen["reached"] is False
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"


# ---------------------------------------------------------------------------
# ⛔ An EMPTY header is not an ABSENT header
# ---------------------------------------------------------------------------


async def test_an_empty_tenant_header_is_400_and_never_inherits_the_default(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """``X-Tenant-Id:`` with no value must be 400 — NOT DEFAULT_TENANT_ID's scope.

    ⛔ THE DEFECT THIS PINS, on the PRODUCTION branch (no token, trusted peer).
    The gate read::

        canonical_tenant_id(x_tenant_id) if x_tenant_id else DEFAULT_TENANT_ID

    and ``""`` is falsy, so an empty header took the ``else``, skipped
    ``canonical_tenant_id`` entirely, and was handed the default tenant's data
    scope. Measured against the running pod from ``10.42.7.9``: empty header ->
    **200**, body full of ``0195f48b-…-0001``'s rows. The bypass branch used
    ``is None`` and correctly 400'd the identical header, so the two branches
    disagreed about the same request — and the branch that was wrong was the one
    production runs.

    ``auth/middleware.py``'s own module docstring forbids exactly this: "An
    unresolvable tenant is 400, never a silent fallback to ``DEFAULT_TENANT_ID``:
    substituting the default would hand the caller that tenant's data scope."

    Truthiness cannot express the distinction that matters here. Header ABSENT
    means "I have no opinion, use the default"; header PRESENT-BUT-EMPTY means
    "here is my tenant id" and the id is not a uuid. Only ``is None`` separates
    them, which is why both branches now use it.
    """
    client, seen = trusted
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": ""})

    assert resp.status_code == 400, resp.text
    assert seen["reached"] is False, "the route ran on an empty tenant header"
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"
    # The specific damage: not merely "not 200", but "not the default's scope".
    assert DEFAULT_TENANT_ID not in resp.text
    assert seen.get("tenant_id") is None


async def test_an_empty_tenant_header_is_400_on_the_bypass_branch_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both branches, one shape. The bypass branch was already correct; pin it.

    Without this the two branches can drift apart again — and drift is what the
    defect above WAS: one branch on ``is None``, the other on truthiness,
    answering differently to the same bytes.
    """
    monkeypatch.setenv("AUTH_ENABLED", "false")
    app, seen = _make_app(bypass_auth=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/artifacts/echo", headers={"X-Tenant-Id": ""})

    assert resp.status_code == 400, resp.text
    assert seen["reached"] is False
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"


# ---------------------------------------------------------------------------
# Smuggling
# ---------------------------------------------------------------------------


#: Header values that must not resolve to a tenant. CR/LF and Bearer-smuggling
#: are NOT stopped by a dedicated sanitiser — there isn't one, and none is
#: needed: none of these is a spelling of a uuid. That is the point of using the
#: uuid grammar as the gate rather than a charset regex.
_SMUGGLED = [
    pytest.param(b"6ba7b810-9dad-11d1-80b4-00c04fd430c8\r\nX-Injected: v", id="crlf-split"),
    pytest.param(b"6ba7b810-9dad-11d1-80b4-00c04fd430c8\nX-Injected: v", id="lf-split"),
    pytest.param(b"6ba7b810-9dad-11d1-80b4-00c04fd430c8\r\n", id="bare-crlf"),
    pytest.param(b" Bearer not-a-real-licence-token", id="leading-space-bearer"),
    pytest.param(b"6ba7b810-9dad-11d1-80b4-00c04fd430c8 Bearer tok", id="uuid-then-bearer"),
    pytest.param(b"  6ba7b810-9dad-11d1-80b4-00c04fd430c8  ", id="whitespace-padded-uuid"),
    pytest.param(b"Bearer", id="bare-bearer-word"),
    pytest.param(
        b"n8n-dev\r\nX-Tenant-Id: 6ba7b810-9dad-11d1-80b4-00c04fd430c8", id="name-then-uuid"
    ),
]


@pytest.mark.parametrize("raw_header", _SMUGGLED)
async def test_crlf_and_bearer_smuggled_tenant_values_are_400(raw_header: bytes) -> None:
    """Driven at the ASGI scope, because an HTTP client refuses to send some of these.

    ``httpx`` raises on a header value containing CR/LF before anything reaches
    the middleware, so sending these through a client would test httpx's
    validator and report green about code that was never executed. Building the
    scope by hand puts the raw bytes in front of the middleware, which is where
    a real proxy-smuggled value would arrive.
    """
    reached = {"n": False}

    async def call_next(_request: Request) -> StarletteResponse:
        reached["n"] = True
        return StarletteResponse("ok")

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/artifacts/echo",
        "query_string": b"",
        "headers": [(b"x-tenant-id", raw_header)],
        "client": ("127.0.0.1", 5555),
    }
    middleware = AuthMiddleware(app=object(), bypass_auth=False)
    response = await middleware.dispatch(Request(scope), call_next)

    assert response.status_code == 400, raw_header
    assert reached["n"] is False, f"{raw_header!r} reached the route"
    assert b"INVALID_TENANT_ID" in bytes(response.body)


async def test_a_whitespace_padded_uuid_is_rejected_not_trimmed(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """A ``.strip()`` was REMOVED here on purpose. Do not put it back.

    Trimming input before validating it is how a smuggled value gets laundered
    into a valid one: with a strip, ``" Bearer <tok>"`` and ``" <uuid> "`` are
    both one call away from being accepted, and the set of strings that resolve
    to a tenant stops being "the uuid spellings" and becomes "the uuid spellings
    plus whatever trimming produces". Surrounding whitespace is not a spelling
    of a uuid, so it is a 400.

    The predecessor of this test asserted the opposite — that
    ``"  spaced-tenant  "`` resolved to the tenant ``"spaced-tenant"``. It was
    not deleted, it was inverted: the behaviour it pinned is the defect.
    """
    client, seen = trusted
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": f"  {TENANT}  "})

    assert resp.status_code == 400, resp.text
    assert seen["reached"] is False
    assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"

    # …and the un-padded value is fine, so this is a rejection of the padding,
    # not of the tenant.
    ok = await client.get("/artifacts/echo", headers={"X-Tenant-Id": TENANT})
    assert ok.status_code == 200, ok.text


# ---------------------------------------------------------------------------
# Normalisation reaches the data scope
# ---------------------------------------------------------------------------


async def test_uppercase_and_lowercase_uuid_headers_reach_the_same_scope(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """Two spellings, ONE tenant scope — and the canonical one, at that.

    Not merely "both return 200": the resolved ``request.state.tenant_id`` must
    be byte-identical, because that value is compared against rows read back from
    a native ``uuid`` column (which always renders lowercase-dashed). If the
    uppercase caller kept its own spelling, every ``==`` against its own rows
    would silently miss.
    """
    client, seen = trusted

    lower = await client.get("/artifacts/echo", headers={"X-Tenant-Id": TENANT})
    assert lower.status_code == 200, lower.text
    lower_state = seen["tenant_id"]

    upper = await client.get("/artifacts/echo", headers={"X-Tenant-Id": TENANT.upper()})
    assert upper.status_code == 200, upper.text
    upper_state = seen["tenant_id"]

    assert TENANT.upper() != TENANT, "premise: the two headers differ as strings"
    assert lower_state == upper_state == TENANT
    assert lower.json()["tenant_id"] == upper.json()["tenant_id"] == TENANT


# ---------------------------------------------------------------------------
# ⛔ The asymmetry. READ THIS BEFORE "HARMONISING" ANYTHING.
# ---------------------------------------------------------------------------


async def test_trusted_branch_still_takes_X_Subject_Id_from_the_wire(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """⛔ IF YOU MADE THIS FAIL BY MAKING THE TWO BRANCHES CONSISTENT, REVERT.

    The two auth branches in ``src/auth/middleware.py`` treat ``X-Subject-Id``
    DIFFERENTLY, and that is correct, not an oversight:

    * LICENSE branch — the subject comes ONLY from the introspected payload. A
      client-supplied ``X-Subject-Id`` is ignored. Honouring it there is a
      within-tenant BOLA: any holder of any valid license could name a victim's
      subject and both read and mutate that user's ``visibility='user'``
      artifacts (``repositories/visibility.py``: ``scope()`` matches on
      ``subject_id``, ``can_mutate()`` gates on it).
    * TRUSTED-NETWORK branch (this test) — there IS no license to introspect.
      The peer is already inside ``TRUSTED_CIDRS`` and ``X-Subject-Id`` is the
      propagated in-mesh identity, the ONLY source of one. Ignoring it here does
      not close a hole; it erases the identity of every in-cluster caller.

    A previous session "harmonised" exactly this in a sibling service
    (discovery-engine) and broke real in-cluster callers. The tenant on this
    branch IS uuid-gated; the subject deliberately is NOT — it is an opaque
    in-mesh identity, and gating it would be the same harmonisation wearing a
    different hat, which is why the assertion below uses a non-uuid subject.
    """
    client, seen = trusted
    resp = await client.get(
        "/artifacts/echo",
        headers={"X-Tenant-Id": TENANT, "X-Subject-Id": "propagated-subject-7"},
    )

    assert resp.status_code == 200, resp.text
    assert seen["tenant_id"] == TENANT
    assert resp.json()["subject_id"] == "propagated-subject-7", (
        "the trusted-network branch stopped reading X-Subject-Id from the wire — "
        "see this test's docstring before changing the middleware"
    )


# ---------------------------------------------------------------------------
# ⛔ NON-VACUITY. Every other test above passes with canonical_tenant_id()
#    hard-coded to return None. This one does not.
# ---------------------------------------------------------------------------


async def test_a_valid_uuid_header_still_reaches_the_route_with_200(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """The gate must still let the legitimate caller through.

    Over-rejection is the failure mode a paranoid gate actually has, and it is
    invisible to a file full of rejection tests: replace ``canonical_tenant_id``
    with ``lambda _v: None`` and every other assertion here still holds while the
    service 400s every request it has ever served.

    So this asserts the positive end to end: 200, the ROUTE ACTUALLY RAN, and the
    tenant that reached it is the one the caller named — on the request shape
    that carries all of this service's real in-mesh traffic.
    """
    client, seen = trusted
    resp = await client.get("/artifacts/echo", headers={"X-Tenant-Id": TENANT})

    assert resp.status_code == 200, resp.text
    assert seen["reached"] is True, "the route never ran — the gate is over-rejecting"
    assert seen["tenant_id"] == TENANT
    assert resp.json()["tenant_id"] == TENANT
    assert resp.json()["user"]["tenant_id"] == TENANT


async def test_the_default_tenant_path_also_still_reaches_the_route(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
    tenant_fallback_mode,
) -> None:
    """Under the observe break-glass, NO header at all is not a rejection.

    A trusted peer that sends no ``X-Tenant-Id`` gets ``DEFAULT_TENANT_ID`` —
    but ONLY with ``AUTH_TENANT_FALLBACK_MODE=observe``. Under enforce (the
    default) it is 401: the default is the SYSTEM tenant, and naming nothing
    must not land a caller in it. (Contrast the 400 tests above: an
    UNRESOLVABLE tenant never falls back, in either mode.)
    """
    tenant_fallback_mode("observe")
    client, seen = trusted
    resp = await client.get("/artifacts/echo")

    assert resp.status_code == 200, resp.text
    assert seen["reached"] is True
    assert seen["tenant_id"] == DEFAULT_TENANT_ID


async def test_no_header_from_a_trusted_peer_is_401_under_enforce(
    trusted: tuple[httpx.AsyncClient, dict[str, Any]],
) -> None:
    """Default mode: the header-less trusted request never reaches the route and
    never sees the default tenant's scope."""
    client, seen = trusted
    resp = await client.get("/artifacts/echo")

    assert resp.status_code == 401, resp.text
    assert seen["reached"] is False
    assert seen.get("tenant_id") is None
    assert resp.json()["error"]["code"] == "TENANT_REQUIRED"
    assert DEFAULT_TENANT_ID not in resp.text


# ---------------------------------------------------------------------------
# Startup configuration
# ---------------------------------------------------------------------------


def _load_middleware_privately() -> Any:
    """Execute ``auth/middleware.py`` under a private module name.

    NOT ``importlib.reload(auth.middleware)``: a reload that raises part-way
    leaves the real module object in ``sys.modules`` with a half-built namespace
    (``DEFAULT_TENANT_ID`` missing, for one), and every later test in the session
    inherits the wreckage.
    """
    spec = importlib.util.spec_from_file_location("_probe_auth_middleware", _MIDDLEWARE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_import_raises_when_DEFAULT_TENANT_ID_is_not_a_uuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A misconfigured default must be a STARTUP crash, not a per-request surprise.

    Every trusted-network request that omits ``X-Tenant-Id`` is scoped to this
    value, so a non-uuid here would either mint on first write or explode on the
    ``tenant_id`` uuid column at query time. This Deployment is
    ``strategy: Recreate`` with 1 replica, so failing at import is a LOUD outage
    — CrashLoopBackOff, no endpoints, alerts — where a per-request 500 would look
    like an application bug and be chased for hours.

    The value used is ``n8n-dev``: the literal that was the default before this
    change, so this test pins that the old configuration can no longer boot.
    """
    monkeypatch.setenv("DEFAULT_TENANT_ID", "n8n-dev")
    core_config.get_settings.cache_clear()
    try:
        with pytest.raises(Exception) as excinfo:  # noqa: B017 - see the assert below
            _load_middleware_privately()
        # Pydantic wraps the Settings field-validator's ValueError in a
        # ValidationError; ``_resolve_default_tenant_id``'s belt-and-braces
        # RuntimeError is what fires if that validator is ever weakened. Either
        # is a correct refusal, so the assertion is on the DIAGNOSIS the operator
        # reads, not on the exception class.
        message = str(excinfo.value)
        assert "uuid" in message.lower(), message
        assert "n8n-dev" in message, (
            "the crash must name the offending value so the operator can fix the "
            f"Deployment; got: {message}"
        )
    finally:
        # Clear while the bad env is still in place, so the NEXT construction —
        # after monkeypatch restores the environment — rebuilds from good values
        # rather than serving a poisoned cache entry.
        core_config.get_settings.cache_clear()


def test_a_valid_DEFAULT_TENANT_ID_is_canonicalised_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuity for the test above: the private loader CAN succeed.

    Without this, a typo in ``_load_middleware_privately`` (wrong path, missing
    loader) would make the previous test pass for the wrong reason — any
    exception satisfies ``pytest.raises(Exception)``. Here the same loader runs
    to completion, and the uppercase input proves the value is normalised rather
    than merely accepted.
    """
    monkeypatch.setenv("DEFAULT_TENANT_ID", TENANT.upper())
    core_config.get_settings.cache_clear()
    try:
        module = _load_middleware_privately()
        assert module.DEFAULT_TENANT_ID == TENANT
    finally:
        core_config.get_settings.cache_clear()


#: Runs in a COLD interpreter, on purpose. See the test below.
_NESTING_PROBE = """
import json
import core.config as cc

original = cc.Settings.__init__
depth = {"now": 0, "max": 0}


def counting_init(self, *args, **kwargs):
    depth["now"] += 1
    depth["max"] = max(depth["max"], depth["now"])
    try:
        return original(self, *args, **kwargs)
    finally:
        depth["now"] -= 1


cc.Settings.__init__ = counting_init
cc.get_settings.cache_clear()
settings = cc.get_settings()
print(json.dumps({"max": depth["max"], "default_tenant_id": settings.default_tenant_id}))
"""


def test_constructing_settings_does_not_re_enter_settings_construction() -> None:
    """``Settings()`` must not build a second ``Settings()`` inside its own validator.

    MEASURED REGRESSION, not a theoretical one. While ``canonical_tenant_id``
    lived at ``src/auth/tenant_id.py``, the ``default_tenant_id`` validator's
    import of it pulled in ``auth/__init__.py``, which eagerly imports
    ``auth.middleware``, which reads ``get_settings()`` at module level — so
    constructing Settings re-entered Settings construction. Measured nesting
    depth: 2. ``alembic upgrade head`` hit it for real.

    The damage was not only the cycle. With a required env var missing, the
    failure surfaced as ``default_tenant_id.jwt_secret_key — Field required``,
    a message that sends an operator hunting the wrong field mid-outage.

    ⛔ WHY A SUBPROCESS, AND WHY THIS TEST WOULD OTHERWISE BE VACUOUS.
    Measured: with the regression reintroduced (a function-local
    ``from auth.tenant_id import …`` inside the validator), the same probe run
    IN THIS PROCESS reports depth 1 and passes. By the time any test executes,
    ``auth`` is already in ``sys.modules`` — conftest and every sibling test
    file put it there — so the offending import is a dictionary lookup and
    re-enters nothing. The cycle only exists on a COLD import that reaches
    ``core.config`` FIRST, which is exactly what alembic does and exactly what
    this subprocess reproduces. Verified both ways: 1 here, 2 with the
    regression restored.

    The fix being pinned is that ``src/tenant_id.py`` is top-level and imports
    nothing from ``auth``. This test fails the day someone moves it back.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT / "src"),
        # Required to build Settings at all.
        "JWT_SECRET_KEY": "test-secret-key-for-unit-tests-min-32-chars",  # pragma: allowlist secret
        "POSTGRES_PASSWORD": "test-password",  # pragma: allowlist secret
        "POSTGRES_HOST": "localhost",
        # `production` demands six real service URLs from the gitops Deployment
        # (core/config.py model_post_init). That gate is correct; this just
        # stays out of its way rather than weakening it.
        "ENVIRONMENT": "development",
    }
    env.pop("DEFAULT_TENANT_ID", None)

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _NESTING_PROBE],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        env=env,
        timeout=120,
    )

    assert completed.returncode == 0, (
        f"the cold-import probe crashed — that is a circular import too.\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    measured = json.loads(completed.stdout.strip().splitlines()[-1])

    # Premise: the probe really constructed a Settings, so the number below is a
    # measurement and not an untouched zero.
    assert measured["max"] >= 1, f"no Settings was constructed; nothing was measured: {measured}"
    assert measured["max"] == 1, (
        f"Settings construction re-entered itself (depth {measured['max']}). Something in "
        "core.config now imports a module that reaches auth/__init__, which imports "
        "auth.middleware, which reads get_settings() at module level. See this test's "
        "docstring."
    )
    # …and the validator still canonicalised on the way through.
    assert measured["default_tenant_id"] == DEFAULT_TENANT_ID
