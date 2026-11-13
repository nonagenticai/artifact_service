"""Extended auth middleware edge-case tests.

Covers token extraction edge cases, introspection fallbacks,
trusted-network quirks, and path normalisation.

TENANT IDS ARE UUIDS (2026-08-26). Three tests in here pinned the OLD
behaviour and were INVERTED rather than deleted — each one documented a string
that used to become a tenant just by being sent:

* ``Bearer `` (empty token) used to resolve to a tenant literally named
  ``"Bearer"``;
* ``BearerNoSpace`` used to resolve to a tenant named ``"BearerNoSpace"``;
* ``"  spaced-tenant  "`` used to be ``.strip()``ed into ``"spaced-tenant"``.

They now assert 400, under names that say so. The strip in particular must not
come back: trimming input before validating it is how a smuggled value gets
laundered into a valid one.
"""

import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars")
os.environ.setdefault("POSTGRES_PASSWORD", "test-password")
os.environ.setdefault("POSTGRES_HOST", "localhost")

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from auth.middleware import DEFAULT_TENANT_ID, AuthMiddleware, _license_cache
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_app(bypass_auth: bool = False) -> FastAPI:
    """Create a minimal test app with AuthMiddleware."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware, bypass_auth=bypass_auth)

    @app.get("/projects/test")
    async def protected_route(request: Request) -> dict:
        return {
            "tenant_id": getattr(request.state, "tenant_id", None),
            "user": getattr(request.state, "user", None),
        }

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Token extraction edge cases
# ---------------------------------------------------------------------------


class TestTokenExtraction:
    """Edge cases around token extraction from headers."""

    def test_an_empty_bearer_header_is_400_not_a_tenant_named_Bearer(self):
        """``X-Tenant-Id: 'Bearer '`` — trailing space, no actual token.

        INVERTED FROM ``test_empty_bearer_token_in_x_tenant_id``, which asserted
        this produced a tenant literally named ``"Bearer"``. The path is
        unchanged: ``_extract_license_token`` returns ``""``, which is falsy, so
        no token is introspected and the request falls to the trusted-network
        branch. What changed is what that branch does with the raw header —
        ``"Bearer "`` is not a spelling of a uuid, so it is a 400.

        Worth keeping rather than deleting: this is the shape a caller produces
        by accident when its token variable is empty, and the old behaviour
        turned that accident into a permanent tenant.
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            resp = client.get("/projects/test", headers={"X-Tenant-Id": "Bearer "})

        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"

    def test_malformed_bearer_no_space_is_400_not_a_tenant_named_BearerNoSpace(self):
        """``X-Tenant-Id: 'BearerNoSpace'`` — missing the space after Bearer.

        INVERTED FROM ``test_malformed_bearer_no_space``. ``startswith("bearer ")``
        is still False, so no token is extracted and the value is still treated
        as a plain tenant id — it is simply not a tenant id any more.
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            resp = client.get("/projects/test", headers={"X-Tenant-Id": "BearerNoSpace"})

        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == "INVALID_TENANT_ID"

    def test_a_valid_uuid_from_a_trusted_peer_still_returns_200(self):
        """Companion control for the two rejections above.

        Both of them would also pass against a gate that refused EVERYTHING.
        This one would not, so it is what distinguishes "the smuggled shapes are
        refused" from "the service is down".
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            resp = client.get("/projects/test", headers={"X-Tenant-Id": TEST_TENANT_A})

        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == TEST_TENANT_A

    def test_a_non_licence_authorization_is_not_a_credential(self):
        """A bearer in Authorization that is NOT an active licence (FR's Keycloak
        JWT introspects token_not_found) authenticates nothing: no X-Tenant-Id
        from an untrusted peer stays 401 — the 2026-04-26 outage class cannot
        turn into an admission. (An ACTIVE licence there IS a credential since
        the RM #222 port; see tests/test_delegation.py.)"""
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": False, "reason": "token_not_found"}
            resp = client.get(
                "/projects/test",
                headers={"Authorization": "Bearer keycloak-jwt"},
            )

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Introspection edge cases
# ---------------------------------------------------------------------------


class TestIntrospectionEdgeCases:
    """Edge cases in the license introspection path."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        _license_cache.clear()
        yield
        _license_cache.clear()

    def test_token_tenant_id_fallback_no_subject_id(self):
        """Introspection returns active=True with tenant_id but no subject_id.

        Line 124-125: ``license_result.get("subject_id") or
        license_result.get("tenant_id")`` — the ``or`` falls through to
        tenant_id when subject_id is absent.
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True, "tenant_id": TEST_TENANT_A}
            resp = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": "Bearer some-valid-token"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == TEST_TENANT_A

    def test_introspection_timeout_returns_401(self):
        """httpx.ConnectTimeout during introspection → _introspect_license
        returns None → middleware returns 401.

        ConnectTimeout inherits from TimeoutException → HTTPError, caught at
        line 85.
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = None  # simulates what happens after the except
            resp = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": "Bearer timeout-token"},
            )

        assert resp.status_code == 401

    def test_introspection_cache_isolation(self):
        """Two different tokens should produce independent cache entries.

        We mock at the httpx level so the real _introspect_license runs
        and populates the cache.
        """
        # DISTINCT on purpose: this test proves the two tokens do not share a
        # cache entry, which is unobservable if both resolve to one tenant.
        result_a = {"active": True, "tenant_id": TEST_TENANT_A}
        result_b = {"active": True, "tenant_id": TEST_TENANT_B}

        def mock_post_side_effect(url, **kwargs):
            """Return different results based on the token in the POST body."""
            token = kwargs.get("json", {}).get("token", "")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if token == "aaa":
                mock_resp.json.return_value = result_a
            else:
                mock_resp.json.return_value = result_b
            return mock_resp

        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_ac = AsyncMock()
            mock_ac.post.side_effect = mock_post_side_effect
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_ac)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            resp_a = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": "Bearer aaa"},
            )
            assert resp_a.status_code == 200
            assert resp_a.json()["tenant_id"] == TEST_TENANT_A

            resp_b = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": "Bearer bbb"},
            )
            assert resp_b.status_code == 200
            assert resp_b.json()["tenant_id"] == TEST_TENANT_B

        # Verify cache contains both entries with correct keys
        key_a = f"lic:{hashlib.sha256(b'aaa').hexdigest()[:16]}"
        key_b = f"lic:{hashlib.sha256(b'bbb').hexdigest()[:16]}"
        assert key_a in _license_cache
        assert key_b in _license_cache
        assert _license_cache[key_a]["tenant_id"] == TEST_TENANT_A
        assert _license_cache[key_b]["tenant_id"] == TEST_TENANT_B


# ---------------------------------------------------------------------------
# Trusted-network edge cases
# ---------------------------------------------------------------------------


class TestTrustedNetworkEdgeCases:
    """Edge cases in the trusted-network fallback path."""

    def test_a_whitespace_padded_uuid_is_rejected_not_trimmed(self):
        """⛔ THE ``.strip()`` WAS REMOVED ON PURPOSE. DO NOT PUT IT BACK.

        INVERTED FROM ``test_trusted_network_whitespace_tenant``, which asserted
        that ``"  spaced-tenant  "`` was trimmed into the tenant
        ``"spaced-tenant"``.

        The removal is not tidying. Trimming input before validating it is how a
        smuggled value gets laundered into a valid one: with a strip in place,
        ``" Bearer <tok>"`` and ``" <uuid> "`` are each one call away from being
        accepted, and the set of strings that resolve to a tenant stops being
        "the uuid spellings" and becomes "the uuid spellings plus whatever
        trimming happens to produce". Surrounding whitespace is not a spelling of
        a uuid, so it is a 400.

        If this test failed because you re-added a strip, the fix is to remove
        the strip, not to update the assertion.
        """
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            padded = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": f"  {TEST_TENANT_A}  "},
            )
            bare = client.get(
                "/projects/test",
                headers={"X-Tenant-Id": TEST_TENANT_A},
            )

        assert padded.status_code == 400, padded.text
        assert padded.json()["error"]["code"] == "INVALID_TENANT_ID"
        # The same value without the padding is accepted, so what was refused is
        # the padding — not the tenant, and not every request.
        assert bare.status_code == 200, bare.text
        assert bare.json()["tenant_id"] == TEST_TENANT_A

    @pytest.mark.asyncio
    async def test_no_client_ip_returns_401(self):
        """When request.client is None, the middleware should reject with 401.

        _is_trusted_network(None) returns False, so the request falls through
        to the "Not trusted, no token" branch.
        """
        mw = AuthMiddleware(MagicMock(), bypass_auth=False)

        request = MagicMock()
        request.url.path = "/projects/test"
        request.headers = {}
        request.client = None
        request.state = MagicMock(spec=[])

        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_awaited()


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


class TestPathNormalization:
    """Edge cases in URL path normalisation."""

    def test_trailing_slash_on_protected_path(self, tenant_fallback_mode):
        """Request to /projects/test/ (trailing slash) still matches
        PROTECTED_PREFIXES after rstrip('/') and auth runs normally.

        From a trusted network (no token, no header) under the observe
        break-glass → succeeds with default tenant.
        """
        tenant_fallback_mode("observe")
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            resp = client.get("/projects/test/")

        # FastAPI may 307 redirect trailing slashes by default, but
        # the middleware strips the slash *before* checking protection.
        # If FastAPI redirects, follow it.
        assert resp.status_code in (200, 307)
        if resp.status_code == 200:
            body = resp.json()
            assert body["tenant_id"] == DEFAULT_TENANT_ID

    def test_trailing_slash_does_not_dodge_the_tenant_requirement(self):
        """Default mode (enforce): the rstrip('/') normalisation means a
        trailing slash cannot step around the header-less refusal."""
        app = make_app()
        client = TestClient(app)

        with patch("auth.middleware._is_trusted_network", return_value=True):
            resp = client.get("/projects/test/")

        # The middleware answers before routing, so there is no 307 to follow.
        assert resp.status_code == 401, resp.text
        assert resp.json()["error"]["code"] == "TENANT_REQUIRED"
