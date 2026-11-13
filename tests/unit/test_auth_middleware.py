"""Tests for authentication middleware.

TENANT IDS ARE UUIDS (2026-08-26). The tenant literals here used to be names
(``tenant-1``, ``my-tenant``, ``trusted-tenant``, ``license-tenant``) and the
bypass branch used to mint ``test_user`` out of nothing. Those values are the
defect written down as fixtures, so they were replaced rather than patched
around: ``TEST_TENANT_A`` / ``TEST_TENANT_B`` from ``tests/conftest.py``.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from auth.middleware import (
    DEFAULT_TENANT_ID,
    AuthMiddleware,
    _introspect_license,
    _is_trusted_network,
    _license_cache,
)
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B


class TestIsTrustedNetwork:
    """Test trusted network detection."""

    def test_localhost_ipv4_trusted(self):
        assert _is_trusted_network("127.0.0.1") is True

    def test_private_192_168_trusted(self):
        assert _is_trusted_network("192.168.1.100") is True

    def test_private_10_trusted(self):
        assert _is_trusted_network("10.42.0.5") is True

    def test_private_172_16_trusted(self):
        assert _is_trusted_network("172.16.0.1") is True

    def test_public_ip_not_trusted(self):
        assert _is_trusted_network("8.8.8.8") is False

    def test_none_host_not_trusted(self):
        assert _is_trusted_network(None) is False

    def test_invalid_host_not_trusted(self):
        assert _is_trusted_network("not-an-ip") is False

    def test_ipv6_localhost_trusted(self):
        assert _is_trusted_network("::1") is True


class TestIntrospectLicense:
    """Test license token introspection."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        _license_cache.clear()
        yield
        _license_cache.clear()

    @pytest.mark.asyncio
    async def test_valid_active_license(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "active": True,
            "subject_id": TEST_TENANT_A,
            "tenant_id": TEST_TENANT_A,
        }

        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("valid-token")
            assert result is not None
            assert result["active"] is True
            assert result["subject_id"] == TEST_TENANT_A

    @pytest.mark.asyncio
    async def test_inactive_license(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": False}

        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("inactive-token")
            assert result is not None
            assert result["active"] is False

    @pytest.mark.asyncio
    async def test_introspection_failure(self):
        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection failed")
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("some-token")
            assert result is None

    @pytest.mark.asyncio
    async def test_cached_result(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "active": True,
            "subject_id": TEST_TENANT_B,
        }

        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            # First call should hit the API
            result1 = await _introspect_license("cache-token")
            assert result1 is not None
            assert result1["subject_id"] == TEST_TENANT_B

        # Second call should use cache (no mock needed)
        result2 = await _introspect_license("cache-token")
        assert result2 is not None
        assert result2["subject_id"] == TEST_TENANT_B

    @pytest.mark.asyncio
    async def test_non_200_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("auth.middleware.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("bad-token")
            assert result is None


class TestAuthMiddleware:
    """Test AuthMiddleware dispatch logic."""

    def _make_request(self, path="/projects/123", headers=None, client_host="127.0.0.1"):
        request = MagicMock()
        request.url.path = path
        request.headers = headers or {}
        if client_host:
            request.client.host = client_host
        else:
            request.client = None
        request.state = MagicMock(spec=[])
        return request

    def _make_middleware(self, bypass=False):
        app = MagicMock()
        return AuthMiddleware(app, bypass_auth=bypass)

    @pytest.mark.asyncio
    async def test_public_endpoint_skipped(self):
        mw = self._make_middleware()
        request = self._make_request(path="/health")
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_protected_path_skipped(self):
        mw = self._make_middleware()
        request = self._make_request(path="/some/unprotected")
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bypass_auth_sets_tenant(self):
        """A header IS still honoured in bypass mode — provided it is a uuid."""
        mw = self._make_middleware(bypass=True)
        request = self._make_request(path="/projects/123", headers={"X-Tenant-Id": TEST_TENANT_A})
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == TEST_TENANT_A
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bypass_auth_rejects_a_non_uuid_tenant_header(self):
        """Bypass mode is not a minting hole.

        Rewritten from the version of ``test_bypass_auth_sets_tenant`` that sent
        ``"my-tenant"`` and asserted it came back: bypass mode writes into the
        same tables production uses, so any string it accepted was a tenant that
        could be created by a test run.
        """
        mw = self._make_middleware(bypass=True)
        request = self._make_request(path="/projects/123", headers={"X-Tenant-Id": "my-tenant"})
        call_next = AsyncMock(return_value=MagicMock())

        response = await mw.dispatch(request, call_next)

        assert response.status_code == 400
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_bypass_auth_default_tenant(self, tenant_fallback_mode):
        """No header -> the CONFIGURED default, never the old ``test_user`` literal.

        ``test_user`` is not a uuid, so since alembic ``20260826_0003`` it cannot
        even be stored in ``artifacts.tenant_id``. The assertion below is on
        DEFAULT_TENANT_ID and the absence of the old literal, so this test fails
        if the fallback is ever reintroduced under another name.

        observe break-glass only; enforce is ``test_bypass_auth_no_header_is_401``.
        """
        tenant_fallback_mode("observe")
        mw = self._make_middleware(bypass=True)
        request = self._make_request(path="/projects/123", headers={})
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == DEFAULT_TENANT_ID
        assert request.state.tenant_id != "test_user"
        assert request.state.user["user_id"] != "test_user"

    @pytest.mark.asyncio
    async def test_bypass_auth_no_header_is_401(self):
        """Default mode (enforce): bypass + no header is refused, route not run."""
        mw = self._make_middleware(bypass=True)
        request = self._make_request(path="/projects/123", headers={})
        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        assert b"TENANT_REQUIRED" in bytes(response.body)
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_trusted_network_no_token(self):
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": TEST_TENANT_A},
            client_host="192.168.1.50",
        )
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == TEST_TENANT_A

    @pytest.mark.asyncio
    async def test_trusted_network_non_uuid_tenant_is_400(self):
        """THE minting path, closed.

        192.168.1.50 is inside TRUSTED_CIDRS — in production that set is the
        whole pod CIDR ``10.0.0.0/8``, so this is any peer in the mesh. It used
        to be able to name a tenant and own it; the sibling test above shows the
        legitimate uuid still works, so this is a rejection of the VALUE, not of
        the peer.
        """
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": "n8n-dev"},
            client_host="192.168.1.50",
        )
        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)

        assert response.status_code == 400
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_trusted_network_default_tenant(self, tenant_fallback_mode):
        """observe break-glass only; enforce is ``test_trusted_network_no_header_is_401``."""
        tenant_fallback_mode("observe")
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={},
            client_host="10.0.0.1",
        )
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        # Should use DEFAULT_TENANT_ID
        assert request.state.tenant_id == DEFAULT_TENANT_ID
        assert request.state.user["tenant_id"] == DEFAULT_TENANT_ID

    @pytest.mark.asyncio
    async def test_trusted_network_no_header_is_401(self):
        """Default mode (enforce): trusted peer + no token + no header -> 401."""
        mw = self._make_middleware()
        request = self._make_request(path="/projects/123", headers={}, client_host="10.0.0.1")
        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        assert b"TENANT_REQUIRED" in bytes(response.body)
        assert not hasattr(request.state, "tenant_id")
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_untrusted_no_token_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)
        assert response.status_code == 401
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_valid_bearer_token(self):
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": "Bearer valid-token"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock(return_value=MagicMock())

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True, "tenant_id": TEST_TENANT_A}
            await mw.dispatch(request, call_next)

        assert request.state.tenant_id == TEST_TENANT_A
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_invalid_bearer_token_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": "Bearer bad-token"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": False}
            response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_token_missing_tenant_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": "Bearer some-token"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True}
            response = await mw.dispatch(request, call_next)

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_license_payload_with_a_non_uuid_tenant_is_401(self):
        """401, not 400: the bad value came from the authz service, not the client."""
        mw = self._make_middleware()
        request = self._make_request(
            path="/projects/123",
            headers={"X-Tenant-Id": "Bearer valid-token"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True, "tenant_id": "n8n-dev"}
            response = await mw.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dispatch_exception_returns_500(self):
        mw = self._make_middleware()
        request = self._make_request(path="/projects/123", client_host="8.8.8.8")
        call_next = AsyncMock(side_effect=ValueError("unexpected"))

        # The exception inside dispatch (before call_next) should be caught
        with patch.object(mw, "_is_public_endpoint", side_effect=ValueError("boom")):
            response = await mw.dispatch(request, call_next)
        assert response.status_code == 500


class TestMiddlewareHelpers:
    """Test middleware helper methods."""

    def _make_middleware(self):
        return AuthMiddleware(MagicMock())

    def test_is_public_endpoint_exact(self):
        mw = self._make_middleware()
        assert mw._is_public_endpoint("/health") is True
        assert mw._is_public_endpoint("/docs") is True
        assert mw._is_public_endpoint("/") is True

    def test_is_public_endpoint_prefix(self):
        mw = self._make_middleware()
        assert mw._is_public_endpoint("/health/live") is True
        assert mw._is_public_endpoint("/docs/swagger") is True
        assert mw._is_public_endpoint("/static/file.js") is True

    def test_is_protected(self):
        mw = self._make_middleware()
        assert mw._is_protected("/projects/123") is True
        assert mw._is_protected("/artifacts/abc") is True
        assert mw._is_protected("/health") is False
        assert mw._is_protected("/other") is False

    def test_extract_license_token_from_x_tenant_id(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {"X-Tenant-Id": "Bearer my-token-123"}
        assert mw._extract_license_token(request) == "my-token-123"

    def test_extract_license_token_ignores_authorization(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {
            "X-Tenant-Id": "plain-tenant-id",
            "Authorization": "Bearer auth-token-456",
        }
        # Authorization header is NOT consulted — license tokens travel in X-Tenant-Id only
        assert mw._extract_license_token(request) is None

    def test_extract_license_token_none(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {"X-Tenant-Id": "plain-value"}
        assert mw._extract_license_token(request) is None

    def test_unauthorized_response(self):
        mw = self._make_middleware()
        resp = mw._unauthorized_response("test detail")
        assert resp.status_code == 401
        import json

        body = json.loads(resp.body)
        assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"
        assert body["error"]["message"] == "test detail"
        assert body["error"]["status"] == 401

    def test_internal_error_response(self):
        mw = self._make_middleware()
        resp = mw._internal_error_response("test error")
        assert resp.status_code == 500
        import json

        body = json.loads(resp.body)
        assert body["error"]["code"] == "AUTHENTICATION_SERVICE_ERROR"
        assert body["error"]["message"] == "test error"
        assert body["error"]["status"] == 500

    def test_extract_no_auth_headers(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {}
        assert mw._extract_license_token(request) is None
