"""Tests for auth dependencies and tenant isolation utilities."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from auth.dependencies import get_creator_id, get_current_user
from auth.tenant import get_resource_with_tenant_check, get_tenant_id, verify_tenant_ownership
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B


class TestGetCurrentUser:
    """Test get_current_user dependency."""

    def test_returns_user_from_state(self):
        request = MagicMock()
        request.state.user = {"user_id": "u1", "tenant_id": "t1"}
        result = get_current_user(request)
        assert result["user_id"] == "u1"

    def test_raises_when_no_user(self):
        request = MagicMock(spec=[])
        request.state = MagicMock(spec=[])  # No 'user' attribute
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(request)
        assert exc_info.value.status_code == 401


class TestGetCreatorId:
    """Test get_creator_id dependency."""

    def test_returns_tenant_id(self):
        request = MagicMock()
        request.state.tenant_id = TEST_TENANT_A
        result = get_creator_id(request)
        assert result == TEST_TENANT_A

    def test_raises_when_no_tenant_id(self):
        request = MagicMock(spec=[])
        request.state = MagicMock(spec=[])
        with pytest.raises(HTTPException) as exc_info:
            get_creator_id(request)
        assert exc_info.value.status_code == 401


class TestGetTenantId:
    """Test get_tenant_id from request state."""

    @pytest.mark.asyncio
    async def test_returns_tenant_id(self):
        request = MagicMock()
        request.state.tenant_id = TEST_TENANT_A
        result = await get_tenant_id(request)
        assert result == TEST_TENANT_A

    @pytest.mark.asyncio
    async def test_raises_when_missing(self):
        request = MagicMock(spec=[])
        request.state = MagicMock(spec=[])
        with pytest.raises(HTTPException) as exc_info:
            await get_tenant_id(request)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_when_empty(self):
        request = MagicMock()
        request.state.tenant_id = ""
        with pytest.raises(HTTPException) as exc_info:
            await get_tenant_id(request)
        assert exc_info.value.status_code == 401


class TestGetResourceWithTenantCheck:
    """Test BOLA prevention helper."""

    @pytest.mark.asyncio
    async def test_returns_resource_when_tenant_matches(self):
        resource = MagicMock()
        resource.tenant_id = TEST_TENANT_A
        db_func = AsyncMock(return_value=resource)

        result = await get_resource_with_tenant_check("id-1", TEST_TENANT_A, db_func)
        assert result is resource

    @pytest.mark.asyncio
    async def test_raises_404_when_not_found(self):
        db_func = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            await get_resource_with_tenant_check("id-1", TEST_TENANT_A, db_func, "Widget")
        assert exc_info.value.status_code == 404
        assert "Widget" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_raises_404_on_tenant_mismatch(self):
        resource = MagicMock()
        resource.tenant_id = TEST_TENANT_B
        db_func = AsyncMock(return_value=resource)

        with pytest.raises(HTTPException) as exc_info:
            await get_resource_with_tenant_check("id-1", TEST_TENANT_A, db_func)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_raises_500_when_no_tenant_id_attr(self):
        resource = MagicMock(spec=[])  # No tenant_id attribute
        db_func = AsyncMock(return_value=resource)

        with pytest.raises(HTTPException) as exc_info:
            await get_resource_with_tenant_check("id-1", TEST_TENANT_A, db_func)
        assert exc_info.value.status_code == 500


class TestVerifyTenantOwnership:
    """Test inline tenant ownership check."""

    def test_passes_when_tenant_matches(self):
        resource = MagicMock()
        resource.tenant_id = TEST_TENANT_A
        verify_tenant_ownership(resource, TEST_TENANT_A)  # Should not raise

    def test_raises_404_on_mismatch(self):
        resource = MagicMock()
        resource.tenant_id = TEST_TENANT_B
        with pytest.raises(HTTPException) as exc_info:
            verify_tenant_ownership(resource, TEST_TENANT_A)
        assert exc_info.value.status_code == 404

    def test_raises_500_when_no_tenant_id_attr(self):
        resource = MagicMock(spec=[])
        with pytest.raises(HTTPException) as exc_info:
            verify_tenant_ownership(resource, TEST_TENANT_A)
        assert exc_info.value.status_code == 500
