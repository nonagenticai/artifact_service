"""Authentication module - License-based auth only."""

from .dependencies import get_creator_id, get_current_user, get_subject_id, get_visibility
from .middleware import AuthMiddleware
from .models import User
from .tenant import (
    get_resource_with_tenant_check,
    get_tenant_id,
    tenant_is_from_fallback,
    verify_tenant_ownership,
)

__all__ = [
    "AuthMiddleware",
    "User",
    "get_current_user",
    "get_creator_id",
    "get_subject_id",
    "get_visibility",
    "get_tenant_id",
    "get_resource_with_tenant_check",
    "tenant_is_from_fallback",
    "verify_tenant_ownership",
]
