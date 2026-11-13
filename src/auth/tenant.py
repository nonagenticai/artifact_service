"""Tenant isolation utilities for multi-tenant artifact service."""

import logging
from collections.abc import Callable
from typing import Any, Protocol

from fastapi import HTTPException, Request, status

from tenant_id import canonical_tenant_id

logger = logging.getLogger(__name__)

#: Message for the dependency-level re-check below. Never echoes the rejected
#: value — see the same rule in ``auth/middleware.py``.
_NOT_A_TENANT_UUID = "X-Tenant-Id must be a tenant UUID. A tenant name is not a tenant id."


class HasTenantId(Protocol):
    tenant_id: str


async def get_tenant_id(request: Request) -> str:
    """Get tenant ID from request state (set by AuthMiddleware).

    Returns the CANONICAL uuid spelling. This is the function every route in
    ``routes/artifacts.py`` actually calls (10 call sites), so it is the last
    boundary before a tenant value reaches a repository query.

    ⛔ DELIBERATE REDUNDANCY — NOT A DUPLICATE TO BE TIDIED AWAY. ``AuthMiddleware``
    already gates every protected path through ``canonical_tenant_id``, and this
    re-check is expected never to fire in production. It stays because the
    middleware is not the only way ``request.state.tenant_id`` can be set: a test
    client, a future dependency, an added middleware, or a route mounted outside
    ``PROTECTED_PREFIXES`` can all populate that state without passing the gate.
    The sibling repo ``procedure_management`` has TWO ``get_tenant_id``
    implementations and the hardened one turned out to have zero production
    callers while all 12 routers imported the other; the cheap insurance against
    that class of defect is to harden the value at the point of USE, not only at
    the point of entry. Delete this and the guarantee "no non-uuid can reach a
    repository query" becomes "no non-uuid can reach it *by the path we thought
    of*".
    """
    if hasattr(request.state, "tenant_id") and request.state.tenant_id:
        canonical = canonical_tenant_id(request.state.tenant_id)
        if canonical is None:
            # 400, not 401: whatever set this state was authenticated; the value
            # is simply not a tenant id. Rendered by main's HTTPException handler
            # as code ``HTTP_400`` (the middleware's own rejection carries the
            # richer ``INVALID_TENANT_ID`` code — this path is unreachable when
            # the middleware is in front).
            logger.warning(
                "Non-uuid tenant reached get_tenant_id; the middleware gate was bypassed"
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_NOT_A_TENANT_UUID)
        # Canonical, so `==` against a value read back from the native `uuid`
        # column (models use Uuid(as_uuid=False) -> canonical lowercase str)
        # always compares like with like.
        return canonical

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant context")


def tenant_is_from_fallback(request: Request) -> bool:
    """True iff AuthMiddleware resolved the tenant via the absent-header fallback.

    ``is True`` on purpose: only the explicit source tag set by the middleware
    counts; anything else (credential, explicit header, no tag) is False.
    """
    return getattr(request.state, "tenant_from_fallback", False) is True


async def get_resource_with_tenant_check(
    resource_id: str,
    tenant_id: str,
    db_func: Callable[..., Any],
    resource_name: str = "Resource",
) -> HasTenantId:
    """
    Prevent BOLA (Broken Object Level Authorization): verify resource belongs to tenant.

    Args:
        resource_id: The ID of the resource to fetch
        tenant_id: The tenant ID from get_tenant_id()
        db_func: Async function that fetches the resource by ID
        resource_name: Human-readable name for error messages

    Returns:
        The resource if found and tenant matches

    Raises:
        HTTPException: 404 if not found OR tenant mismatch (don't reveal existence)
    """
    resource = await db_func(resource_id)

    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )

    # SECURITY: Check tenant_id matches
    if not hasattr(resource, "tenant_id"):
        logger.error(f"Resource {resource_name} missing tenant_id column - security risk!")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        )

    # COMPARISON CONTRACT (both sides canonical, or this silently 404s):
    #   right side — ``tenant_id`` comes from ``get_tenant_id`` above, which
    #     returns the canonical lowercase-dashed spelling, so an uppercase,
    #     braced or ``urn:uuid:`` header no longer mismatches a stored row.
    #   left side  — ``tenant_id`` is ``Uuid(as_uuid=False)`` on the models, so
    #     SQLAlchemy hands back the canonical lowercase str. ``str()`` is a
    #     no-op for that, and only matters if a model ever flips to
    #     ``as_uuid=True``, where a bare ``!=`` against a str would 404 EVERY
    #     request — a fail-closed outage that looks like missing data.
    if str(resource.tenant_id) != tenant_id:
        # SECURITY: Don't reveal that the resource exists - return 404, not 403
        logger.warning(
            f"BOLA attempt: tenant {tenant_id} tried to access "
            f"{resource_name} {resource_id} owned by {resource.tenant_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )

    return resource


def verify_tenant_ownership(
    resource: HasTenantId, tenant_id: str, resource_name: str = "Resource"
) -> None:
    """
    Simple inline tenant ownership check for resources already loaded.

    Args:
        resource: The resource object (must have tenant_id attribute)
        tenant_id: The tenant ID from get_tenant_id()
        resource_name: Human-readable name for error messages

    Raises:
        HTTPException: 404 if tenant mismatch (don't reveal existence)
    """
    if not hasattr(resource, "tenant_id"):
        logger.error(f"Resource {resource_name} missing tenant_id column - security risk!")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error"
        )

    # Same comparison contract as get_resource_with_tenant_check above.
    if str(resource.tenant_id) != tenant_id:
        logger.warning(
            f"BOLA attempt: tenant {tenant_id} tried to access "
            f"{resource_name} owned by {resource.tenant_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )
