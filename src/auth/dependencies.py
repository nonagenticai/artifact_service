"""FastAPI dependencies for authentication.

Simple license-based auth. No Keycloak/JWT.

Tenant + subject scoping:
- get_tenant_id: organization the caller represents
- get_subject_id: the user within the tenant (X-Subject-Id from license-authz;
    empty string when not present — treated as "tenant-only caller")
- get_visibility: desired visibility for newly-created artifacts (X-Visibility
    header; 'tenant' or 'user', defaults to 'tenant')
"""

from typing import Annotated, Any, cast

from fastapi import Header, HTTPException, Request, status


def get_current_user(request: Request) -> dict[str, Any]:
    """Get authenticated user from request state."""
    if not hasattr(request.state, "user"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return cast(dict[str, Any], request.state.user)


def get_creator_id(request: Request) -> str:
    """Get creator/user ID from request state."""
    if not hasattr(request.state, "tenant_id"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return cast(str, request.state.tenant_id)


async def get_subject_id(request: Request) -> str:
    """Get subject (user) ID from request state.

    Falls back to empty string when the caller has not provided an
    X-Subject-Id (trusted-network call or pre-Plan-2 client). Empty string
    is treated as "tenant-only caller" downstream:
    - list/get queries include only visibility='tenant' rows in the OR clause
    - uploads land with subject_id := tenant_id (legacy backfill semantics)
      so mutation gating always defers to tenant scope.
    """
    return str(getattr(request.state, "subject_id", "") or "")


def get_tenant_name(request: Request) -> str:
    """Get human-readable tenant name from request state.

    Set by AuthMiddleware from the X-Tenant-Name header injected by
    license-authz. Falls back to empty string when the header is absent
    (pre-Phase-3 callers, trusted-network calls, bypass mode). The
    before_insert listener on Artifact auto-fills tenant_name := tenant_id
    when this is empty so the DB column is always populated.

    Never raises — mirrors get_subject_id shape.
    """
    return str(getattr(request.state, "tenant_name", "") or "")


VISIBILITY_VALUES = frozenset({"tenant", "user"})


def get_visibility(
    x_visibility: Annotated[str, Header(alias="X-Visibility")] = "tenant",
) -> str:
    """Caller-supplied visibility for new-row creation. Read paths ignore.

    Invalid values silently coerce to 'tenant' (the safer default — exposes
    rather than over-restricts; rejecting would break legacy clients).
    """
    raw = x_visibility.strip().lower()
    return raw if raw in VISIBILITY_VALUES else "tenant"
