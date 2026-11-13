"""Per-user-within-tenant visibility helpers.

Two scoping axes:
- tenant_id: the organization that owns the data
- subject_id: the user (Subject UUID from licenses) within that tenant

Rows have a `visibility` column ('tenant' default | 'user'). List queries
return tenant-visible rows + the caller's own user-visible rows. Mutations
on user-visible rows are gated to the creator.

System-tenant inheritance (READ paths only):
When `include_system=True`, `system_tenant_id` differs from the active tenant
AND the active tenant is a PLATFORM tenant (`may_inherit_system` — owner's
ruling 2026-09-30: system and improvement data are never visible to a customer
tenant), SELECTs widen to also admit rows owned by the system tenant that are
`visibility='tenant'` AND `publish_status='published'`. A non-platform (e.g.
customer) tenant's SELECT is unaffected by `include_system`: it stays
own-tenant-only, regardless of the published row's existence. System DRAFTS
and user-private system rows are never visible to another tenant. Mutations
never widen: every lookup that feeds a write keeps `include_system=False`, and
`can_mutate` additionally refuses any row outside the active tenant, so a
mis-flipped call site still cannot write a system row.

The SYSTEM tenant is NOT a super-admin (owner's ruling 2026-10-02, cancelling
G-B): when the active tenant is the system tenant, `scope()` applies the
ordinary own-tenant clause exactly like any other tenant, so it can never read
another tenant's (customer) data. The only cross-tenant direction that exists
is a PLATFORM tenant reading SYSTEM-PUBLISHED rows, above. `is_inherited`
treats the system tenant reading its own rows as ordinary own rows.

Same shape as procedure_management's `repositories/visibility.py`, plus the
publish gate that tenant has no equivalent of.
"""

from typing import Any

from sqlalchemy import and_, or_
from sqlalchemy.sql.expression import Select

from core.config import get_settings
from tenant_id import canonical_tenant_id

PUBLISHED = "published"


def may_inherit_system(tenant_id: str) -> bool:
    """Owner's ruling 2026-09-30: only PLATFORM tenants may inherit SYSTEM rows.

    System and improvement data must never be visible to a customer tenant, so
    the published-system widen in :func:`scope` is gated on the caller being in
    ``settings.artifacts_platform_tenant_ids``. Read at CALL time (not captured
    at import) so tests and ops can change the list live — same convention as
    ``routes.artifacts._system_tenant_id``. Mirrors procedure_management's
    `may_inherit_system`.
    """
    if not tenant_id:
        return False
    t = canonical_tenant_id(str(tenant_id)) or str(tenant_id)
    platform = {
        canonical_tenant_id(str(p)) or str(p) for p in get_settings().artifacts_platform_tenant_ids
    }
    return t in platform


def scope(
    stmt: Select,
    model: Any,
    *,
    tenant_id: str,
    subject_id: str,
    include_system: bool = False,
    system_tenant_id: str | None = None,
) -> Select:
    """Narrow a SELECT to rows visible to (tenant_id, subject_id).

    Returns:
        - all rows in the tenant with visibility='tenant' (this includes the
          system tenant itself: it gets no wider scope than any other tenant,
          so every statement carries a `tenant_id` predicate), plus
        - rows in the tenant with visibility='user' that the caller owns,
        - (only when `include_system`, `system_tenant_id != tenant_id` AND the
          caller is a PLATFORM tenant — `may_inherit_system`) rows in the
          system tenant with visibility='tenant' AND publish_status='published'.
          A non-platform (customer) tenant's SELECT is unaffected by
          `include_system`: it stays own-tenant-only.
    """
    own_clause = and_(
        model.tenant_id == tenant_id,
        or_(
            model.visibility == "tenant",
            and_(model.visibility == "user", model.subject_id == subject_id),
        ),
    )
    if (
        include_system
        and system_tenant_id
        and system_tenant_id != tenant_id
        and may_inherit_system(tenant_id)
    ):
        return stmt.where(
            or_(
                own_clause,
                and_(
                    model.tenant_id == system_tenant_id,
                    model.visibility == "tenant",
                    model.publish_status == PUBLISHED,
                ),
            )
        )
    return stmt.where(own_clause)


def is_inherited(row: Any, *, tenant_id: str, system_tenant_id: str | None) -> bool:
    """True when `row` reached `tenant_id` only by system inheritance.

    This is the wire's `is_system`: a system-tenant row read by a DIFFERENT
    tenant. The system tenant reading its own rows gets False — for it they are
    ordinary own rows, writable, and its responses stay exactly as before.
    """
    if not system_tenant_id or system_tenant_id == tenant_id:
        return False
    return str(row.tenant_id) == system_tenant_id


def can_mutate(row: Any, *, subject_id: str, tenant_id: str) -> bool:
    """True if caller may mutate row.

    - row outside the active tenant (e.g. an inherited system row): never.
      `tenant_id` is REQUIRED so a new call site cannot forget the check.
    - tenant-visible: any tenant member (caller is in the tenant by virtue
      of having reached this row through scope()).
    - user-visible: only the creator.
    """
    # str(): tenant_id is Uuid(as_uuid=False) today, but a bare UUID != str
    # comparison is always True — see models/artifact.py tenant_id comment.
    if str(row.tenant_id) != tenant_id:
        return False
    if row.visibility == "tenant":
        return True
    return bool(row.subject_id == subject_id)
