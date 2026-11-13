"""License Token Authentication Middleware.

Uses license token (`X-Tenant-Id: Bearer <token>`) as the primary auth method.
No Keycloak, no JWT, no RBAC - valid license = full access.

INGRESS LICENCE CALLERS (2026-10-11): through the public ingress the gateway
rewrites the licence carrier — it strips the client's ``X-Tenant-Id``, keeps
``Authorization: Bearer <licence>`` and injects the licence's tenant as a bare
uuid ``X-Tenant-Id``. Such a request (from a peer outside ``TRUSTED_CIDRS``) is
admitted iff the ``Authorization`` licence introspects ACTIVE to exactly that
uuid tenant — see the end of ``AuthMiddleware._dispatch``.

LICENCE CARRIERS AND DELEGATION (2026-10-14, RM #222/#223 port)
----------------------------------------------------------------
* ``X-Tenant-Id: Bearer <licence>`` — primary carrier, any network.
* ``Authorization: Bearer <licence>`` — read when X-Tenant-Id carries no
  licence. An ACTIVE one is a licence principal; a plain X-Tenant-Id beside it
  must equal the licence tenant (else 403) unless the subject delegates. A token
  that is NOT an active licence (fr's ``streamArtifact`` forwards a Keycloak
  JWT) is a hard 401 only under ``AUTH_TENANT_PROOF_MODE=enforce``; under
  ``observe`` (default) the request continues on the tokenless path unchanged.
* ``AUTH_DELEGATING_SUBJECTS`` (empty default = no delegation): an introspected
  licence SUBJECT on it may name the tenant it acts for in
  ``X-Effective-Tenant-Id`` (or the plain X-Tenant-Id beside an Authorization
  licence). Tagged ``licence_delegated``. Anyone else naming a different tenant
  there gets 403 ``EFFECTIVE_TENANT_FORBIDDEN``. The licence's own tenant is
  always ``tenant_id``, never ``subject_id``.

TENANT IDS ARE UUIDS (2026-08-26)
---------------------------------
Every tenant this middleware puts on ``request.state`` now passes through
``tenant_id.canonical_tenant_id``. Before that, the bare ``X-Tenant-Id``
path accepted any string a header could carry, which meant any peer inside
``TRUSTED_CIDRS`` (in production the whole pod CIDR ``10.0.0.0/8``) could MINT a
tenant by naming one — a charset rule is a licence to mint, not a validation
rule.

DECLARED CONSEQUENCE: an in-cluster caller sending ``X-Tenant-Id: n8n-dev``
gets 200 today and **400 INVALID_TENANT_ID** after this change. Externally
nothing regresses — the gateway already 401s such requests, so the only callers
that can observe the difference are in-mesh ones.

⛔ WHAT THIS DOES NOT DO: the gate constrains the SHAPE of a tenant id, not the
EXISTENCE of the tenant — a trusted peer sending a well-formed but unregistered
uuid (``X-Tenant-Id: 00000000-dead-beef-cafe-000000000042``, no token) still
gets 200 and still owns what it writes, because nothing here consults
``licenses.tenants``. Minting is narrowed to uuid-shaped values, not closed.

The uuid grammar SUBSUMES the header-hygiene checks a charset regex used to be
asked for: CR/LF header-splitting, whitespace-smuggled ``Bearer <token>``
values, log forging, and unbounded length are all simply not uuids. There is no
separate sanitiser and none is needed.

An unresolvable tenant is 400, never a silent fallback to ``DEFAULT_TENANT_ID``:
substituting the default would hand the caller that tenant's data scope. It is
400 and not 401 because the request authenticated fine — it just named
something that is not a tenant — so no ``WWW-Authenticate`` header is sent. The
one exception is the licence branch, which stays 401: there the bad value comes
from the introspected payload, not from the client's request.

ABSENT TENANT (2026-10): a token-less request with NO ``X-Tenant-Id`` used to be
served as ``DEFAULT_TENANT_ID`` — the SYSTEM tenant — on both the trusted and
the bypass branch. Under ``AUTH_TENANT_FALLBACK_MODE=enforce`` (the default) it
is now 401 ``TENANT_REQUIRED``, counted as ``refused_missing_tenant``.
``observe`` restores the fallback (tagged ``fallback_default``) as a break-glass.
Auth-exempt paths (``PUBLIC_ENDPOINTS`` and anything outside
``PROTECTED_PREFIXES``) never reach this decision.
"""

import hashlib
import ipaddress
import logging
import os
from collections.abc import Callable
from typing import Any, Literal, cast

import httpx
from cachetools import TTLCache
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import get_settings
from metrics import (
    TenantProof,
    TenantSource,
    record_effective_tenant,
    record_tenant_proof,
    record_tenant_source,
)
from tenant_guc import current_tenant_var
from tenant_id import canonical_tenant_id

logger = logging.getLogger(__name__)

# License introspection cache (5 min TTL, 1000 entries max)
_license_cache: TTLCache = TTLCache(maxsize=1000, ttl=300)
# artifact_service#53: bearers that introspected INACTIVE on the trusted-branch proof
# check. Proof only — never consulted by the licence branch.
#   _proof_negative_cache  60 s — a genuinely inactive licence (revoked/expired).
#   _proof_not_found_cache 10 s — `token_not_found`, which is BOTH what FR's Keycloak
#     JWT gets (so each FR bearer costs ~1 round trip per 10 s, not one per request)
#     AND what a freshly rotated licence can briefly get (so under enforce a valid new
#     licence is refused for at most 10 s).
_proof_negative_cache: TTLCache = TTLCache(maxsize=1000, ttl=60)
_proof_not_found_cache: TTLCache = TTLCache(maxsize=1000, ttl=10)


def _license_introspect_url() -> str:
    """Resolve license introspection URL from settings at call time.

    Settings provides the value via the LICENSE_INTROSPECT_URL env var; the
    production validator in core.config refuses to start without it.
    """
    return get_settings().license_introspect_url


# Public endpoints that don't require authentication
PUBLIC_ENDPOINTS = {
    "/",
    "/api/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/health",
    "/health/ready",
    "/health/live",
    "/healthz",
    "/metrics",
    "/favicon.ico",
}

# Protected path prefixes
PROTECTED_PREFIXES = {"/projects", "/artifacts", "/api/artifacts"}

#: Sent as the 400 body message whenever a CLIENT-SUPPLIED X-Tenant-Id is not a
#: uuid. Fixed text: it must not echo the rejected value back to the caller.
_INVALID_TENANT_HEADER_MESSAGE = (
    "X-Tenant-Id must be a tenant UUID. A tenant name is not a tenant id; "
    "no tenant is created by naming one."
)


def _resolve_default_tenant_id() -> str:
    """Read the default tenant from the VALIDATED Settings and canonicalise it.

    This used to be an independent ``os.getenv("DEFAULT_TENANT_ID", "n8n-dev")``,
    so the service had two unrelated defaults — ``core.config.Settings`` (which
    nothing in the request path read) and this one (which decided every
    trusted-network request). They could disagree silently. There is now one
    source: ``Settings.default_tenant_id``, which reads the same env var and is
    validated there.

    Validated AT IMPORT, and ``RuntimeError`` if it is not a uuid. This
    Deployment is ``strategy: Recreate`` with 1 replica: a startup crash is at
    least a LOUD outage — CrashLoopBackOff, no endpoints, alerts — whereas a
    per-request 500 on a misconfigured default is a quiet one that looks like an
    application bug. Belt and braces with the Settings field validator: if that
    validator is ever weakened, this still refuses to serve.
    """
    configured = get_settings().default_tenant_id
    canonical = canonical_tenant_id(configured)
    if canonical is None:
        raise RuntimeError(
            f"DEFAULT_TENANT_ID must be a uuid, got {configured!r}. A tenant id is a uuid, "
            "not a name — see src/tenant_id.py. Refusing to start."
        )
    return canonical


DEFAULT_TENANT_ID = _resolve_default_tenant_id()

_TRUSTED_CIDRS_RAW = os.getenv(
    "TRUSTED_CIDRS",
    "127.0.0.1/32,::1/128,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8",
)
TRUSTED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network(cidr.strip(), strict=False)
    for cidr in _TRUSTED_CIDRS_RAW.split(",")
    if cidr.strip()
]


def _is_trusted_network(host: str | None) -> bool:
    """Check if the client IP is within a trusted CIDR range."""
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in TRUSTED_NETWORKS)
    except ValueError:
        return False


async def _introspect_license(token: str) -> dict[str, Any] | None:
    """Introspect license token to get tenant context."""
    cache_key = f"lic:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
    if cache_key in _license_cache:
        return cast(dict[str, Any], _license_cache[cache_key])

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(_license_introspect_url(), json={"token": token})
            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                if data.get("active"):
                    _license_cache[cache_key] = data
                return data
    except (httpx.HTTPError, OSError) as e:
        logger.warning(f"License introspection failed: {e}")
    return None


def _licence_tenant(license_result: dict[str, Any]) -> tuple[str | None, str | None]:
    """The tenant an ACTIVE introspected licence speaks for, canonical — or an error.

    Returns ``(tenant, None)`` or ``(None, reason)``. The ONE derivation of a
    licence's tenant: the licence branch scopes the request by it, and the
    trusted branch's proof check (artifact_service#53) compares the header
    against it. Two copies could drift, and then "proven" would mean a
    different tenant from the one a licence request is actually scoped to.

    The TENANT is ``tenant_id`` and ONLY ``tenant_id`` (2026-10-11). licenses'
    introspect returns BOTH, and ``subject_id`` is the licence HOLDER's subject
    row id — a different uuid from the tenant on every one of the 403 active
    licences (measured read-only on ``licenses.license``: 0 null tenant_id, 0
    tenant_id == subject_id). The old ``subject_id or tenant_id`` precedence
    therefore scoped every licence caller into a "tenant" named after its
    subject — procedure_management's pm#78 cross-tenant defect, fixed there the
    same way — and made the ingress-injected ``X-Tenant-Id`` (license-authz
    emits ``result.tenant_id``, never the subject) a MISMATCH for every real
    licence. No artifact row was ever written under a subject uuid (measured:
    only the two real tenants appear in ``artifacts.tenant_id``), so nothing is
    stranded. The payload is decoded JSON, so the value may be a number, a bool
    or a name — ``canonical_tenant_id`` takes ``object`` for that reason.
    """
    raw = license_result.get("tenant_id")
    if not raw:
        return None, "License token missing tenant context"
    canonical = canonical_tenant_id(raw)
    if canonical is None:
        return None, "License token tenant context is not a uuid"
    return canonical, None


def _tenant_fallback_mode() -> str:
    """``AUTH_TENANT_FALLBACK_MODE``, read from Settings at REQUEST time.

    Not captured at import like ``DEFAULT_TENANT_ID``: the mode is a policy
    switch, and reading it per request is what lets a test (or an operator via
    a restart-free settings patch) flip it without re-importing this module.
    """
    return get_settings().auth_tenant_fallback_mode


def _tenant_proof_mode() -> str:
    """``AUTH_TENANT_PROOF_MODE``, read per request for the same reason as above."""
    return get_settings().auth_tenant_proof_mode


def _tag_tenant_source(request: Request, source: TenantSource) -> None:
    """Record WHERE the tenant came from — the ONE place that does so.

    Sets the ``request.state.tenant_from_fallback`` source tag the routes read
    (``auth.tenant.tenant_is_from_fallback``) AND increments
    ``artifact_service_tenant_resolution_total{source}`` from the same value, so
    the tag and the metric cannot disagree. Pure observation: it changes no
    admission decision.
    """
    request.state.tenant_from_fallback = source == "fallback_default"
    record_tenant_source(source)


def _bind_request_tenant(request: Request, tenant_id: str) -> None:
    """Set ``request.state.tenant_id`` AND the request-tenant ContextVar together.

    art#49: the ContextVar feeds the transaction-local ``app.current_tenant`` GUC
    (tenant_guc.py) that the RLS policies key on. Assigning both in one place is
    what keeps the GUC equal to the tenant the routes scope by — never assign
    either one alone.
    """
    request.state.tenant_id = tenant_id
    current_tenant_var.set(tenant_id)


def _admit_licence(request: Request, license_result: dict[str, Any], tenant_id: str) -> None:
    """Bind a request authenticated by an ACTIVE introspected licence.

    The ONE place both licence-authenticated paths admit a request — the
    ``X-Tenant-Id: Bearer <licence>`` branch and the untrusted ingress rescue
    (``Authorization`` licence proving the gateway-injected uuid tenant) — so
    the two cannot drift on tenant, subject or source tag.

    SECURITY: on the license path the subject comes ONLY from the INTROSPECTED
    payload — never from the wire. The old expression was
    ``request.headers.get("X-Subject-Id") or license_result.get("subject_id") or
    ""``, i.e. a client-supplied header BEAT the license-authz-validated Subject
    UUID. Any holder of any valid license token could send ``X-Subject-Id:
    <victim-subject>`` and both read and mutate that user's visibility='user'
    artifacts inside the tenant — repositories/visibility.py ``scope()`` matches
    on subject_id and ``can_mutate()`` gates on it — a within-tenant BOLA. Empty
    = "tenant-only caller" downstream: read paths then see only
    visibility='tenant' rows, and the Artifact before_insert listener
    (_autofill_subject_id) still fills subject_id := tenant_id, so writes are
    unaffected. Matches requirements_management / hirag_service.
    """
    subject_id = license_result.get("subject_id") or ""
    request.state.user = {
        "user_id": str(tenant_id),
        "tenant_id": str(tenant_id),
        "sub": str(tenant_id),
    }
    _bind_request_tenant(request, str(tenant_id))
    _tag_tenant_source(request, "licence")  # credential-resolved
    request.state.tenant_delegated = False
    request.state.subject_id = str(subject_id)
    request.state.tenant_name = request.headers.get("X-Tenant-Name", "")
    logger.debug(f"Authenticated via license token: {tenant_id} subject={subject_id!r}")


#: Wire name, identical to requirements_management / worker_management / kag_common
#: and to what fr's ``tenantBearerEnvVar`` sends. One spelling across the estate.
EFFECTIVE_TENANT_HEADER = "X-Effective-Tenant-Id"

_INVALID_EFFECTIVE_TENANT_MESSAGE = (
    "X-Effective-Tenant-Id must be a tenant UUID. A tenant name is not a tenant id."
)


def _delegating_subjects() -> frozenset[str]:
    """``AUTH_DELEGATING_SUBJECTS`` (canonical uuids), read per request.

    Empty — the default — disables delegation entirely: no subject can match.
    """
    return frozenset(get_settings().auth_delegating_subjects)


def _is_delegating(license_result: dict[str, Any]) -> bool:
    """Is the INTROSPECTED licence subject allowed to act for another tenant?

    Keyed on ``subject_id`` from license-authz's answer — a value the caller
    cannot forge — never on any header. The subject decides WHO may delegate;
    the licence's own tenant is still ``tenant_id`` and only ``tenant_id``
    (``_licence_tenant``).
    """
    subject = canonical_tenant_id(license_result.get("subject_id"))
    return subject is not None and subject in _delegating_subjects()


def _admit_delegated(
    request: Request, license_result: dict[str, Any], effective_tenant: str
) -> None:
    """Bind a DELEGATED request: a delegating licence acting for ``effective_tenant``.

    Provenance is explicit — source ``licence_delegated``,
    ``request.state.tenant_delegated = True`` and the delegator's introspected
    subject on ``request.state.delegating_subject`` — so a delegated request is
    never mistaken for one the licence's own tenant made.

    SUBJECT: the end user the delegator forwarded in ``X-Subject-Id`` (blank =
    tenant-only caller), NOT the delegator's own subject — the service account's
    subject means nothing inside the customer tenant, and owning the customer's
    ``visibility='user'`` rows as fr's service account would be wrong. Reading
    ``X-Subject-Id`` here is safe for the same reason it is on the trusted
    branch: only a caller whose introspected subject is on the allowlist reaches
    this line. It is exactly the subject fr already sends on today's tokenless
    calls, so delegated reads see the same rows as before.
    """
    request.state.user = {
        "user_id": effective_tenant,
        "tenant_id": effective_tenant,
        "sub": effective_tenant,
    }
    _bind_request_tenant(request, effective_tenant)
    _tag_tenant_source(request, "licence_delegated")
    request.state.tenant_delegated = True
    request.state.delegating_subject = str(license_result.get("subject_id") or "")
    request.state.subject_id = (request.headers.get("X-Subject-Id") or "").strip()
    request.state.tenant_name = request.headers.get("X-Tenant-Name", "")
    record_effective_tenant("delegated")
    logger.info(
        "auth.effective_tenant_delegated subject=%s effective_tenant=%s",
        request.state.delegating_subject,
        effective_tenant,
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """License Token Authentication Middleware."""

    def __init__(self, app: Any, bypass_auth: bool = False):
        super().__init__(app)
        self.bypass_auth = bypass_auth

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process authentication via license token.

        art#49: the request-tenant ContextVar starts EMPTY for every request and
        is reset when the request ends, so a tenant can never leak from one
        request into another through a reused context.
        """
        token = current_tenant_var.set(None)
        try:
            return await self._dispatch(request, call_next)
        finally:
            current_tenant_var.reset(token)

    async def _dispatch(self, request: Request, call_next: Callable) -> Response:
        """Authenticate and bind the tenant (see :meth:`dispatch`)."""
        try:
            path = request.url.path.rstrip("/") or "/"

            # Skip auth for public/non-protected endpoints
            if self._is_public_endpoint(path) or not self._is_protected(path):
                return cast(Response, await call_next(request))

            # Skip auth if bypassed (for testing) - but still use X-Tenant-Id if provided
            if self.bypass_auth or os.getenv("AUTH_ENABLED", "true").lower() == "false":
                # Header absent -> the configured default. Header present -> it
                # must be a uuid. The old `"test_user"` fallback literal is gone:
                # it wrote a non-uuid tenant into the same tables production
                # uses, so a bypass-mode run could mint the very kind of tenant
                # this middleware now refuses.
                raw_tenant_id = request.headers.get("X-Tenant-Id")
                if raw_tenant_id is None:
                    # Bypass mode is not a way round tenant separation: enforce
                    # refuses here exactly as on the trusted branch below.
                    if _tenant_fallback_mode() == "enforce":
                        return self._tenant_required_response(request, path)
                    tenant_id = DEFAULT_TENANT_ID
                else:
                    checked = canonical_tenant_id(raw_tenant_id)
                    if checked is None:
                        return self._bad_request(_INVALID_TENANT_HEADER_MESSAGE)
                    tenant_id = checked
                request.state.user = {"user_id": tenant_id, "tenant_id": tenant_id}
                _bind_request_tenant(request, tenant_id)
                # Header absent -> DEFAULT_TENANT_ID (see the trusted branch).
                _tag_tenant_source(
                    request, "fallback_default" if raw_tenant_id is None else "explicit_header"
                )
                request.state.subject_id = request.headers.get("X-Subject-Id", "")
                request.state.tenant_name = request.headers.get("X-Tenant-Name", "")
                return cast(Response, await call_next(request))

            # Extract token from X-Tenant-Id header (Bearer format)
            token = self._extract_license_token(request)
            x_tenant_id = request.headers.get("X-Tenant-Id")

            # If a token is provided, always validate it (even from trusted networks)
            if token:
                license_result = await _introspect_license(token)
                if not license_result or not license_result.get("active"):
                    return self._unauthorized_response("Invalid or expired license token")

                # 401 rather than 400 on a missing / non-uuid tenant: the fault
                # is in the licence payload the authz service returned, not in
                # anything the client sent, so the client's remedy is a
                # different token. Derivation shared with the trusted branch's
                # proof check — see `_licence_tenant`.
                license_tenant_id, licence_error = _licence_tenant(license_result)
                if license_tenant_id is None:
                    return self._unauthorized_response(
                        licence_error or "License token missing tenant context"
                    )

                # Subject from the INTROSPECTED payload only — see `_admit_licence`.
                # X-Effective-Tenant-Id: delegation for an allowlisted subject,
                # 403 for anyone else naming a different tenant.
                refused = self._admit_licence_principal(
                    request, license_result, license_tenant_id, plain_tenant=None
                )
                if refused is not None:
                    return refused
                return cast(Response, await call_next(request))

            # LICENCE IN `Authorization` (RM #222 port). X-Tenant-Id carried no
            # licence, so `Authorization: Bearer` is read as one. Three outcomes:
            #
            # * ACTIVE licence — a licence principal on ANY network. A plain
            #   X-Tenant-Id beside it is a tenant CLAIM, never ignored and never
            #   silently replaced: it must equal the licence's tenant, or the
            #   licence's subject must be a delegating subject (then the header
            #   names the tenant it acts for), else 403. This subsumes the old
            #   untrusted ingress rescue (gateway-injected uuid == licence tenant)
            #   and the trusted branch's "proven" case.
            # * NOT a licence (fr's streamArtifact forwards the user's Keycloak
            #   JWT here; it introspects `token_not_found`), revoked, or
            #   license-authz unreachable — under AUTH_TENANT_PROOF_MODE=enforce a
            #   hard 401. Under `observe` (the default) the request falls through
            #   to the tokenless logic below EXACTLY as before this port, counted
            #   `explicit_header_unproven`: live downloads keep working until the
            #   owner flips the mode on measured traffic.
            # * no Bearer in Authorization — the tokenless logic below, unchanged.
            auth_state, auth_licence = await self._authorization_licence(request)
            if auth_state == "active" and auth_licence is not None:
                license_tenant_id, licence_error = _licence_tenant(auth_licence)
                if license_tenant_id is None:
                    return self._unauthorized_response(
                        licence_error or "License token missing tenant context"
                    )
                plain_tenant: str | None = None
                if x_tenant_id is not None:
                    plain_tenant = canonical_tenant_id(x_tenant_id)
                    if plain_tenant is None:
                        return self._bad_request(_INVALID_TENANT_HEADER_MESSAGE)
                refused = self._admit_licence_principal(
                    request, auth_licence, license_tenant_id, plain_tenant=plain_tenant
                )
                if refused is not None:
                    return refused
                return cast(Response, await call_next(request))
            if auth_state == "inactive" and _tenant_proof_mode() == "enforce":
                return self._tenant_proof_required_response(
                    request, request.url.path.rstrip("/") or "/"
                )

            # No token — check if request is from a trusted network
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                # THE minting path this change closes: a trusted peer used to be
                # able to name any string here and own it. No `.strip()` any
                # more — surrounding whitespace is not a spelling of a uuid, and
                # refusing it is what makes a smuggled `" Bearer <tok>"` value
                # unrepresentable.
                #
                # ⛔ `is None`, NEVER a truthiness test. This branch used to read
                # `canonical_tenant_id(x_tenant_id) if x_tenant_id else
                # DEFAULT_TENANT_ID`, and `""` is falsy — so `X-Tenant-Id:` with
                # an EMPTY value took the else, skipped the gate entirely and was
                # silently handed DEFAULT_TENANT_ID's data scope. Measured from
                # 10.42.7.9 against the running pod: empty header -> 200, with
                # `0195f48b-…-0001`'s rows in the body. That is precisely the
                # "never a silent fallback to DEFAULT_TENANT_ID" this module's
                # docstring forbids, and it was live on the PRODUCTION branch
                # while the bypass branch above (which uses `is None`) answered
                # 400 to the same header. Header ABSENT and header PRESENT-BUT-
                # EMPTY are different requests: absent means "no opinion, use the
                # default", empty means "a tenant id that is not a uuid".
                #
                # ABSENT is itself refused under AUTH_TENANT_FALLBACK_MODE=enforce
                # (the default): DEFAULT_TENANT_ID is the SYSTEM tenant, and a
                # request that names no tenant must not land in it silently.
                # `observe` keeps the fallback as a break-glass.
                if x_tenant_id is None:
                    if _tenant_fallback_mode() == "enforce":
                        return self._tenant_required_response(request, path)
                    tenant_id = DEFAULT_TENANT_ID
                else:
                    checked_tenant_id = canonical_tenant_id(x_tenant_id)
                    if checked_tenant_id is None:
                        return self._bad_request(_INVALID_TENANT_HEADER_MESSAGE)
                    tenant_id = checked_tenant_id
                    # artifact_service#53: a uuid header from a trusted peer is
                    # a CLAIM, not a proof — any pod in TRUSTED_CIDRS could name
                    # any tenant. Proof = a licence in `Authorization: Bearer`
                    # whose tenant IS the header. Under observe (the default,
                    # owner's ruling: measure first) NOTHING is refused — an
                    # unproven or mismatched header is admitted and counted, so
                    # the flip to enforce is decided on measured traffic. Under
                    # enforce, unproven -> 401 and mismatch -> 403.
                    #
                    # An ACTIVE licence in Authorization never reaches here (it was
                    # admitted or refused above), so a uuid header on this branch is
                    # always unproven.
                    proof: TenantProof = "explicit_header_unproven"
                    if _tenant_proof_mode() == "enforce":
                        return self._tenant_proof_required_response(request, path)
                    # The source tag below stays `explicit_header` either way;
                    # proof is counted on its own series (metrics.TenantProof).
                    request.state.tenant_proof = proof
                    record_tenant_proof(proof)
                request.state.user = {
                    "user_id": str(tenant_id),
                    "tenant_id": str(tenant_id),
                    "sub": str(tenant_id),
                }
                _bind_request_tenant(request, str(tenant_id))
                # SOURCE TAG: True iff the tenant came from the absent-header
                # fallback above, never from a credential or an explicit header.
                # DEFAULT_TENANT_ID is the SYSTEM tenant, whose PUBLISHED rows
                # every tenant inherits — so routes refuse `publish_status=
                # published` when this is True (a header-less peer must not be
                # able to publish estate-wide). Only reachable in `observe` mode;
                # `enforce` refused the absent header above.
                _tag_tenant_source(
                    request, "fallback_default" if x_tenant_id is None else "explicit_header"
                )
                # DELIBERATE ASYMMETRY with the license branch above: this peer
                # is already inside the trusted CIDR set, so X-Subject-Id IS the
                # in-mesh propagated identity and is the only source of one. Do
                # NOT "fix" this to match the license branch — discovery-engine
                # inverted precedence here and broke real in-cluster callers.
                request.state.subject_id = request.headers.get("X-Subject-Id", "")
                # (The tenant above is now uuid-gated; the subject deliberately
                # is NOT — it is an opaque in-mesh identity, and gating it would
                # be exactly the "harmonisation" the comment above forbids.)
                request.state.tenant_name = request.headers.get("X-Tenant-Name", "")
                request.state.license = None
                logger.debug(f"Trusted network access from {client_host}: tenant={tenant_id}")
                return cast(Response, await call_next(request))

            # Not trusted and no ACTIVE licence in either carrier. The ingress
            # licence caller (gateway keeps `Authorization: Bearer <licence>` and
            # injects the licence's tenant as a bare uuid X-Tenant-Id; the pod
            # sees ztunnel's 169.254.7.127, outside TRUSTED_CIDRS) was admitted
            # above by the `Authorization` licence branch — equality, never
            # substitution, unless the licence's subject is a delegating one.
            return self._unauthorized_response("Missing authentication token")

        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            logger.error(f"Authentication middleware error: {e}", exc_info=True)
            return self._internal_error_response("Authentication service error")

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public."""
        if path in PUBLIC_ENDPOINTS:
            return True
        public_prefixes = ["/docs", "/redoc", "/static", "/health"]
        return any(path.startswith(prefix) for prefix in public_prefixes)

    def _is_protected(self, path: str) -> bool:
        """Check if path requires authentication."""
        return any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES)

    def _extract_license_token(self, request: Request) -> str | None:
        """The licence in ``X-Tenant-Id: Bearer <token>`` — the PRIMARY carrier.

        ``Authorization: Bearer`` is the SECOND carrier, read only when this one
        is empty (``_authorization_licence``) and only ever as a licence: a
        Keycloak JWT there (fr's ``streamArtifact``) is not a licence and is
        refused under ``AUTH_TENANT_PROOF_MODE=enforce``, ignored under
        ``observe``. It is never a credential that can silently adopt the JWT's
        or the licence's tenant over an explicit ``X-Tenant-Id`` claim.
        """
        x_tenant_id = request.headers.get("X-Tenant-Id")
        if x_tenant_id and x_tenant_id.lower().startswith("bearer "):
            return x_tenant_id[7:].strip()
        return None

    async def _authorization_licence(
        self, request: Request
    ) -> tuple[Literal["absent", "inactive", "active"], dict[str, Any] | None]:
        """Introspect ``Authorization: Bearer <token>`` as a licence.

        Returns ``("absent", None)`` when there is no non-empty Bearer,
        ``("inactive", None)`` when the token is not an active licence — a
        Keycloak JWT (``token_not_found``), a revoked licence, a payload that is
        not an object, or license-authz unreachable — and ``("active", licence)``
        otherwise. Called only when ``X-Tenant-Id`` carried no licence (that
        carrier has precedence, as in requirements_management).

        Never raises: an introspection failure is ``inactive`` and logged, so
        under ``observe`` a license-authz outage cannot turn admitted traffic
        into 500s (the outer handler in ``_dispatch`` would).
        """
        authorization = request.headers.get("Authorization", "")
        if not authorization.lower().startswith("bearer "):
            return "absent", None
        licence_token = authorization[7:].strip()
        if not licence_token:
            return "absent", None
        neg_key = hashlib.sha256(licence_token.encode()).hexdigest()[:16]
        if neg_key in _proof_negative_cache or neg_key in _proof_not_found_cache:
            return "inactive", None
        try:
            licence = await _introspect_license(licence_token)
        except Exception as e:  # noqa: BLE001 - observe must never turn admitted traffic into a 500
            # Broad on purpose: `_introspect_license` only absorbs transport
            # errors; a 200 with a non-JSON or non-object body raises
            # ValueError/AttributeError, which the outer handler would make a 500.
            logger.warning(
                "tenant_proof: licence introspection failed, treating as unproven: %s",
                type(e).__name__,
            )
            return "inactive", None
        if not isinstance(licence, dict):
            return "inactive", None
        if not licence.get("active"):
            # An ANSWERED "inactive" is remembered briefly so the same bearer does
            # not cost a license-authz round trip on every request; `None`
            # (outage) is never cached. TTLs and why: see the caches' definition.
            if licence.get("reason") == "token_not_found":
                _proof_not_found_cache[neg_key] = True
            else:
                _proof_negative_cache[neg_key] = True
            return "inactive", None
        return "active", licence

    def _admit_licence_principal(
        self,
        request: Request,
        license_result: dict[str, Any],
        licence_tenant: str,
        plain_tenant: str | None,
    ) -> Response | None:
        """Admit an ACTIVE licence — own tenant or delegated — or return the refusal.

        ``plain_tenant`` is the canonical uuid of a plain ``X-Tenant-Id`` sent
        beside an ``Authorization`` licence (``None`` for the ``X-Tenant-Id:
        Bearer`` carrier, which has no room for one).

        * Delegating subject (``AUTH_DELEGATING_SUBJECTS``): the requested tenant
          is ``X-Effective-Tenant-Id``, else the plain header. Equal to the
          licence's own tenant (or absent) → an ordinary licence principal.
          Otherwise → delegated (``_admit_delegated``). A plain header naming a
          THIRD tenant, different from both, is contradictory → 403.
        * Anyone else: ``X-Effective-Tenant-Id`` and the plain header must each
          be the licence's own tenant, else 403 (RM #223: refused, never served
          silently as the licence's own tenant).

        A malformed ``X-Effective-Tenant-Id`` is 400 for everybody. Blank = absent.
        """
        trusted = _is_trusted_network(request.client.host if request.client else None)
        raw_effective = (request.headers.get(EFFECTIVE_TENANT_HEADER) or "").strip()
        effective: str | None = None
        if raw_effective:
            effective = canonical_tenant_id(raw_effective)
            if effective is None:
                record_effective_tenant("refused_malformed")
                return self._bad_request(_INVALID_EFFECTIVE_TENANT_MESSAGE)

        path = request.url.path.rstrip("/") or "/"
        if _is_delegating(license_result):
            requested = effective or plain_tenant
            if plain_tenant is not None and plain_tenant not in (licence_tenant, requested):
                return self._tenant_proof_mismatch_response(request, path)
            if requested is None or requested == licence_tenant:
                _admit_licence(request, license_result, licence_tenant)
                if plain_tenant is not None and trusted:
                    request.state.tenant_proof = "explicit_header_proven"
                    record_tenant_proof("explicit_header_proven")
                return None
            _admit_delegated(request, license_result, requested)
            if plain_tenant is not None and trusted:
                request.state.tenant_proof = "explicit_header_delegated"
                record_tenant_proof("explicit_header_delegated")
            return None

        if effective is not None and effective != licence_tenant:
            return self._effective_tenant_forbidden_response(request, path, license_result)
        if plain_tenant is not None and plain_tenant != licence_tenant:
            return self._tenant_proof_mismatch_response(request, path)
        _admit_licence(request, license_result, licence_tenant)
        if plain_tenant is not None and trusted:
            request.state.tenant_proof = "explicit_header_proven"
            record_tenant_proof("explicit_header_proven")
        return None

    def _effective_tenant_forbidden_response(
        self, request: Request, path: str, license_result: dict[str, Any]
    ) -> Response:
        """403 ``EFFECTIVE_TENANT_FORBIDDEN`` — a non-delegating licence named another tenant.

        Neither tenant is echoed. The introspected subject IS logged: before a
        delegator is armed this is precisely the "the caller is ready, add it to
        AUTH_DELEGATING_SUBJECTS" signal.
        """
        from fastapi.responses import JSONResponse

        record_effective_tenant("refused_not_delegating")
        logger.warning(
            "auth.effective_tenant_rejected path=%s subject=%s",
            path,
            license_result.get("subject_id") or "",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "code": "EFFECTIVE_TENANT_FORBIDDEN",
                    "message": (
                        "X-Effective-Tenant-Id names a tenant other than the licence's own, "
                        "and this licence's subject is not permitted to delegate."
                    ),
                    "status": 403,
                }
            },
        )

    def _tenant_proof_required_response(self, request: Request, path: str) -> Response:
        """401 ``TENANT_PROOF_REQUIRED`` — unproven uuid header under enforce.

        Same envelope and challenge as ``_tenant_required_response``: the remedy
        is a credential (a licence for that tenant in ``Authorization``).
        """
        from fastapi.responses import JSONResponse

        client_host = request.client.host if request.client else None
        record_tenant_proof("refused_unproven_tenant")
        logger.warning(
            "tenant_proof_required: refused unproven X-Tenant-Id path=%s client=%s",
            path,
            client_host,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": {
                    "code": "TENANT_PROOF_REQUIRED",
                    "message": (
                        "tenant_proof_required: X-Tenant-Id must be proven by a licence "
                        "for that tenant in 'Authorization: Bearer <licence token>'."
                    ),
                    "status": 401,
                }
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _tenant_proof_mismatch_response(self, request: Request, path: str) -> Response:
        """403 ``TENANT_PROOF_MISMATCH`` — the licence is valid but for ANOTHER tenant.

        403, not 401, and no challenge: the credential authenticated fine, it
        just does not grant the tenant the caller named. BOTH modes since the
        ``Authorization`` licence port (RM #222): a live licence for another
        tenant is refused, never served under the header's tenant.
        Neither tenant is echoed back.
        """
        from fastapi.responses import JSONResponse

        client_host = request.client.host if request.client else None
        record_tenant_proof("refused_tenant_mismatch")
        logger.warning(
            "tenant_proof_mismatch: licence tenant != X-Tenant-Id path=%s client=%s",
            path,
            client_host,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "code": "TENANT_PROOF_MISMATCH",
                    "message": (
                        "tenant_proof_mismatch: the licence in Authorization belongs to "
                        "a different tenant than X-Tenant-Id."
                    ),
                    "status": 403,
                }
            },
        )

    def _bad_request(self, detail: str) -> Response:
        """Return 400 Bad Request in the service's standard error envelope.

        Envelope matches ``routes.responses.ErrorResponse`` — the same
        ``{"error": {"code", "message", "status"}}`` shape the 401 and 500 paths
        emit. Deliberately NOT 401 and deliberately no ``WWW-Authenticate``:
        the caller's credentials (or trusted-network position) were fine, so
        offering a re-auth challenge would send them down the wrong road. The
        message never echoes the rejected value — reflecting an attacker-chosen
        string into a response body is how a rejected header becomes a payload.
        """
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {"code": "INVALID_TENANT_ID", "message": detail, "status": 400}},
        )

    def _tenant_required_response(self, request: Request, path: str) -> Response:
        """Refuse a token-less request that sent NO ``X-Tenant-Id`` (mode=enforce).

        401 with the standard envelope, code ``TENANT_REQUIRED``. 401 and not
        400 (contrast ``_bad_request``): the caller did not name a bad tenant,
        it named none, and the remedy is to send a credential — a uuid
        ``X-Tenant-Id`` from a trusted peer, or ``X-Tenant-Id: Bearer
        <licence>`` — so the re-auth challenge is the right signal.

        Counted as ``source="refused_missing_tenant"`` (the one counted
        rejection — see ``metrics.TenantSource``) and logged once at WARNING
        with path and peer so the remaining header-less callers can be found.
        """
        from fastapi.responses import JSONResponse

        client_host = request.client.host if request.client else None
        record_tenant_source("refused_missing_tenant")
        logger.warning(
            "tenant_required: refused request without X-Tenant-Id path=%s client=%s",
            path,
            client_host,
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": {
                    "code": "TENANT_REQUIRED",
                    "message": (
                        "tenant_required: send X-Tenant-Id (a tenant UUID, or "
                        "'Bearer <licence token>'). Requests without a tenant are no "
                        "longer served as the default tenant."
                    ),
                    "status": 401,
                }
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _unauthorized_response(self, detail: str) -> Response:
        """Return 401 Unauthorized response."""
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": {"code": "AUTHENTICATION_REQUIRED", "message": detail, "status": 401}
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _internal_error_response(self, detail: str) -> Response:
        """Return 500 Internal Server Error response."""
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {"code": "AUTHENTICATION_SERVICE_ERROR", "message": detail, "status": 500}
            },
        )
