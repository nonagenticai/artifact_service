"""Prometheus metrics for artifact_service.

The service's first Prometheus surface. Naming follows the estate convention
(``<service>_<thing>_total``, every label bounded) used by
``requirements_management/src/metrics.py`` and ``kag_common.metrics``.

Exposed on the DEDICATED metrics-only listener (``metrics_server.py``,
``METRICS_PORT``), never on the API port.

⛔ NOTHING HERE ENFORCES ANYTHING. These counters only count.
"""

from __future__ import annotations

from typing import Final, Literal

from prometheus_client import Counter

#: Where the request's tenant came from. EXACTLY the three outcomes
#: ``AuthMiddleware.dispatch`` distinguishes — the same split that sets
#: ``request.state.tenant_from_fallback``:
#:
#: * ``licence``          — resolved from an introspected licence token.
#: * ``licence_delegated`` — an introspected licence whose SUBJECT is on
#:   ``AUTH_DELEGATING_SUBJECTS`` named ANOTHER tenant (``X-Effective-Tenant-Id``,
#:   or a plain ``X-Tenant-Id`` beside an ``Authorization`` licence). The tenant
#:   is caller-named but vouched for by that delegating licence.
#: * ``explicit_header``  — a caller-named, uuid-gated ``X-Tenant-Id`` (trusted
#:   peer, or the AUTH-bypass branch).
#: * ``fallback_default`` — ``X-Tenant-Id`` ABSENT, served as
#:   ``DEFAULT_TENANT_ID`` (the SYSTEM tenant). Only reachable with
#:   ``AUTH_TENANT_FALLBACK_MODE=observe``; this is the population the design
#:   (TENANCY_AND_IMPROVEMENT.md §4.3, D3 gate 1) needed to see before the
#:   fallback could be closed.
#: * ``refused_missing_tenant`` — ``X-Tenant-Id`` ABSENT under
#:   ``AUTH_TENANT_FALLBACK_MODE=enforce`` (the default): 401
#:   ``TENANT_REQUIRED``, no tenant resolved. The ONE rejection that is
#:   counted, because it is the same population as ``fallback_default`` after
#:   the switch flips — without it the closed fallback would be invisible.
#:
#: Every other rejected request (400/401) resolves no tenant and is not counted.
TenantSource = Literal[
    "licence", "licence_delegated", "explicit_header", "fallback_default", "refused_missing_tenant"
]
TENANT_SOURCES: Final[tuple[TenantSource, ...]] = (
    "licence",
    "licence_delegated",
    "explicit_header",
    "fallback_default",
    "refused_missing_tenant",
)

tenant_resolution_total = Counter(
    "artifact_service_tenant_resolution",
    "Requests admitted by AuthMiddleware, by where the tenant was resolved from "
    "(plus refused_missing_tenant: header-less requests refused under enforce).",
    ["source"],
)
# Pre-create every child at 0: a counter child born on its first increment is
# invisible to increase() for that first event, and an absent series cannot be
# told apart from a broken scrape. Emitting all three from startup makes
# `fallback_default == 0` a measurement rather than an absence.
for _source in TENANT_SOURCES:
    tenant_resolution_total.labels(source=_source)


def record_tenant_source(source: TenantSource) -> None:
    """Count one resolved tenant. Never raises into the auth path."""
    try:
        tenant_resolution_total.labels(source=source).inc()
    except Exception:  # pragma: no cover - a metric must never break auth
        pass


#: artifact_service#53 — was a trusted-peer ``X-Tenant-Id: <uuid>`` PROVEN by a
#: licence in ``Authorization: Bearer``? Only the trusted-network branch with a
#: uuid header reaches this decision (``AUTH_TENANT_PROOF_MODE``):
#:
#: * ``explicit_header_proven``   — licence active and its tenant == the header.
#: * ``explicit_header_delegated`` — licence active, its SUBJECT is a delegating
#:   subject, and the header names the tenant it acts for (admitted, both modes).
#: * ``explicit_header_unproven`` — no / inactive / unintrospectable licence;
#:   admitted under ``observe`` (the default). The population ``enforce`` would cut.
#: * ``explicit_header_mismatch`` — RETIRED (no longer emitted; kept pre-created
#:   so existing queries read 0, not absent). It counted an active licence for a
#:   DIFFERENT tenant admitted under ``observe``; measured 0 in production, and
#:   since the ``Authorization`` licence port (RM #222 semantics) that request is
#:   refused in BOTH modes and counted ``refused_tenant_mismatch``.
#: * ``refused_tenant_mismatch``  — active licence for a different tenant, from a
#:   non-delegating subject: 403, both modes.
#: * ``refused_unproven_tenant``  — unproven under ``enforce``: 401.
#:
#: A SEPARATE counter on purpose, not more ``TenantSource`` labels: the source is
#: still the explicit header either way, so ``tenant_resolution_total`` keeps
#: counting it as ``explicit_header`` and every query on that series is
#: unchanged. Proof is an orthogonal dimension of the same request.
TenantProof = Literal[
    "explicit_header_proven",
    "explicit_header_delegated",
    "explicit_header_unproven",
    "explicit_header_mismatch",
    "refused_tenant_mismatch",
    "refused_unproven_tenant",
]
TENANT_PROOFS: Final[tuple[TenantProof, ...]] = (
    "explicit_header_proven",
    "explicit_header_delegated",
    "explicit_header_unproven",
    "explicit_header_mismatch",
    "refused_tenant_mismatch",
    "refused_unproven_tenant",
)

tenant_proof_total = Counter(
    "artifact_service_tenant_proof",
    "Trusted-network requests with a uuid X-Tenant-Id, by whether a licence in "
    "Authorization proved that tenant (refused_* = rejected).",
    ["outcome"],
)
for _outcome in TENANT_PROOFS:
    tenant_proof_total.labels(outcome=_outcome)


def record_tenant_proof(outcome: TenantProof) -> None:
    """Count one tenant-proof decision. Never raises into the auth path."""
    try:
        tenant_proof_total.labels(outcome=outcome).inc()
    except Exception:  # pragma: no cover - a metric must never break auth
        pass


#: ``X-Effective-Tenant-Id`` decisions on a licence-authenticated request:
#:
#: * ``delegated``              — a delegating subject was re-scoped to another tenant.
#: * ``refused_not_delegating`` — a subject NOT on ``AUTH_DELEGATING_SUBJECTS``
#:   named a tenant other than its licence's own: 403 ``EFFECTIVE_TENANT_FORBIDDEN``.
#: * ``refused_malformed``      — the header is present but not a tenant uuid: 400.
#:
#: An effective tenant EQUAL to the licence's own is a no-op and is not counted.
EffectiveTenantOutcome = Literal["delegated", "refused_not_delegating", "refused_malformed"]
EFFECTIVE_TENANT_OUTCOMES: Final[tuple[EffectiveTenantOutcome, ...]] = (
    "delegated",
    "refused_not_delegating",
    "refused_malformed",
)

effective_tenant_total = Counter(
    "artifact_service_effective_tenant",
    "Licence-authenticated requests naming an effective tenant other than the "
    "licence's own, by outcome.",
    ["outcome"],
)
for _eff in EFFECTIVE_TENANT_OUTCOMES:
    effective_tenant_total.labels(outcome=_eff)


def record_effective_tenant(outcome: EffectiveTenantOutcome) -> None:
    """Count one effective-tenant decision. Never raises into the auth path."""
    try:
        effective_tenant_total.labels(outcome=outcome).inc()
    except Exception:  # pragma: no cover - a metric must never break auth
        pass
