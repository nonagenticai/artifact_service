"""The tenant id VALUE TYPE — what may be accepted as a tenant identifier here.

Counterpart to ``auth/tenant.py``, and deliberately not merged into it: that
module records *how* a request's tenant was established (provenance); this one
answers *whether a string is a tenant id at all* (shape). They are separate
concerns and they fail differently — a bad provenance still yields a usable data
scope, a bad shape yields no tenant at all.

⛔ THIS MODULE LIVES AT THE TOP LEVEL, NOT IN ``auth/``. DO NOT MOVE IT BACK.
Its importers include ``core.config``, and importing ANY name from the ``auth``
package executes ``auth/__init__.py``, which eagerly imports ``auth.middleware``,
which reads Settings at import time. From ``core.config`` that re-enters
``Settings()`` mid-construction: measured nesting depth 2, two Settings objects
per cold start (the inner one wins the ``get_settings`` lru_cache), and a
missing env var renders as ``default_tenant_id.jwt_secret_key — Field required``
— an error naming the wrong field, during a Recreate-strategy outage. A
top-level module has no package ``__init__`` to execute, so there is nothing to
re-enter. ``procedure_management`` places it here for the same reason.

WHY THIS MODULE EXISTS
----------------------
A CHARSET RULE IS NOT A VALIDATION RULE; IT IS A LICENCE TO MINT. The bare
``X-Tenant-Id`` path admitted anything a header could carry, so any peer inside
``TRUSTED_CIDRS`` — in production the whole pod CIDR ``10.0.0.0/8`` — could
CREATE a tenant simply by naming one, and every row it wrote became permanently
addressable under that name. That is how the literal string ``n8n-dev`` came to
own 284 rows in this database.

No regex over ``[A-Za-z0-9_-]`` can express "is a tenant id"; only the uuid
grammar can. So this module is the single gate. A value that is not a uuid is
not a tenant, and the caller returns 400 rather than substituting a default —
quietly downgrading an unresolvable tenant to ``DEFAULT_TENANT_ID`` would hand
the caller *that* tenant's data scope.

WHAT THIS STILL STOPS, now as a side effect rather than as the goal: CR/LF
header-splitting (``"<uuid>\\nX-Injected: v"`` is not a uuid), whitespace-
smuggled ``Bearer`` values, log forging, and unbounded-length headers — the
value is forwarded verbatim downstream and is written into structured logs.

⛔ THIS GATE CONSTRAINS THE **SHAPE** OF A TENANT ID, NOT THE **EXISTENCE** OF
THE TENANT. Nothing here — and nothing in ``auth/middleware.py`` — checks that
the uuid names a row in ``licenses.tenants``, so a trusted in-mesh peer sending
``X-Tenant-Id: 00000000-dead-beef-cafe-000000000042`` with no token still gets
200 and still owns whatever it writes. Minting is NARROWED to uuid-shaped values,
not CLOSED; closing it needs registry validation at the boundary and is a
separate unit of work.

NO NAME RESOLUTION. ``billing_service/src/tenancy.py`` carries a frozen snapshot
of ``licenses.tenants`` so a NAME like ``n8n-dev`` resolves to its uuid. This
service deliberately has no such table: resolving a name behind a bare header
would re-open the minting path this module closes. If a real name→uuid need
ever appears here, it belongs behind an introspected license, not behind a
header any in-mesh peer can set.
"""

from __future__ import annotations

import uuid

#: Longest string worth attempting to parse. A uuid in any accepted spelling is
#: at most 45 characters (``urn:uuid:`` + braces), so this is generous; it exists
#: so an unbounded header is rejected before it reaches the parser, not as a
#: validation rule of its own.
MAX_TENANT_ID_LENGTH = 64


def canonical_tenant_id(value: object) -> str | None:
    """The canonical lowercase-dashed uuid for ``value``, or ``None``.

    ``None`` means "this is not a tenant id" — it is never a soft failure the
    caller may paper over with a default.

    Accepts every spelling ``uuid.UUID`` accepts (dashed, dashless, braced,
    ``urn:uuid:``) and NORMALISES all of them to one form, which is why an
    uppercase uuid keeps working after this change while ``n8n-dev`` stops.
    Surrounding whitespace is NOT accepted: ``uuid.UUID`` rejects it, and that is
    what makes the smuggled ``" Bearer <tok>"`` shape unrepresentable here.

    The normalisation matters beyond ergonomics: Postgres stores ``uuid``
    canonically, so a value that round-trips through the database comes back in
    this exact spelling. Returning anything else would make ``==`` comparisons
    against a freshly-read row fail for a caller who sent the same tenant.
    """
    # isinstance BEFORE len(). The licence-introspection payload is decoded JSON,
    # so ``tenant_id`` can arrive as a number or a bool, and ``len()`` on those
    # raises TypeError OUTSIDE any try — a 500, not a 401. The parameter is typed
    # ``object`` rather than ``str | None`` for exactly that reason: the wire can
    # hand this function anything JSON can express.
    if not isinstance(value, str) or not value:
        return None
    if len(value) > MAX_TENANT_ID_LENGTH:
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None

    # ⛔ ROUND-TRIP GUARD — ``uuid.UUID`` is far more permissive than it looks.
    # It strips the value to hex digits and calls ``int(x, 16)``, which ignores
    # internal whitespace and accepts non-ASCII decimal digits. Measured: both
    # ``{6ba7b8109dad11d180b400c04fd430c<TAB>}`` and ``٦ba7b810-...``
    # (Arabic-Indic six) parse — the first into a DIFFERENT, perfectly valid
    # uuid. Without this check a mangled header is not refused; it silently
    # lands in ANOTHER TENANT's scope, which is the failure this module exists
    # to stop. Both are refused here.
    #
    # ⛔ WHAT THIS CHECK ACTUALLY GUARANTEES — corrected 2026-08-26, because the
    # comment that used to sit here overstated it as "accept only a recognised
    # SPELLING of the value being returned", and a comment that overstates a
    # guard teaches the next reader to trust a bound that is not there.
    #
    # It is a VALUE-PRESERVATION check, not a canonical-spelling allowlist. It
    # is SOUND — no admitted value can mean a uuid other than the one returned,
    # because the comparison is against ``parsed.hex`` where ``parsed`` IS
    # ``uuid.UUID(value)``, so passing ties the two together by construction.
    # Measured: 300,000 fuzzed strings over the alphabet ``[0-9a-fA-F-{}\t ٦:urn]``
    # produced ZERO admitted values whose returned uuid differed from
    # ``uuid.UUID(value)``.
    #
    # It is NOT TIGHT. ``.strip("{}")`` removes any number of braces and
    # ``.replace("-", "")`` erases dashes wherever they sit, so these are all
    # admitted and all normalise to the same uuid: ``{{<uuid>}}``, ``-<uuid>-``,
    # ``<uuid>`` with doubled or misplaced dashes, ``urn:uuid:{<uuid>}``.
    #
    # DELIBERATELY LEFT LOOSE. Tightening to an exact allowlist of the four
    # documented spellings would buy no security — soundness above already
    # denies the only failure that matters, a value landing in another tenant's
    # scope — while adding a way to reject a caller who is naming the RIGHT
    # tenant in a slightly odd way. The returned value is ``str(parsed)``
    # regardless, so no two spellings can become two silos in the column.
    #
    # Known and deliberate asymmetry: ``urn:uuid:<v>`` is accepted but
    # ``URN:UUID:<v>`` is not, because ``uuid.UUID`` itself raises on the
    # uppercase prefix before this check is ever reached. Widening to accept it
    # would mean lowercasing before the parse, i.e. accepting MORE than the
    # stdlib does; no caller sends that spelling, so the narrower behaviour
    # stands.
    if value.lower().removeprefix("urn:uuid:").strip("{}").replace("-", "") != parsed.hex:
        return None
    return str(parsed)


def is_tenant_id(value: object) -> bool:
    """True iff ``value`` is a tenant id. Prefer ``canonical_tenant_id``.

    Use this only where the normalised value is genuinely not wanted — an
    assertion or a guard. Anywhere the value is stored or forwarded, take the
    canonical form, or two spellings of one tenant end up in the column again.
    """
    return canonical_tenant_id(value) is not None
