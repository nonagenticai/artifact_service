"""Boundary tests for the tenant-id VALUE TYPE (``src/tenant_id.py``).

``canonical_tenant_id`` is the single gate that decides whether a string is a
tenant id at all. Everything else in this service — the middleware's 400, the
``get_tenant_id`` re-check, the native ``uuid`` column added by alembic
``20260826_0003`` — trusts its answer, so these tests are about the FUNCTION,
not about the HTTP boundary (that is ``test_the_boundary_does_not_mint_a_tenant``).

The two tests that carry weight here are the round-trip-guard tests at the
bottom. They are the only ones that fail if the guard in ``canonical_tenant_id``
is deleted; every other test in this file passes against a naive
``try: uuid.UUID(v) except: return None``.
"""

from __future__ import annotations

import uuid

import pytest

from tenant_id import MAX_TENANT_ID_LENGTH, canonical_tenant_id, is_tenant_id

#: One tenant, spelled the canonical way. Lowercase, dashed — the exact form
#: Postgres hands back from a ``uuid`` column, which is why it is also the form
#: ``canonical_tenant_id`` must return for every accepted spelling.
CANONICAL = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


# ---------------------------------------------------------------------------
# Accepted spellings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spelling", "label"),
    [
        ("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "dashed"),
        ("6ba7b8109dad11d180b400c04fd430c8", "dashless"),  # pragma: allowlist secret
        ("{6ba7b810-9dad-11d1-80b4-00c04fd430c8}", "braced"),
        ("{6ba7b8109dad11d180b400c04fd430c8}", "braced dashless"),
        ("urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8", "urn:uuid:"),
    ],
)
def test_every_uuid_spelling_is_accepted_and_normalised(spelling: str, label: str) -> None:
    """Each accepted spelling collapses to the ONE canonical form.

    Normalisation is not cosmetic. A value that round-trips through the
    ``artifacts.tenant_id`` uuid column comes back canonical, so a function that
    returned the caller's spelling would make ``==`` against a freshly-read row
    fail for a caller who sent the same tenant in a different case.
    """
    assert canonical_tenant_id(spelling) == CANONICAL, f"{label} spelling was not normalised"


def test_uppercase_normalises_and_the_two_spellings_compare_equal() -> None:
    """``6BA7…`` and ``6ba7…`` are one tenant, not two.

    This is the compatibility half of the change: an in-mesh caller that has
    always sent an uppercase uuid keeps working, while ``n8n-dev`` stops. If
    both spellings did not collapse, the uuid column would end up holding one
    tenant under two keys — the same "two spellings in one column" problem the
    module docstring calls out.
    """
    upper = CANONICAL.upper()
    assert upper != CANONICAL, "premise: the two spellings differ as strings"

    assert canonical_tenant_id(upper) == CANONICAL
    assert canonical_tenant_id(upper) == canonical_tenant_id(CANONICAL)


def test_the_uppercase_urn_prefix_is_rejected_and_that_is_deliberate() -> None:
    """``URN:UUID:<v>`` is refused — pinned so it is not "fixed" by lowercasing.

    ``uuid.UUID`` itself raises on the uppercase prefix (its ``replace`` calls
    are case-sensitive), so accepting it would mean lowercasing BEFORE the
    parse, i.e. accepting strictly more than the stdlib does. Measured on this
    interpreter, not assumed: the premise assertion below is what makes that
    concrete.
    """
    with pytest.raises(ValueError):
        uuid.UUID(f"URN:UUID:{CANONICAL}")

    assert canonical_tenant_id(f"URN:UUID:{CANONICAL}") is None
    assert canonical_tenant_id(f"urn:uuid:{CANONICAL}") == CANONICAL


# ---------------------------------------------------------------------------
# Rejected: names, and the specific literals this change exists to kill
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "not_a_tenant",
    [
        "n8n-dev",  # THE defect: 284 rows minted by a header that named a tenant
        "test_user",  # the old bypass-branch fallback literal
        "",  # empty header
        "test-tenant",  # the old fixture literal
        "tenant-1",  # the old fixture literal
        "platform-cp-1",  # a real tenant's NAME — a name is still not an id
        "019de842-c92a-7e37-8fdd-eb0d8c5396fx",  # near-miss: one non-hex char
        "notauuid",
        "-",
        " ",
    ],
)
def test_a_name_is_not_a_tenant_id(not_a_tenant: str) -> None:
    """A charset rule is a licence to mint; only the uuid grammar is a gate."""
    assert canonical_tenant_id(not_a_tenant) is None
    assert is_tenant_id(not_a_tenant) is False


# ---------------------------------------------------------------------------
# Rejected: non-str, WITHOUT raising
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "not_a_string",
    [
        None,
        123,
        True,  # bool is an int subclass — and `len(True)` raises just the same
        False,
        1.5,
        {},
        {"tenant_id": CANONICAL},
        [],
        [CANONICAL],
        b"6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # bytes: `len()` works, parse would not
        bytearray(b"x"),
        uuid.UUID(CANONICAL),  # the parsed object, not its spelling
    ],
)
def test_non_str_input_is_refused_without_raising(not_a_string: object) -> None:
    """``isinstance`` must come BEFORE ``len()``.

    The licence-introspection payload is decoded JSON, so ``tenant_id`` can
    arrive as a number or a bool. ``len(123)`` raises ``TypeError`` OUTSIDE the
    ``try``, which would be a 500 on the licence path rather than the 401 the
    caller can act on. Calling this and letting a ``TypeError`` escape IS the
    failure — the assertion below is secondary to the call not blowing up.
    """
    assert canonical_tenant_id(not_a_string) is None
    assert is_tenant_id(not_a_string) is False


# ---------------------------------------------------------------------------
# Rejected: unbounded input
# ---------------------------------------------------------------------------


def test_over_length_input_is_refused_before_the_parser() -> None:
    """The value is forwarded downstream and written to structured logs.

    ``MAX_TENANT_ID_LENGTH`` is generous (the longest accepted spelling,
    ``{urn:uuid:…}``, is 45 chars), so anything past it is not a near-miss uuid
    — it is an unbounded header.
    """
    longest_real_spelling = f"urn:uuid:{CANONICAL}"
    assert len(longest_real_spelling) <= MAX_TENANT_ID_LENGTH, (
        "premise: the bound must not reject a legitimate spelling"
    )

    assert canonical_tenant_id("a" * (MAX_TENANT_ID_LENGTH + 1)) is None
    assert canonical_tenant_id(CANONICAL + "x" * MAX_TENANT_ID_LENGTH) is None
    # A megabyte header must be refused as cheaply as a short one, not parsed.
    assert canonical_tenant_id("0" * 1_000_000) is None


# ---------------------------------------------------------------------------
# ⛔ NON-VACUITY. These two are the tests that fail if the round-trip guard in
#    canonical_tenant_id is deleted. Everything above still passes without it.
# ---------------------------------------------------------------------------


#: Values MEASURED (python 3.14.3) to be ACCEPTED by bare ``uuid.UUID`` while
#: not being a spelling of the uuid it returns. ``uuid.UUID`` strips ``urn:`` /
#: ``uuid:`` / braces / dashes, requires exactly 32 remaining characters, then
#: calls ``int(hex, 16)`` — and ``int`` tolerates surrounding whitespace and a
#: sign, so a whitespace character INSIDE the 32-char window silently stands in
#: for a hex digit and the parse lands on a DIFFERENT, perfectly valid uuid.
_WHITESPACE_MANGLES = [
    " ba7b8109dad11d180b400c04fd430c8",  # leading space inside the 32-char block
    "\tba7b8109dad11d180b400c04fd430c8",  # tab
    "\nba7b8109dad11d180b400c04fd430c8",  # newline — the header-splitting shape
    "ba7b8109dad11d180b400c04fd430c8 ",  # trailing space inside the block
    "{ ba7b8109dad11d180b400c04fd430c8}",  # braced, so the block is still 32
]


@pytest.mark.parametrize("mangled", _WHITESPACE_MANGLES)
def test_round_trip_guard_rejects_embedded_whitespace_that_uuid_module_accepts(
    mangled: str,
) -> None:
    """The guard's whole reason to exist, proved against the real stdlib.

    THE PREMISE IS ASSERTED FIRST. Without it this test proves nothing about
    Python and everything about my imagination: if a future CPython tightened
    ``uuid.UUID`` so these raised, the second half would pass trivially and the
    test would keep reporting green while guarding nothing.

    What the premise establishes: ``uuid.UUID(mangled)`` SUCCEEDS, and the uuid
    it returns is NOT what the string spells. A mangled header is therefore not
    refused by the parser — it silently lands in ANOTHER TENANT's data scope.
    Only the round-trip guard turns that into a rejection.

    ⛔ Delete the ``value.lower().removeprefix(...)... != parsed.hex`` check in
    ``tenant_id.py`` and THIS is the test that goes red.
    """
    # --- premise: the stdlib accepts it, and lands somewhere else -----------
    parsed = uuid.UUID(mangled)  # must NOT raise; if it does, the premise died
    assert str(parsed) != mangled.strip(), (
        "premise: the parse must land on a uuid the input does not spell"
    )
    assert str(parsed) == "0ba7b810-9dad-11d1-80b4-00c04fd430c8", (
        "premise: the whitespace stood in for a hex digit and produced 0ba7…, "
        f"not the 6ba7… a reader would expect; got {parsed}"
    )

    # --- the gate refuses it ------------------------------------------------
    assert canonical_tenant_id(mangled) is None, (
        "the round-trip guard is gone: a whitespace-mangled header just resolved "
        "to a different tenant"
    )


#: Arabic-Indic digits. ``int(x, 16)`` accepts any character with a Unicode
#: decimal value, so these parse into a valid — and different — uuid. Measured
#: on python 3.14.3; unlike the whitespace class this one has held across every
#: CPython that has an ``int(str, 16)``.
_NON_ASCII_DIGIT_MANGLES = [
    ("٦ba7b810-9dad-11d1-80b4-00c04fd430c8", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
    ("٦٦٦7b810-9dad-11d1-80b4-00c04fd430c8", "6667b810-9dad-11d1-80b4-00c04fd430c8"),
    ("6ba7b810-9dad-11d1-80b4-00c04fd430c٨", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
]


@pytest.mark.parametrize(("mangled", "lands_on"), _NON_ASCII_DIGIT_MANGLES)
def test_round_trip_guard_rejects_non_ascii_decimal_digits_that_uuid_module_accepts(
    mangled: str, lands_on: str
) -> None:
    """Same guard, second class of input — non-ASCII decimal digits.

    Premise first again: ``uuid.UUID`` ACCEPTS ``٦ba7b810-…`` and returns
    ``6ba7b810-…``. The string is not ASCII hex anywhere, yet it resolves to a
    real tenant. Two visually distinct headers therefore address ONE scope, and
    a caller can reach a tenant whose id it cannot spell.

    ⛔ Delete the round-trip guard and this goes red alongside the whitespace
    test above.
    """
    # --- premise -----------------------------------------------------------
    parsed = uuid.UUID(mangled)  # must NOT raise
    assert str(parsed) == lands_on, f"premise: expected the parse to land on {lands_on}"
    assert mangled != lands_on, "premise: the input is not a spelling of what it parses to"
    assert not mangled.isascii(), "premise: the input is genuinely non-ASCII"

    # --- the gate refuses it ------------------------------------------------
    assert canonical_tenant_id(mangled) is None, (
        f"the round-trip guard is gone: a non-ASCII-digit header just resolved to tenant {lands_on}"
    )


def test_the_urn_prefix_strip_is_global_and_the_guard_catches_it() -> None:
    """``uuid.UUID`` strips ``urn:`` / ``uuid:`` ANYWHERE, not just as a prefix.

    Measured: ``"<uuid>urn:"`` and ``"uuid:<uuid>"`` both parse. Neither is a
    spelling this service should accept, and again only the round-trip guard
    says so — the parser is happy.
    """
    for mangled in (
        f"{CANONICAL}urn:",
        f"uuid:{CANONICAL}",
        "6ba7b810-9dad-11d1-80b4-urn:00c04fd430c8",
    ):
        assert uuid.UUID(mangled) == uuid.UUID(CANONICAL), "premise: the stdlib accepts it"
        assert canonical_tenant_id(mangled) is None


def test_stray_dashes_and_braces_are_ACCEPTED_and_that_is_measured_not_intended() -> None:
    """Pin what the guard actually lets through, so nobody re-derives it wrongly.

    The guard mirrors the stdlib's own ``strip("{}")`` and ``replace("-", "")``,
    so a value with EXTRA dashes or doubled braces round-trips and is accepted.
    Measured, not assumed — this test exists so the accepted set is written down
    somewhere other than a reader's assumption, and so that narrowing it later
    is a deliberate red test rather than a surprise.

    This is harmless where the whitespace and non-ASCII-digit cases are not:
    these spellings resolve to the uuid they visibly spell, so no caller lands
    in a tenant it did not name. It is a cosmetic widening, not a scope leak.
    """
    for tolerated in (
        f"-{CANONICAL}-",
        f"{{{{{CANONICAL}}}}}",
        "6ba7b810--9dad-11d1-80b4-00c04fd430c8",
    ):
        assert canonical_tenant_id(tolerated) == CANONICAL, (
            f"{tolerated!r} used to be accepted; if this is now a rejection, that is a "
            "narrowing — confirm it is deliberate before editing this test"
        )
