"""
Schemathesis hooks to handle nullable parameter generation.

Schemathesis generates literal strings "None" or "null" for nullable parameters,
which FastAPI correctly rejects. These hooks filter out such invalid values.
"""

from typing import Any

import schemathesis


@schemathesis.hook
def filter_query(
    _context: schemathesis.hooks.HookContext,
    query: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """
    Filter query parameters to remove null-like string values.

    Schemathesis generates "null" strings for nullable enum parameters.
    FastAPI expects these to be omitted rather than sent as literal "null".
    """
    if query is None:
        return None

    return {k: v for k, v in query.items() if v not in ("null", "None", None, "")}


@schemathesis.hook
def filter_body(
    _context: schemathesis.hooks.HookContext,
    body: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """
    Filter body/form parameters to remove null-like string values.

    Schemathesis generates "None" strings for nullable UUID parameters.
    FastAPI expects these to be omitted rather than sent as literal "None".
    """
    if body is None:
        return None

    if not isinstance(body, dict):
        return body

    return {k: v for k, v in body.items() if v not in ("null", "None", None)}
