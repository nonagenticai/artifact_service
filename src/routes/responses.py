"""Common response definitions for OpenAPI documentation.

Provides the error-envelope schema used across the service plus a few
ready-made response dictionaries for the per-route ``responses=`` argument.

The envelope shape matches ``worker_management/src/api/common_responses.py``'s
``{error: {code, message, status}}`` core, extended with optional
``request_id``, ``timestamp``, and ``details`` fields.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Inner error payload."""

    code: str = Field(..., description="Stable machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    status: int = Field(..., description="HTTP status code")
    request_id: str | None = Field(default=None, description="Request UUID7 for log correlation")
    timestamp: str | None = Field(
        default=None, description="ISO-8601 UTC timestamp the error was emitted"
    )
    details: str | None = Field(
        default=None,
        description="Optional debug detail; only populated when LEAK_EXCEPTION_DETAILS=true",
    )


class ErrorResponse(BaseModel):
    """Standard error response envelope."""

    error: ErrorDetail


# Shared response dicts for the FastAPI ``responses=`` decorator argument.

AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Authentication required", "model": ErrorResponse},
}

NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Resource not found", "model": ErrorResponse},
}

AUTH_AND_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    **AUTH_RESPONSES,
    **NOT_FOUND_RESPONSES,
}

#: Declares ``X-Total-Count`` on the 200 of a paged list route whose body is a
#: bare array and therefore has nowhere to carry the total. Without it in the
#: contract a generated client has no way to know the page was truncated.
TOTAL_COUNT_HEADER: dict[int | str, dict[str, Any]] = {
    200: {
        "headers": {
            "X-Total-Count": {
                "description": (
                    "Rows matching the query BEFORE limit/offset. The response is "
                    "truncated when `offset + len(body) < X-Total-Count`."
                ),
                "schema": {"type": "integer", "minimum": 0},
            }
        }
    },
}
