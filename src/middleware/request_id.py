"""Request ID middleware.

Mints a uuid7 request ID on every request (if the caller did not supply one
via ``X-Request-ID``) and pins it to ``request.state.request_id`` so every
downstream middleware, log line, and exception envelope can reference the same
identifier. Echoes the value back on the response as ``X-Request-ID``.

Runs before ``RequestLoggingMiddleware`` and the auth middleware so that any
401/403/500 emitted from the auth layer carries a stable request ID.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.responses import Response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Set ``request.state.request_id`` and echo ``X-Request-ID``."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        incoming = request.headers.get("x-request-id", "").strip()
        request_id = incoming or str(uuid.uuid7())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
