"""Security headers middleware.

Adds a baseline set of response security headers (clickjacking, MIME sniffing,
referrer leak, HSTS, basic permissions policy). The two distinct profiles
mirror ``worker_management/src/api/security_middleware.py``:

- **Docs profile** for ``/docs`` / ``/redoc`` / ``/openapi.json`` — keeps
  Swagger UI working by allowing the FastAPI CDN.
- **Default profile** for every other route — restrictive CSP, ``X-Frame-Options:
  DENY``, HSTS with subdomain include + preload.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.responses import Response


_DOCS_PATHS: frozenset[str] = frozenset({"/docs", "/redoc", "/openapi.json"})

_DOCS_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": (
        "default-src 'self' https://cdn.jsdelivr.net https://fastapi.tiangolo.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

_DEFAULT_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach a baseline set of security headers to every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        headers = _DOCS_HEADERS if request.url.path in _DOCS_PATHS else _DEFAULT_HEADERS
        for name, value in headers.items():
            response.headers.setdefault(name, value)
        return response
