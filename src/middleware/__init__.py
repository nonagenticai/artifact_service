"""HTTP middleware for the artifact service.

Canonical stack copied verbatim from nlp_service. Registration order in main.py
is the reverse of execution order — see main.py header comment for the
expected request-side flow.
"""

from middleware.logging import RequestLoggingMiddleware
from middleware.request_id import RequestIdMiddleware
from middleware.security_headers import SecurityHeadersMiddleware

__all__ = [
    "RequestIdMiddleware",
    "RequestLoggingMiddleware",
    "SecurityHeadersMiddleware",
]
