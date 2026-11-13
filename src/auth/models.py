"""User models for authentication.

Simple license-based auth. No Keycloak/JWT.
"""

from typing import Any

# User is now just a dict from request.state.user
# Keys: user_id, tenant_id, sub
User = dict[str, Any]
