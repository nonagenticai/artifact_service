"""Integration test fixtures for a live artifact_service.

These tests hit a REAL running artifact_service. They require:
- ARTIFACT_SERVICE_URL set explicitly (no default: unset => every test SKIPS)
- LICENSE_TOKEN set in the environment when the target enforces auth
  (no token is committed here)

ARTIFACT_SERVICE_URL that names a non-local host (any public name, LAN or
pod-network address, or a bare service name) is REFUSED unless
ALLOW_PROD_INTEGRATION=1 — a stale URL in the environment once made a hand run
upload real artifacts somewhere real. See tests/integration/target_guard.py.

Run with:  ARTIFACT_SERVICE_URL=http://localhost:8556 uv run pytest tests/integration/ -v -m integration
"""

import os

import httpx
import pytest

from .target_guard import integration_target

pytestmark = pytest.mark.integration

LICENSE_TOKEN = os.environ.get("LICENSE_TOKEN", "")

# The tenant these integration tests address on the LIVE service.
#
# Was ``"n8n-dev"``. That string is a tenant NAME, and since alembic revision
# ``20260826_0003`` it is not a tenant id at all: ``artifacts.tenant_id`` is a
# native ``uuid`` column and the boundary answers 400 INVALID_TENANT_ID to a
# bare non-uuid ``X-Tenant-Id``. Leaving the old default here would have meant
# an integration run that either 400s or, worse, silently addresses nothing.
#
# The replacement is not invented: ``licenses.tenants`` row named ``n8n-dev`` IS
# ``019de842-c92a-7e37-8fdd-eb0d8c5396f9``, and the migration REMAPPED the 284
# ``'n8n-dev'`` rows onto exactly that uuid. So this points at the same data the
# old literal pointed at. It is deliberately NOT
# ``0195f48b-d000-7000-8000-000000000001`` — that is a DIFFERENT tenant
# (``platform-cp-1``, 42,387 rows); folding one into the other is the
# cross-tenant merge the migration docstring exists to make un-repeatable.
#
# Not a test fixture value: the unit-test constants live in ``tests/conftest.py``
# as ``TEST_TENANT_A`` / ``TEST_TENANT_B`` and are fictional on purpose. This one
# names a real tenant because these tests talk to a real deployment.
TENANT_ID = os.environ.get("TENANT_ID", "019de842-c92a-7e37-8fdd-eb0d8c5396f9")


@pytest.fixture(scope="session")
def artifact_client():
    """httpx client pointed at artifact_service with license token in X-Tenant-Id."""
    url = integration_target("ARTIFACT_SERVICE_URL")  # raises ProdTargetRefused for prod
    if url is None:
        pytest.skip("ARTIFACT_SERVICE_URL not set — integration tests never default to production")
    with httpx.Client(
        base_url=url,
        headers={
            "X-Tenant-Id": f"Bearer {LICENSE_TOKEN}",
        },
        verify=False,
        timeout=30.0,
    ) as client:
        yield client
