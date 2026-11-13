"""Health check routes."""

import asyncio
import logging
from datetime import UTC, datetime

import sqlalchemy.exc
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import get_settings
from core.database import get_db
from services import StorageService, VirusScanner

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])
settings = get_settings()


async def _discard_failed_statement(db: AsyncSession) -> None:
    """Return a session whose statement failed (or was cancelled) to a clean state.

    Both probes below deliberately SWALLOW database failures — that is their
    whole job: report "not ready" rather than propagate. But swallowing is not
    the same as cleaning up, and the difference was a live production 500.

    What happened: ``asyncio.wait_for`` cancels the in-flight ``db.execute``,
    SQLAlchemy invalidates the connection, and the ``Session`` is left holding a
    transaction it can no longer use. The probe then returns its 503 *normally*,
    so ``core.database.get_db`` reaches its post-yield ``await session.commit()``
    (``database.py:45``), which tries to revalidate the dead connection and
    raises::

        sqlalchemy.exc.PendingRollbackError: Can't reconnect until invalid
        transaction is rolled back.

    ``get_db`` re-raises it, so the carefully-constructed 503 never reaches the
    client: Kubernetes sees a **500 with a traceback** from the endpoint whose
    entire contract is "answer cleanly when the database is unwell". Confirmed
    live in the ``artifacts`` pod: ``Readiness check timed out`` immediately
    followed by ``Database session error, rolling back``.

    ``rollback()`` is the documented remedy the exception itself names. After it
    the session holds no transaction, so ``get_db``'s ``commit()`` autobegins and
    commits an empty transaction — it never acquires a connection, so it cannot
    fail even when the database is genuinely gone.

    The rollback is itself guarded: a probe that can raise while reporting the
    database is unreachable is a probe that reports 500 exactly when 503 is the
    answer, which is the defect this function exists to remove.

    Args:
        db: The session whose in-flight statement failed or was cancelled.
    """
    try:
        await db.rollback()
    except OSError, sqlalchemy.exc.SQLAlchemyError:
        logger.warning("Rollback after a failed health probe statement failed", exc_info=True)


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    service: str
    version: str
    timestamp: datetime
    checks: dict[str, bool]


@router.get(
    "/health",
    operation_id="health_check",
    summary="Check service health",
    response_model=HealthResponse,
)
async def health_check(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    """
    Health check endpoint.

    Checks:
    - Database connectivity
    - MinIO connectivity
    - ClamAV connectivity (if enabled)

    All checks run in parallel with 10s overall timeout.
    """
    loop = asyncio.get_running_loop()

    async def db_check() -> tuple[str, bool]:
        try:
            result = await db.execute(text("SELECT 1"))
            return ("database", result.scalar() == 1)
        except (OSError, sqlalchemy.exc.SQLAlchemyError) as e:
            logger.error(f"Database health check failed: {e}")
            # Same trap as the readiness probe: reporting the failure is not the
            # same as cleaning up after it, and this handler also returns
            # normally into get_db's post-yield commit.
            await _discard_failed_statement(db)
            return ("database", False)

    async def storage_check() -> tuple[str, bool]:
        def check_storage() -> bool:
            try:
                storage = StorageService()
                return storage.health_check()
            except (OSError, RuntimeError) as e:
                logger.error(f"Storage health check failed: {e}")
                return False

        try:
            result = await asyncio.wait_for(loop.run_in_executor(None, check_storage), timeout=5.0)
            return ("storage", result)
        except TimeoutError:
            logger.error("Storage health check timed out")
            return ("storage", False)

    async def clamav_check() -> tuple[str, bool]:
        if not settings.enable_virus_scanning:
            return ("virus_scanner", True)

        def check_clamav() -> bool:
            try:
                scanner = VirusScanner()
                return scanner.ping()
            except (ConnectionError, OSError, RuntimeError) as e:
                logger.error(f"Virus scanner health check failed: {e}")
                return False

        try:
            result = await asyncio.wait_for(loop.run_in_executor(None, check_clamav), timeout=5.0)
            return ("virus_scanner", result)
        except TimeoutError:
            logger.error("Virus scanner health check timed out")
            return ("virus_scanner", False)

    # Run all checks in parallel with overall 10s timeout
    try:
        results = await asyncio.wait_for(
            asyncio.gather(db_check(), storage_check(), clamav_check()),
            timeout=10.0,
        )
        checks = dict(results)
    except TimeoutError:
        logger.error("Overall health check timed out")
        # This timeout cancels db_check() mid-statement, which is the exact
        # state that produced PendingRollbackError in production — the inner
        # `except` above never runs on a cancellation, so the cleanup must also
        # happen here.
        await _discard_failed_statement(db)
        checks = {"database": False, "storage": False, "virus_scanner": False}

    # Determine overall status
    overall_status = "healthy" if all(checks.values()) else "unhealthy"

    return HealthResponse(
        status=overall_status,
        service=settings.service_name,
        version="0.1.0",
        timestamp=datetime.now(UTC),
        checks=checks,
    )


@router.get(
    "/health/live",
    operation_id="health_live",
    summary="Kubernetes liveness probe",
    status_code=status.HTTP_200_OK,
)
async def liveness_probe() -> dict:
    """Liveness probe for Kubernetes."""
    return {"status": "alive"}


@router.get(
    "/health/ready",
    operation_id="health_ready",
    summary="Kubernetes readiness probe",
)
async def readiness_probe(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Readiness probe for Kubernetes.

    Returns 200 when the database is reachable, otherwise 503 so that
    Kubernetes pulls the pod out of the Service endpoints while the DB is
    unreachable. Only the database is gated here (MinIO/ClamAV are out of
    scope for readiness).
    """
    try:
        await asyncio.wait_for(db.execute(text("SELECT 1")), timeout=5.0)
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready"})
    except TimeoutError:
        logger.error("Readiness check timed out")
        # The cancelled statement left this session unusable; clean it up before
        # returning, or get_db's post-yield commit turns this 503 into a 500.
        await _discard_failed_statement(db)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "error": "Database check timed out"},
        )
    except (OSError, sqlalchemy.exc.SQLAlchemyError) as e:
        logger.error(f"Readiness check failed: {e}")
        await _discard_failed_statement(db)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "error": str(e)},
        )
