"""Artifact management routes with tenant + per-user isolation."""

import asyncio
import hashlib
import io
import logging
import re
import secrets
import threading
from collections.abc import AsyncGenerator
from typing import Annotated, Any, Literal
from urllib.parse import unquote
from uuid import UUID

import httpx
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import Select

from auth import get_subject_id, get_tenant_id, get_visibility, tenant_is_from_fallback
from core.config import get_settings
from core.database import get_db
from models import (
    DECISION_TO_STATUS,
    DOC_TYPE_MAX,
    PHASE_MAX,
    PLANKA_CARD_ID_MAX,
    SUMMARY_MAX,
    TITLE_MAX,
    Artifact,
    ArtifactKind,
    ArtifactMetadataIn,
    ArtifactOut,
    ArtifactReview,
    ArtifactSensitivity,
    ArtifactStatus,
    ArtifactTag,
    Manifest,
    ManifestScope,
    PublishStatus,
    PublishStatusIn,
    ReviewIn,
    ReviewOut,
    ReviewResponse,
    UploadResponse,
    validate_origin_consistency,
)
from repositories.visibility import can_mutate, is_inherited
from repositories.visibility import scope as visibility_scope
from services import StorageService, VirusScanner, document_renderer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/projects/{project_id}/artifacts", tags=["artifacts"])
# Cross-project lookup router: resolves artifacts without requiring a project_id
# in the URL. Used by n8n improvement-loop workflows that have card_id +
# tenant_id only.
cross_project_router = APIRouter(prefix="/api/artifacts", tags=["artifacts"])
settings = get_settings()

from .responses import AUTH_RESPONSES, NOT_FOUND_RESPONSES, TOTAL_COUNT_HEADER  # noqa: E402


def get_storage_service() -> StorageService:
    """Get storage service instance."""
    return StorageService()


def _system_tenant_id() -> str:
    """The tenant whose PUBLISHED rows every other tenant inherits read-only.

    Read per call from the module-level ``settings`` (not captured at import)
    so tests can patch ``routes.artifacts.settings`` like every other setting.
    """
    return str(settings.system_tenant_id)


_PUBLISH_NEEDS_EXPLICIT_TENANT = (
    "publishing requires an explicit tenant (a license credential or an X-Tenant-Id "
    "header); a request that falls back to the default tenant cannot publish"
)


def _refuse_publish_via_fallback(request: Request, publish_status: PublishStatus) -> None:
    """403 when a fallback-resolved caller asks for publish_status=published.

    The absent-header fallback resolves to DEFAULT_TENANT_ID, which is the
    SYSTEM tenant — whose PUBLISHED rows every tenant inherits. Without this
    fence any header-less trusted-network peer could publish estate-wide.
    Drafts via the fallback stay allowed (unchanged behaviour).
    """
    if publish_status is PublishStatus.PUBLISHED and tenant_is_from_fallback(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_PUBLISH_NEEDS_EXPLICIT_TENANT,
        )


#: The conveyor links an artifact to its card with a `planka_card:<id>` tag
#: (live: every one of the run-7/run-8 rows; `card_id` itself is NULL on all of
#: them). The tag is the source of truth until producers send `card_id`.
PLANKA_CARD_TAG = "planka_card:"


def card_id_from_tags(tags: list[str]) -> UUID | None:
    """The card id carried by the first parseable `planka_card:<id>` tag, else None.

    ⚠️ `card_id` is a UUID column. A tag value that is not a UUID is IGNORED here
    (never coerced, never hashed into a fake UUID): an invented id would make
    `/api/artifacts/by-card/{card_id}` answer for a card nobody can name.
    """
    for tag in tags:
        if tag.startswith(PLANKA_CARD_TAG):
            try:
                return UUID(tag[len(PLANKA_CARD_TAG) :].strip())
            except ValueError:
                continue
    return None


def planka_card_id_from_tags(tags: list[str]) -> str | None:
    """The first non-empty `planka_card:<id>` tag value (any format, <= 64 chars)."""
    for tag in tags:
        if tag.startswith(PLANKA_CARD_TAG):
            value = tag[len(PLANKA_CARD_TAG) :].strip()
            if value and len(value) <= PLANKA_CARD_ID_MAX:
                return value
    return None


@router.post(
    "/upload",
    operation_id="upload_artifact",
    summary="Upload an artifact file",
    response_model=UploadResponse,
    responses={**AUTH_RESPONSES, 400: {"description": "Invalid request body"}},
)
async def upload_artifact(
    request: Request,
    project_id: UUID,
    file: UploadFile = File(..., description="File to upload"),
    filename: str = Form(..., description="Artifact filename"),
    content_type: str = Form(..., description="MIME type"),
    kind: ArtifactKind = Form(..., description="Artifact type"),
    card_id: UUID | None = Form(
        None,
        description=(
            "Card this artifact is the output of. Supply it whenever the upload "
            "happens with a card in context — this is the deliverable link, and "
            "the only thing that makes /api/artifacts/by-card/{card_id} able to "
            "find the artifact later. Omit it ONLY for uploads with genuinely no "
            "card (human library uploads, system artefacts): those stay NULL on "
            "purpose, not by accident."
        ),
    ),
    step: str | None = Form(None, description="Optional step identifier"),
    container_name: str | None = Form(None, description="Optional container name"),
    sensitivity: ArtifactSensitivity = Form(ArtifactSensitivity.INTERNAL),
    tags: str = Form("", description="Comma-separated tags"),
    origin_kind: str = Form(
        "tenant",
        description="Provenance: tenant (human library upload) | project | workflow",
    ),
    origin_project_id: UUID | None = Form(None, description="Required when origin_kind='project'"),
    origin_workflow_run_id: str | None = Form(
        None, description="Required when origin_kind='workflow' (n8n run id, max 200 chars)"
    ),
    created_by_user_id: str | None = Form(
        None,
        description=(
            "Subject id of the creator. Defaults to the authenticated X-Subject-Id "
            "when omitted; empty string when the caller is tenant-only."
        ),
    ),
    publish_status: PublishStatus = Form(
        PublishStatus.DRAFT,
        description=(
            "draft (default) | published. Only meaningful for the system tenant: its "
            "PUBLISHED artifacts are inherited read-only by every other tenant."
        ),
    ),
    title: str | None = Form(
        None, max_length=TITLE_MAX, description="Document title shown to humans (DOC-1)"
    ),
    doc_type: str | None = Form(
        None,
        max_length=DOC_TYPE_MAX,
        description="Document type, e.g. 'analysis_report' or 'architecture_decision_record'",
    ),
    phase: str | None = Form(
        None, max_length=PHASE_MAX, description="Project phase that produced the document"
    ),
    summary: str | None = Form(
        None, max_length=SUMMARY_MAX, description="One-line summary shown in the document trail"
    ),
    planka_card_id: str | None = Form(
        None,
        max_length=PLANKA_CARD_ID_MAX,
        description=(
            "Planka card id (any format, max 64). Defaults to the value of a "
            "`planka_card:<id>` tag when omitted."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage_service),
    subject_id: str = Depends(get_subject_id),
    visibility: str = Depends(get_visibility),
) -> UploadResponse:
    """
    Upload an artifact file.

    Files are proxied through storage_service which handles MinIO storage
    and virus scanning. No presigned URLs are used.

    Pass X-Visibility: user to make the artifact private to the uploading subject.
    Default is 'tenant' (visible to all tenant members).
    """
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)
    _refuse_publish_via_fallback(request, publish_status)

    # Validate filename - enhanced path traversal protection
    # URL decode to catch encoded traversal
    decoded_filename = unquote(unquote(filename))

    # Check for null bytes
    if "\x00" in decoded_filename or "\x00" in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename cannot contain null bytes",
        )

    # Check both raw and decoded for traversal patterns
    traversal_patterns = ["..", "/", "\\", "%2e", "%2f", "%5c"]
    for pattern in traversal_patterns:
        if pattern in filename.lower() or pattern in decoded_filename.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename cannot contain path traversal characters",
            )

    # Validate content-type against whitelist
    if content_type not in settings.allowed_mimes:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Content-type '{content_type}' not allowed",
        )

    # Validate provenance BEFORE a single byte is read or stored. The database
    # holds the same rule as a CHECK constraint, so an inconsistent triple would
    # otherwise be caught on COMMIT — after the object is already in MinIO, and
    # surfacing as a 500 rather than as "your request was wrong".
    try:
        validate_origin_consistency(origin_kind, origin_project_id, origin_workflow_run_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if origin_workflow_run_id is not None and len(origin_workflow_run_id) > 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="origin_workflow_run_id exceeds 200 characters",
        )
    # Unsupplied -> the authenticated subject.
    #
    # ⚠️ MEASURED, do not "improve" this into an empty-vs-omitted distinction:
    # on a MULTIPART form FastAPI cannot tell them apart. A field sent with an
    # empty value is on the wire (`Content-Disposition: name="x"` + empty body)
    # but the form parser reports it as ABSENT — a required `str = Form(...)`
    # 422s with `type: "missing"` against it. So `created_by_user_id is None`
    # here covers BOTH "omitted" and "sent empty", and a caller that genuinely
    # wants an empty creator recorded cannot express that through this
    # endpoint. Documented rather than worked around, because a comment
    # claiming the distinction is kept would be false.
    creator_user_id = subject_id if created_by_user_id is None else created_by_user_id
    if len(creator_user_id) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="created_by_user_id exceeds 255 characters",
        )

    # Parse tags (before the scope: a `planka_card:<id>` tag can supply card_id)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    if card_id is None:
        card_id = card_id_from_tags(tag_list)
    if planka_card_id is None:
        planka_card_id = planka_card_id_from_tags(tag_list)

    # Generate artifact ID and storage key
    artifact_id = UUID(int=secrets.randbits(128))
    version = 1

    # Determine scope
    if card_id:
        scope = "card"
        scope_ref = str(card_id)
    elif step:
        scope = "step"
        scope_ref = step
    else:
        scope = "project"
        scope_ref = "_"

    storage_key = storage.generate_storage_key(
        project_id=project_id,
        scope=scope,
        scope_ref=scope_ref,
        artifact_id=artifact_id,
        version=version,
        filename=filename,
    )

    # Read file content in chunks with early size rejection
    chunks = []
    total_size = 0
    while chunk := await file.read(8192):
        total_size += len(chunk)
        if total_size > settings.max_file_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"File exceeds maximum size of {settings.max_file_size_bytes} bytes",
            )
        chunks.append(chunk)
    file_content = b"".join(chunks)
    file_size = total_size

    # Calculate SHA256
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    # Virus scan BEFORE upload
    if settings.enable_virus_scanning:
        try:
            import io

            virus_scanner = VirusScanner()
            scan_result = virus_scanner.scan_stream(io.BytesIO(file_content))
            if not scan_result.is_clean:
                logger.warning(f"Virus detected in upload: {scan_result.virus_name}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"File rejected: malware detected ({scan_result.virus_name})",
                )
        except HTTPException:
            raise
        except (ConnectionError, OSError, RuntimeError) as e:
            # FAIL CLOSED, unconditionally. `quarantine_infected_files` governs
            # what to do with a file the scanner CONVICTED; it must not govern
            # what happens when the scanner itself is broken. A scan that never
            # ran is not a clean scan, so a caller that reaches here has to be
            # told the upload was refused rather than silently getting an
            # unscanned file stored. To accept unscanned uploads, turn the
            # scanner off explicitly with `enable_virus_scanning=false`.
            logger.error(f"Virus scan failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Virus scan failed - upload rejected for safety",
            )

    # Upload to storage service (scan already done)
    try:
        import io

        storage.upload_file(
            storage_key=storage_key,
            file_data=io.BytesIO(file_content),
            size=file_size,
            content_type=content_type,
        )
    except (httpx.HTTPError, OSError) as e:
        logger.error(f"Failed to upload file to storage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload file: {str(e)}",
        )

    # Create artifact record
    # Note: subject_id is left empty when caller didn't supply X-Subject-Id.
    # The before_insert listener on Artifact auto-fills subject_id := tenant_id
    # so mutation gating defers to tenant scope (matching pre-Plan-2 semantics).
    artifact = Artifact(
        id=artifact_id,
        tenant_id=tenant_id,  # TENANT ISOLATION
        subject_id=subject_id,
        visibility=visibility,
        project_id=project_id,
        card_id=card_id,
        step=step,
        container_name=container_name,
        version=version,
        filename=filename,
        content_type=content_type,
        kind=kind,
        sensitivity=sensitivity,
        size=file_size,
        sha256=sha256_hash,
        storage_key=storage_key,
        created_by=tenant_id,  # Use tenant_id as created_by
        # Asset-bindings provenance. These four columns have existed since
        # alembic 20260519_0002 and were written by NOTHING — every one of the
        # 58,573 production rows carries the server default. Declared on the
        # wire, persisted here.
        origin_kind=origin_kind,
        origin_project_id=origin_project_id,
        origin_workflow_run_id=origin_workflow_run_id,
        created_by_user_id=creator_user_id,
        # Always the CALLER's tenant (tenant_id above) — an upload can never
        # publish into another tenant, so no extra ownership check is needed.
        publish_status=publish_status.value,
        title=title,
        doc_type=doc_type,
        phase=phase,
        summary=summary,
        planka_card_id=planka_card_id,
    )

    db.add(artifact)

    # Add tags
    for tag in tag_list[:20]:  # Limit to 20 tags
        artifact_tag = ArtifactTag(artifact_id=artifact.id, tag=tag[:50])
        db.add(artifact_tag)

    await db.commit()
    await db.refresh(artifact)

    logger.info(f"Uploaded artifact {artifact.id} ({artifact.filename}) to project {project_id}")

    # Echo from the REFRESHED ROW, never from the request parameters. Echoing
    # the inputs back would confirm only that the caller can type; echoing the
    # row confirms the store accepted it.
    return UploadResponse(
        artifact_id=artifact.id,
        version=artifact.version,
        storage_key=artifact.storage_key,
        size=file_size,
        sha256=sha256_hash,
        card_id=artifact.card_id,
        origin_kind=artifact.origin_kind,
        origin_project_id=artifact.origin_project_id,
        origin_workflow_run_id=artifact.origin_workflow_run_id,
        created_by_user_id=artifact.created_by_user_id,
        publish_status=PublishStatus(artifact.publish_status),
        title=artifact.title,
        doc_type=artifact.doc_type,
        phase=artifact.phase,
        summary=artifact.summary,
        planka_card_id=artifact.planka_card_id,
    )


@router.api_route("/upload", methods=["GET", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def upload_method_not_allowed() -> None:
    """Return 405 for unsupported methods on /upload."""
    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail="Method not allowed",
        headers={"Allow": "POST"},
    )


@router.get(
    "",
    operation_id="list_artifacts",
    summary="List artifacts with filters",
    response_model=list[ArtifactOut],
    responses=AUTH_RESPONSES,
)
async def list_artifacts(
    request: Request,
    project_id: UUID,
    card_id: UUID | None = None,
    step: str | None = None,
    kind: ArtifactKind | None = None,
    sensitivity: ArtifactSensitivity | None = None,
    name_prefix: str | None = None,
    tags: Annotated[list[str] | None, Query()] = None,
    phase: str | None = Query(None, description="Only documents produced in this phase"),
    doc_type: str | None = Query(None, description="Only documents of this type"),
    planka_card_id: str | None = Query(None, description="Only artifacts of this Planka card"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> list[ArtifactOut]:
    """List artifacts for a project with optional filters."""
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id + visibility OR clause
    query = visibility_scope(
        select(Artifact).where(Artifact.project_id == project_id),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )

    # Apply filters
    if card_id:
        query = query.where(Artifact.card_id == card_id)
    if step:
        query = query.where(Artifact.step == step)
    if kind:
        query = query.where(Artifact.kind == kind)
    if sensitivity:
        query = query.where(Artifact.sensitivity == sensitivity)
    if name_prefix:
        query = query.where(Artifact.filename.startswith(name_prefix))
    if phase is not None:
        query = query.where(Artifact.phase == phase)
    if doc_type is not None:
        query = query.where(Artifact.doc_type == doc_type)
    if planka_card_id is not None:
        query = query.where(Artifact.planka_card_id == planka_card_id)

    # Filter by tags if provided
    if tags:
        query = query.join(ArtifactTag).where(ArtifactTag.tag.in_(tags))

    # Order by creation date (newest first)
    query = query.order_by(Artifact.created_at.desc())

    # Apply pagination
    query = query.limit(limit).offset(offset)

    # Load artifacts with tags
    query = query.options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifacts = result.scalars().all()

    # Convert to output models (no download URLs - use /download endpoint)
    artifact_outs = [_artifact_to_out(artifact, tenant_id=tenant_id) for artifact in artifacts]

    return artifact_outs


@router.get(
    "/{artifact_id}",
    operation_id="get_artifact",
    summary="Get artifact metadata",
    response_model=ArtifactOut,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def get_artifact(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> ArtifactOut:
    """Get a specific artifact by ID."""
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id + visibility OR clause
    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    ).options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    return _artifact_to_out(artifact, tenant_id=tenant_id)


@router.get(
    "/{artifact_id}/download",
    operation_id="download_artifact",
    summary="Download artifact file",
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def download_artifact(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage_service),
    subject_id: str = Depends(get_subject_id),
) -> StreamingResponse:
    """
    Download an artifact file.

    Streams the file content from storage_service. No presigned URLs.
    """
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id + visibility OR clause
    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )

    result = await db.execute(query)
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    # Download from storage before starting the response so errors
    # surface as proper HTTP 500 (headers haven't been sent yet).
    try:
        content = storage.download_file(str(artifact.storage_key))
    except (httpx.HTTPError, OSError) as e:
        logger.error(f"Failed to download file from storage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download file",
        )

    async def stream_content() -> AsyncGenerator[bytes]:
        """Generator that yields chunks from the already-fetched content."""
        chunk_size = 65536  # 64KB chunks
        for i in range(0, len(content), chunk_size):
            yield content[i : i + chunk_size]

    # Stream response with proper headers
    return StreamingResponse(
        stream_content(),
        media_type=str(artifact.content_type),
        headers={
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "Content-Length": str(artifact.size),
            "X-Artifact-Id": str(artifact.id),
            "X-Artifact-SHA256": str(artifact.sha256),
        },
    )


@router.delete(
    "/{artifact_id}",
    operation_id="delete_artifact",
    summary="Delete an artifact",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def delete_artifact(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage_service),
    subject_id: str = Depends(get_subject_id),
) -> None:
    """Delete an artifact."""
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id + visibility OR clause
    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
    )
    result = await db.execute(query)
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    # PER-USER MUTATION GATE: user-visible artifacts can only be deleted by their creator,
    # and nothing outside the active tenant (an inherited system artifact) is ever deletable.
    # The lookup above is own-tenant (include_system left False) — this is the second fence.
    # Return 404 (not 403) to avoid leaking existence.
    if not can_mutate(artifact, subject_id=subject_id, tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    # Delete from storage
    try:
        storage.delete_file(str(artifact.storage_key))
    except (httpx.HTTPError, OSError) as e:
        logger.error(f"Failed to delete artifact from storage: {e}")
        # Continue with database deletion even if storage deletion fails

    # Derived renders (DOC-1) for the row's CURRENT metadata. Renders made under
    # earlier metadata carry other fingerprints and are not reachable from here;
    # they are unreachable through the API too (the row is gone), but stay in
    # the bucket until a prefix sweep of derived/{artifact_id}/ removes them.
    for fmt in document_renderer.FORMATS:
        try:
            storage.delete_file(render_cache_key(artifact, fmt, _meta_for(artifact)))
        except (httpx.HTTPError, OSError) as e:
            logger.warning("Failed to delete derived render of %s: %s", artifact_id, e)

    # Delete from database - INCLUDE tenant_id in WHERE clause
    await db.execute(
        delete(Artifact).where(
            Artifact.tenant_id == tenant_id,
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        )
    )
    await db.commit()

    logger.info(f"Deleted artifact {artifact_id} from project {project_id} (tenant: {tenant_id})")


@router.patch(
    "/{artifact_id}/publish-status",
    operation_id="set_artifact_publish_status",
    summary="Set an artifact's publish status (draft | published)",
    response_model=ArtifactOut,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def set_artifact_publish_status(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    body: PublishStatusIn,
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> ArtifactOut:
    """Publish or unpublish an artifact.

    Only callers in the artifact's OWN tenant can change it. The lookup is
    own-tenant (``include_system`` left False), so an inherited system artifact
    is a 404 for every other tenant — the same answer as a nonexistent id, so
    existence is not leaked — and ``can_mutate`` re-checks the tenant as a
    second fence. Publishing a SYSTEM-tenant artifact is what makes it readable
    by every other tenant; unpublishing withdraws it on the next read.
    Publishing requires an explicitly resolved tenant (403 via the fallback).
    """
    tenant_id = await get_tenant_id(request)
    _refuse_publish_via_fallback(request, body.publish_status)

    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
    ).options(selectinload(Artifact.tags))
    artifact = (await db.execute(query)).scalar_one_or_none()

    if not artifact or not can_mutate(artifact, subject_id=subject_id, tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    artifact.publish_status = body.publish_status.value
    await db.commit()
    await db.refresh(artifact, attribute_names=["publish_status", "tags"])

    logger.info(
        "Set publish_status=%s on artifact %s (tenant: %s)",
        body.publish_status.value,
        artifact_id,
        tenant_id,
    )
    return _artifact_to_out(artifact, tenant_id=tenant_id)


@router.patch(
    "/{artifact_id}/metadata",
    operation_id="update_artifact_metadata",
    summary="Set an artifact's document metadata (title, doc_type, phase, summary, card_id)",
    response_model=ArtifactOut,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def update_artifact_metadata(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    body: ArtifactMetadataIn,
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> ArtifactOut:
    """PARTIAL update of the document metadata on an existing artifact.

    Only fields present in the JSON body are written; an explicit ``null``
    clears a field; unknown fields are a 422. Same write fences as
    ``/publish-status``: own-tenant lookup (an inherited system artifact is a
    404, as is a nonexistent id) plus ``can_mutate``.
    """
    tenant_id = await get_tenant_id(request)

    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
    ).options(selectinload(Artifact.tags))
    artifact = (await db.execute(query)).scalar_one_or_none()

    if not artifact or not can_mutate(artifact, subject_id=subject_id, tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    changed = sorted(body.model_fields_set)
    for name in changed:
        setattr(artifact, name, getattr(body, name))
    await db.commit()
    await db.refresh(artifact)
    await db.refresh(artifact, attribute_names=["tags"])

    logger.info("Updated metadata %s on artifact %s (tenant: %s)", changed, artifact_id, tenant_id)
    return _artifact_to_out(artifact, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Document render (DOC-1)
# ---------------------------------------------------------------------------

RenderFormat = Literal["html", "pdf"]

_RENDER_MEDIA_TYPES: dict[str, str] = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}

# Render responses carry their own, stricter policy than the API default
# (SecurityHeadersMiddleware only fills headers a response has not set). The page
# is sanitised markup with ONE inline <style> and no script, image, font or
# remote resource, so inline styles are all it needs; img-src data: is the only
# image source allowed. frame-ancestors 'self' (+ the matching legacy
# X-Frame-Options) lets a same-origin reader embed it; nothing else may.
_RENDER_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
}

# At most ``render_max_concurrency`` renders run at once per process; one more
# is answered 503 + Retry-After immediately instead of queueing (a render can
# take seconds of CPU, and a queue would just move the overload into latency).
# A threading semaphore, taken INSIDE the worker thread: a request cancelled
# before its thread starts never takes a slot, and one cancelled mid-render
# keeps its slot until the CPU work really ends.
_RENDER_SLOTS = threading.BoundedSemaphore(settings.render_max_concurrency)
RENDER_RETRY_AFTER_SECONDS = 5


class RenderBusyError(Exception):
    """Every render slot is taken."""


def render_cache_key(artifact: Artifact, fmt: str, meta: document_renderer.DocumentMeta) -> str:
    """Derived-object key for one (artifact id, version, format) render.

    The trailing fingerprint covers everything else that reaches the bytes —
    the source sha256, the header metadata (title/doc_type/phase/summary can be
    PATCHed) and the renderer version — so a stale render can never be served
    for changed inputs. A change simply misses and renders afresh.
    """
    parts = [
        document_renderer.RENDER_VERSION,
        str(artifact.sha256),
        *meta.fingerprint_parts(),
    ]
    fp = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:24]
    return f"derived/{artifact.id}/v{artifact.version}/render-{fmt}-{fp}.{fmt}"


def _meta_for(artifact: Artifact) -> document_renderer.DocumentMeta:
    return document_renderer.DocumentMeta(
        title=artifact.title,
        doc_type=artifact.doc_type,
        phase=artifact.phase,
        summary=artifact.summary,
        version=artifact.version,
        filename=str(artifact.filename),
    )


def _render_bytes(content: bytes, *, content_type: str, meta: Any, fmt: str) -> bytes:
    """CPU-bound: runs in a worker thread, holding one render slot."""
    if not _RENDER_SLOTS.acquire(blocking=False):
        raise RenderBusyError
    try:
        page = document_renderer.render_html(content, content_type=content_type, meta=meta)
        if fmt == "pdf":
            return document_renderer.html_to_pdf(page)
        return page.encode("utf-8")
    finally:
        _RENDER_SLOTS.release()


async def _cached_render(artifact: Artifact, fmt: str, storage: StorageService) -> Response:
    try:
        document_renderer.classify(str(artifact.content_type), str(artifact.filename))
    except document_renderer.NotRenderableError as e:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(e))
    if int(artifact.size or 0) > settings.render_max_source_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Document exceeds the render limit of {settings.render_max_source_bytes} bytes",
        )

    meta = _meta_for(artifact)
    key = render_cache_key(artifact, fmt, meta)
    media_type = _RENDER_MEDIA_TYPES[fmt]

    cached: bytes | None = None
    try:
        cached = await asyncio.to_thread(storage.download_file, key)
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            logger.warning("render cache read failed for %s: %s", key, e)
    except (httpx.HTTPError, OSError) as e:
        # A broken cache must never break the read: render instead.
        logger.warning("render cache read failed for %s: %s", key, e)

    if cached:
        body, cache_state = cached, "hit"
    else:
        try:
            source = await asyncio.to_thread(storage.download_file, str(artifact.storage_key))
        except (httpx.HTTPError, OSError) as e:
            logger.error(f"Failed to download file from storage for render: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to download file",
            )
        try:
            body = await asyncio.to_thread(
                _render_bytes,
                source,
                content_type=str(artifact.content_type),
                meta=meta,
                fmt=fmt,
            )
        except RenderBusyError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="All document renderers are busy; retry shortly",
                headers={"Retry-After": str(RENDER_RETRY_AFTER_SECONDS)},
            )
        except Exception:  # noqa: BLE001 - surfaced as a 500 with the cause logged
            logger.exception("render of artifact %s as %s failed", artifact.id, fmt)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to render document as {fmt}",
            )
        cache_state = "miss"
        try:
            await asyncio.to_thread(
                storage.upload_file,
                storage_key=key,
                file_data=io.BytesIO(body),
                size=len(body),
                content_type=media_type.split(";")[0],
            )
        except (httpx.HTTPError, OSError) as e:
            logger.warning("render cache write failed for %s: %s", key, e)

    # Header-safe: the stored filename is free text apart from path characters.
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", str(artifact.filename).rsplit(".", 1)[0]) or "document"
    disposition = "inline" if fmt == "html" else "attachment"
    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{stem}.{fmt}"',
            "X-Artifact-Id": str(artifact.id),
            "X-Render-Cache": cache_state,
            **_RENDER_SECURITY_HEADERS,
        },
    )


_RENDER_DOC = """Render the artifact as a readable document: ``format=html`` (default) or
``format=pdf``.

Sources: ``document.json`` (``{title, sections:[{heading, body_md, sources}]}``),
markdown / plain text, or any other JSON report (rendered as a definition list /
table of its top-level keys). HTML is sanitised (no raw HTML, no script, no
remote resources) with a table of contents from the headings and section sources
as footnotes; PDF is WeasyPrint over that HTML. Other content types are 415.

Rendered output is cached as a derived object per (artifact id, version, format);
``X-Render-Cache: hit|miss`` says which. Same tenant + visibility scoping as the
get-artifact route: a missing or invisible id is 404."""


@router.get(
    "/{artifact_id}/render",
    operation_id="render_artifact",
    summary="Render an artifact as an HTML or PDF document",
    description=_RENDER_DOC,
    responses={
        **AUTH_RESPONSES,
        **NOT_FOUND_RESPONSES,
        200: {"content": {"text/html": {}, "application/pdf": {}}},
        415: {"description": "Content type cannot be rendered as a document"},
    },
)
async def render_artifact(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    format: RenderFormat = Query("html", description="html | pdf"),  # noqa: A002
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage_service),
    subject_id: str = Depends(get_subject_id),
) -> Response:
    tenant_id = await get_tenant_id(request)
    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )
    artifact = (await db.execute(query)).scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return await _cached_render(artifact, format, storage)


@router.get(
    "/manifests/{scope}",
    operation_id="get_manifest",
    summary="Get artifact manifest by scope",
    response_model=Manifest,
    responses=AUTH_RESPONSES,
)
async def get_manifest(
    request: Request,
    project_id: UUID,
    scope: ManifestScope,
    scope_ref: str | None = Query(None),
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> Manifest:
    """Get a manifest of artifacts for a specific scope.

    ⛔ BEHAVIOUR CHANGE: `artifacts` used to hold EVERY row in the scope, so a
    project-scope manifest over a large project scanned and serialised the lot.
    It is now one page, and a caller that reads `artifacts` without reading
    `truncated` will silently see less than it used to.

    ⚠️ The default `limit` is the CAP (1000), NOT the 100 the list endpoints
    use, and that asymmetry is deliberate. MEASURED 2026-09-08 against the
    production database: one project holds 55,036 artifacts, and the live
    `n8n-nodes-artifacts` `getManifest` sends neither `limit` nor `offset` and
    discards response headers. A default of 100 would silently 550x-truncate a
    live consumer; 1000 makes that 55x while the client is fixed to page. The
    by-card route keeps the 100 default because it matches nothing today
    (`card_id` is NULL on all 55,057 production rows).

    A partial manifest is only safe because truncation is VISIBLE in the body:
    `total_count` and `total_size` are computed by the DATABASE over the whole
    scope (which is what their descriptions have always claimed), and
    `truncated` states the comparison outright — `offset + len(artifacts) <
    total_count` — so a client cannot miss it by failing to ask. Page by
    raising `offset` until `truncated` is false.
    """
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id + visibility OR clause
    # Note: `scope` is the ManifestScope path parameter; visibility_scope is the helper.
    query = visibility_scope(
        select(Artifact).where(Artifact.project_id == project_id),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )

    # Apply scope filter
    if scope == ManifestScope.CARD and scope_ref:
        try:
            card_id = UUID(scope_ref)
            query = query.where(Artifact.card_id == card_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid card_id format",
            )
    elif scope == ManifestScope.STEP and scope_ref:
        query = query.where(Artifact.step == scope_ref)

    # Aggregates over the WHOLE scope, computed in the database and BEFORE
    # pagination — derived from `query` itself so they can never drift from
    # the filters that produced the page.
    total_count, total_size = await _count_and_size(db, query)

    # Load artifacts with tags. Bound the read IN THE DATABASE; slicing the
    # rows in Python afterwards would still have hydrated every one of them.
    query = (
        query.options(selectinload(Artifact.tags))
        .order_by(Artifact.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    result = await db.execute(query)
    artifacts = result.scalars().all()

    # Convert to output models (no download URLs)
    artifact_outs = [_artifact_to_out(artifact, tenant_id=tenant_id) for artifact in artifacts]

    return Manifest(
        project_id=project_id,
        scope=scope,
        scope_ref=scope_ref,
        artifacts=artifact_outs,
        total_count=total_count,
        total_size=total_size,
        truncated=(offset + len(artifact_outs)) < total_count,
    )


def _unpaged(query: Select) -> Any:
    """`query` stripped of ordering and pagination, as a subquery.

    Wrapping the *already filtered* SELECT rather than re-stating its WHERE
    clauses is the point: a filter added to the page query can never be
    forgotten in the total, because both readings are the same predicate by
    construction.
    """
    return query.order_by(None).limit(None).offset(None).subquery()


async def _count_and_size(db: AsyncSession, query: Select) -> tuple[int, int]:
    """(row count, summed `size`) for `query`, ignoring ordering and pagination."""
    sub = _unpaged(query)
    row = (
        await db.execute(
            select(func.count(), func.coalesce(func.sum(sub.c.size), 0)).select_from(sub)
        )
    ).first()
    if row is None:  # pragma: no cover - aggregate always yields exactly one row
        return 0, 0
    return int(row[0] or 0), int(row[1] or 0)


async def _count_matching(db: AsyncSession, query: Select) -> int:
    """Number of rows `query` matches, ignoring ordering and pagination.

    Deliberately does NOT go through `_count_and_size`: that one sums a `size`
    column, which only the artifact tables have.
    """
    result = await db.execute(select(func.count()).select_from(_unpaged(query)))
    return int(result.scalar_one() or 0)


def _artifact_to_out(artifact: Artifact, *, tenant_id: str) -> ArtifactOut:
    """Build ArtifactOut from an Artifact ORM row (tags relationship preloaded).

    ⚠️ THE ONLY place an ArtifactOut is built, and that is the point. There used
    to be six copies of this constructor, each naming every field by hand. A
    column added to the model and to ArtifactOut therefore reached the wire only
    if all six copies were edited — and the four provenance columns
    (20260519_0002) were edited into NONE of them, so every read returned the
    Pydantic defaults ('tenant', null, null, '') no matter what the row held.
    That failure is silent and it LIES: it reports a plausible value rather than
    an absent one. One constructor makes "forgot a field" impossible.

    `tenant_id` is the ACTIVE tenant; it is required because `is_system` is a
    property of (row, reader), not of the row alone.
    """
    return ArtifactOut(
        id=artifact.id,
        version=artifact.version,
        filename=artifact.filename,
        content_type=artifact.content_type,
        kind=artifact.kind,
        project_id=artifact.project_id,
        card_id=artifact.card_id,
        step=artifact.step,
        container_name=artifact.container_name,
        sensitivity=artifact.sensitivity,
        size=artifact.size,
        sha256=artifact.sha256,
        storage_key=artifact.storage_key,
        created_at=artifact.created_at,
        created_by=artifact.created_by,
        tags=[tag.tag for tag in artifact.tags],
        status=ArtifactStatus(artifact.status),
        review_callback_url=artifact.review_callback_url,
        origin_kind=artifact.origin_kind,
        origin_project_id=artifact.origin_project_id,
        origin_workflow_run_id=artifact.origin_workflow_run_id,
        created_by_user_id=artifact.created_by_user_id,
        publish_status=PublishStatus(artifact.publish_status),
        is_system=is_inherited(artifact, tenant_id=tenant_id, system_tenant_id=_system_tenant_id()),
        title=artifact.title,
        doc_type=artifact.doc_type,
        phase=artifact.phase,
        summary=artifact.summary,
        planka_card_id=artifact.planka_card_id,
    )


@router.post(
    "/{artifact_id}/review",
    operation_id="submit_artifact_review",
    summary="Submit a review decision for an artifact",
    response_model=ReviewResponse,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def submit_artifact_review(
    request: Request,
    project_id: UUID,
    artifact_id: UUID,
    body: ReviewIn,
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> ReviewResponse:
    """Record a human review decision against an artifact.

    Inserts a row in `artifact_reviews` capturing decision + comment +
    reviewer + timestamp, then updates the artifact's `status` to the
    resulting state (approve→approved, reject→rejected, revise→needs_revision).

    Tenant + visibility scoping mirrors the delete/get endpoints. The
    artifact must be in the caller's tenant (or visible per X-Visibility=user
    rules). Reviews are persisted under the reviewer's home tenant — recorded
    on the review row — so cross-tenant reviews (super-admin) preserve audit
    integrity.

    The N8N webhook callback (when `artifacts.review_callback_url` is set on
    the row) is fired by the BFF (fr-backend), not here — this endpoint stays
    pure DB. Keeping the callback at the BFF avoids artifact_service
    egressing to arbitrary URLs.
    """
    tenant_id = await get_tenant_id(request)

    query = visibility_scope(
        select(Artifact).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
    ).options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    # WRITE path: the lookup above is own-tenant (include_system left False);
    # this is the second fence, so an inherited system artifact can never be
    # reviewed from another tenant even if the lookup is ever widened.
    if not can_mutate(artifact, subject_id=subject_id, tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    new_status = DECISION_TO_STATUS[body.decision]
    review = ArtifactReview(
        artifact_id=artifact.id,
        decision=body.decision.value,
        comment=body.comment,
        reviewer_id=subject_id or tenant_id,
        reviewer_tenant_id=tenant_id,
    )
    db.add(review)
    artifact.status = new_status.value
    await db.commit()
    await db.refresh(review)
    await db.refresh(artifact, attribute_names=["tags"])

    logger.info(
        "Recorded review on artifact %s: decision=%s status=%s reviewer=%s",
        artifact_id,
        body.decision.value,
        new_status.value,
        review.reviewer_id,
    )

    return ReviewResponse(
        artifact=_artifact_to_out(artifact, tenant_id=tenant_id),
        review=ReviewOut.model_validate(review),
    )


@router.get(
    "/{artifact_id}/reviews",
    operation_id="list_artifact_reviews",
    summary="List review history for an artifact",
    response_model=list[ReviewOut],
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES, **TOTAL_COUNT_HEADER},
)
async def list_artifact_reviews(
    request: Request,
    response: Response,
    project_id: UUID,
    artifact_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> list[ReviewOut]:
    """Return one PAGE of an artifact's reviews, oldest-first.

    ⛔ BEHAVIOUR CHANGE: this returned EVERY review row for the artifact with
    no limit — the same unbounded-read defect as the by-card and manifest
    routes, on a table that grows once per review submission and is never
    pruned. `limit`/`offset` match the list endpoints (default 100, max 1000)
    and the bound is applied in SQL.

    Truncation is reported in `X-Total-Count` (the full match count before
    limit/offset), since the body is a bare array with nowhere to carry it:
    truncated exactly when `offset + len(body) < X-Total-Count`.

    The 100 default is safe here where the manifest's is not: MEASURED
    2026-09-08 against the production database, `artifact_reviews` holds
    ZERO rows, so no live caller can be truncated by it today.
    """
    tenant_id = await get_tenant_id(request)

    # Ensure the caller can see the artifact before we expose its review log.
    gate = visibility_scope(
        select(Artifact.id).where(
            Artifact.id == artifact_id,
            Artifact.project_id == project_id,
        ),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
    )
    gate_res = await db.execute(gate)
    if gate_res.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    review_query = select(ArtifactReview).where(ArtifactReview.artifact_id == artifact_id)

    # Total BEFORE pagination, derived from the page query itself.
    response.headers["X-Total-Count"] = str(await _count_matching(db, review_query))

    # Bound the read IN THE DATABASE, not with a Python slice.
    rows = await db.execute(
        review_query.order_by(ArtifactReview.reviewed_at).limit(limit).offset(offset)
    )
    return [ReviewOut.model_validate(r) for r in rows.scalars().all()]


@cross_project_router.get(
    "",
    operation_id="artifacts_list_cross_project",
    summary="List artifacts across all projects in tenant",
    response_model=list[ArtifactOut],
    responses=AUTH_RESPONSES,
)
async def list_artifacts_cross_project(
    request: Request,
    card_id: UUID | None = None,
    step: str | None = None,
    kind: ArtifactKind | None = None,
    sensitivity: ArtifactSensitivity | None = None,
    name_prefix: str | None = None,
    tags: Annotated[list[str] | None, Query()] = None,
    phase: str | None = Query(None, description="Only documents produced in this phase"),
    doc_type: str | None = Query(None, description="Only documents of this type"),
    planka_card_id: str | None = Query(None, description="Only artifacts of this Planka card"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> list[ArtifactOut]:
    """List artifacts across ALL projects in the caller's tenant.

    Tenant + visibility scoped via `visibility_scope()`; otherwise mirrors the
    per-project `list_artifacts` filter surface. Used by the fr-backend Library
    workspace tab and other callers that hold tenant context but no project_id.
    """
    tenant_id = await get_tenant_id(request)

    query = visibility_scope(
        select(Artifact),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )

    if card_id:
        query = query.where(Artifact.card_id == card_id)
    if step:
        query = query.where(Artifact.step == step)
    if kind:
        query = query.where(Artifact.kind == kind)
    if sensitivity:
        query = query.where(Artifact.sensitivity == sensitivity)
    if name_prefix:
        query = query.where(Artifact.filename.startswith(name_prefix))
    if phase is not None:
        query = query.where(Artifact.phase == phase)
    if doc_type is not None:
        query = query.where(Artifact.doc_type == doc_type)
    if planka_card_id is not None:
        query = query.where(Artifact.planka_card_id == planka_card_id)
    if tags:
        query = query.join(ArtifactTag).where(ArtifactTag.tag.in_(tags))

    query = query.order_by(Artifact.created_at.desc()).limit(limit).offset(offset)
    query = query.options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifacts = result.scalars().all()

    return [_artifact_to_out(a, tenant_id=tenant_id) for a in artifacts]


@cross_project_router.get(
    "/by-card/{card_id}",
    operation_id="artifacts_list_by_card_cross_project",
    summary="List artifacts by card across all projects",
    response_model=list[ArtifactOut],
    responses={**AUTH_RESPONSES, **TOTAL_COUNT_HEADER},
)
async def list_artifacts_by_card_cross_project(
    request: Request,
    response: Response,
    card_id: UUID,
    name_prefix: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> list[ArtifactOut]:
    """List artifacts matching a card_id across ALL projects.

    Returns one PAGE of the artifacts the caller can see (tenant + visibility
    scoped) that have the given `card_id`, regardless of which project the
    artifact belongs to. Required by n8n improvement-loop workflows that hold
    tenant_id + card_id but not project_id.

    Optional `name_prefix` filters by `Artifact.filename.startswith(name_prefix)`,
    matching the per-project list endpoint's semantics.

    `limit`/`offset` mirror `list_artifacts` and `list_artifacts_cross_project`
    exactly (default 100, max 1000). ⛔ BEHAVIOUR CHANGE: this route used to
    return EVERY matching row, so a long-lived card could make it scan and
    serialise tens of thousands of artifacts. It now returns at most `limit`.
    So that the truncation is never silent, the full match count for the query
    (ignoring limit/offset) is returned in the `X-Total-Count` header: a caller
    is truncated exactly when `offset + len(body) < X-Total-Count`, and pages
    by raising `offset` until that is false.
    """
    # Get tenant ID from trusted header or JWT
    tenant_id = await get_tenant_id(request)

    # TENANT + VISIBILITY ISOLATION: visibility_scope() applies tenant_id +
    # visibility OR clause. NO project_id filter — that's the whole point of
    # this route.
    query = visibility_scope(
        select(Artifact).where(Artifact.card_id == card_id),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )

    if name_prefix:
        query = query.where(Artifact.filename.startswith(name_prefix))

    # Total BEFORE pagination, derived from `query` itself so the count can
    # never drift from the filters that produced the page.
    total = await _count_matching(db, query)
    response.headers["X-Total-Count"] = str(total)

    # Order by creation date (newest first) — match list_artifacts ordering
    query = query.order_by(Artifact.created_at.desc())

    # Bound the read IN THE DATABASE. Slicing in Python afterwards would still
    # have fetched and hydrated every row, which is the defect.
    query = query.limit(limit).offset(offset)

    # Load artifacts with tags
    query = query.options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifacts = result.scalars().all()

    artifact_outs = [_artifact_to_out(artifact, tenant_id=tenant_id) for artifact in artifacts]

    return artifact_outs


# Registered AFTER `/by-card/{card_id}` on purpose so a literal-prefix route is
# never shadowed by this single-segment catch-all.
@cross_project_router.get(
    "/{artifact_id}",
    operation_id="artifacts_get_cross_project",
    summary="Get artifact metadata by id across all projects in tenant",
    response_model=ArtifactOut,
    responses={**AUTH_RESPONSES, **NOT_FOUND_RESPONSES},
)
async def get_artifact_cross_project(
    request: Request,
    artifact_id: UUID,
    db: AsyncSession = Depends(get_db),
    subject_id: str = Depends(get_subject_id),
) -> ArtifactOut:
    """Get one artifact by id without knowing its owning project.

    Tenant + visibility scoped exactly like `list_artifacts_cross_project`
    (published system-tenant rows are inherited read-only). A missing artifact
    and one the caller cannot see are indistinguishable: both are 404, never
    403. Used by fr, whose asset bindings store only the artifact id.
    """
    tenant_id = await get_tenant_id(request)

    query = visibility_scope(
        select(Artifact).where(Artifact.id == artifact_id),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    ).options(selectinload(Artifact.tags))

    result = await db.execute(query)
    artifact = result.scalar_one_or_none()

    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )

    return _artifact_to_out(artifact, tenant_id=tenant_id)


@cross_project_router.get(
    "/{artifact_id}/render",
    operation_id="artifacts_render_cross_project",
    summary="Render an artifact as an HTML or PDF document, by id across all projects",
    description=_RENDER_DOC,
    responses={
        **AUTH_RESPONSES,
        **NOT_FOUND_RESPONSES,
        200: {"content": {"text/html": {}, "application/pdf": {}}},
        415: {"description": "Content type cannot be rendered as a document"},
    },
)
async def render_artifact_cross_project(
    request: Request,
    artifact_id: UUID,
    format: RenderFormat = Query("html", description="html | pdf"),  # noqa: A002
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage_service),
    subject_id: str = Depends(get_subject_id),
) -> Response:
    tenant_id = await get_tenant_id(request)
    query = visibility_scope(
        select(Artifact).where(Artifact.id == artifact_id),
        Artifact,
        tenant_id=tenant_id,
        subject_id=subject_id,
        include_system=True,  # READ path: inherit published system artifacts
        system_tenant_id=_system_tenant_id(),
    )
    artifact = (await db.execute(query)).scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return await _cached_render(artifact, format, storage)
