"""Pydantic schemas for API request/response models."""

# NOTE (UP042): the enums below deliberately stay `(str, Enum)` rather than
# `enum.StrEnum`. They are API-surface enums that are written straight into the
# ORM (routes/artifacts.py:230-231) and rendered into storage keys
# (services/storage_service.py:83). `StrEnum` changes what `str()`/f-string
# interpolation yields ("doc" instead of "ArtifactKind.DOC"), so the migration
# is a behaviour change on a persisted-data path, not a lint cleanup. Reading
# the code says it is inert here; that has NOT been exercised end-to-end.
# Convert in its own PR with an upload->read round-trip as the gate.

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ArtifactKind(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """Types of artifacts that can be stored."""

    DOC = "doc"
    PRESENTATION = "presentation"
    IMAGE = "image"
    DATASET = "dataset"
    JSON = "json"
    GRAPH = "graph"
    OTHER = "other"


class ArtifactSensitivity(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """Sensitivity levels for artifacts."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SECRET = "secret"


class ArtifactStatus(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """Review status of an artifact. Reflects the latest review decision."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"


class PublishStatus(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """Publication state. A PUBLISHED system-tenant artifact is inherited read-only
    by every other tenant; a DRAFT one never leaves the system tenant. Separate
    axis from ArtifactStatus (the review decision)."""

    DRAFT = "draft"
    PUBLISHED = "published"


class ReviewDecision(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """The verb a reviewer submits. Maps to ArtifactStatus via DECISION_TO_STATUS."""

    APPROVE = "approve"
    REJECT = "reject"
    REVISE = "revise"


# Map review verb → resulting artifact status. Source of truth lives here so
# routes + tests stay in sync.
DECISION_TO_STATUS: dict[ReviewDecision, ArtifactStatus] = {
    ReviewDecision.APPROVE: ArtifactStatus.APPROVED,
    ReviewDecision.REJECT: ArtifactStatus.REJECTED,
    ReviewDecision.REVISE: ArtifactStatus.NEEDS_REVISION,
}


class ManifestScope(str, Enum):  # noqa: UP042 - see NOTE at top; StrEnum changes str()/f-string output
    """Scope levels for artifact manifests."""

    PROJECT = "project"
    CARD = "card"
    STEP = "step"


#: The three provenance origins. Kept as a module constant so the JSON body
#: model, the multipart upload route and the tests all read the SAME list; the
#: DB-side authority is the CHECK constraint `ck_artifacts_origin_kind`
#: (alembic 20260519_0002).
ORIGIN_KINDS = ("tenant", "project", "workflow")


def validate_origin_consistency(
    origin_kind: str,
    origin_project_id: UUID | None,
    origin_workflow_run_id: str | None,
) -> None:
    """Raise ValueError unless the origin triple is internally consistent.

    ⚠️ ONE authority, deliberately. This mirrors the database CHECK constraint
    `ck_artifacts_origin_consistency` (alembic 20260519_0002) clause for clause.
    A second, hand-copied version in the route would be free to drift, and the
    way it would announce the drift is a 500 from psycopg's CheckViolation
    instead of a 400 — i.e. the caller would be told the server is broken when
    in fact the request was.
    """
    if origin_kind not in ORIGIN_KINDS:
        raise ValueError(f"origin_kind must be one of {', '.join(ORIGIN_KINDS)}")
    if origin_kind == "tenant":
        if origin_project_id is not None or origin_workflow_run_id is not None:
            raise ValueError(
                "origin_kind='tenant' requires origin_project_id and origin_workflow_run_id to be null"
            )
    elif origin_kind == "project":
        if origin_project_id is None:
            raise ValueError("origin_kind='project' requires origin_project_id")
        if origin_workflow_run_id is not None:
            raise ValueError("origin_kind='project' must not carry origin_workflow_run_id")
    elif origin_kind == "workflow":
        if origin_workflow_run_id is None:
            raise ValueError("origin_kind='workflow' requires origin_workflow_run_id")


# ---------------------------------------------------------------------------
# Document metadata (DOC-1). Length caps are enforced HERE (and on the upload
# form) rather than only by the column types: doc_type/phase are VARCHAR(100),
# so an over-long value would otherwise surface as a 500 from the database
# instead of a 400/422 that names the field.
# ---------------------------------------------------------------------------
TITLE_MAX = 500
DOC_TYPE_MAX = 100
PHASE_MAX = 100
SUMMARY_MAX = 4000
PLANKA_CARD_ID_MAX = 64


class ArtifactMetadataIn(BaseModel):
    """PATCH body for an artifact's document metadata.

    PARTIAL update: only the fields PRESENT in the body are written. A field sent
    as ``null`` clears it; a field left out is unchanged. ``card_id`` follows the
    same rule.
    """

    title: str | None = Field(None, max_length=TITLE_MAX, description="Human title")
    doc_type: str | None = Field(
        None, max_length=DOC_TYPE_MAX, description="Document type, e.g. 'analysis_report'"
    )
    phase: str | None = Field(
        None, max_length=PHASE_MAX, description="Project phase that produced it"
    )
    summary: str | None = Field(None, max_length=SUMMARY_MAX, description="One-line summary")
    card_id: UUID | None = Field(None, description="Card this artifact is the output of")
    planka_card_id: str | None = Field(
        None, max_length=PLANKA_CARD_ID_MAX, description="Planka card id (any format)"
    )

    model_config = ConfigDict(extra="forbid")


class ArtifactIn(BaseModel):
    """Input model for artifact creation."""

    filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Name of the file (REQUIRED). Cannot contain path traversal characters (/, \\, ..)",
    )
    content_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="MIME type of the file (REQUIRED). Example: 'application/pdf'",
    )
    kind: ArtifactKind = Field(
        ...,
        description="Type of artifact (REQUIRED). One of: doc, presentation, image, dataset, json, graph, other",
    )
    project_id: UUID = Field(..., description="Project UUID (REQUIRED)")
    card_id: UUID | None = Field(
        None, description="Optional: Card UUID to associate artifact with a specific card"
    )
    step: str | None = Field(
        None, max_length=100, description="Optional: Step identifier (e.g., 'QA:validation')"
    )
    container_name: str | None = Field(
        None, max_length=255, description="Optional: Container identifier"
    )
    sensitivity: ArtifactSensitivity = Field(
        ArtifactSensitivity.INTERNAL,
        description="Sensitivity level (defaults to 'internal'). One of: public, internal, secret",
    )
    tags: list[str] = Field(
        default_factory=list, description="Optional: List of tags (max 20 tags, each max 50 chars)"
    )
    # Asset-bindings provenance (~/.claude/plans/fr-asset-bindings-and-reuse.md Phase G).
    origin_kind: str = Field(
        default="tenant",
        pattern="^(tenant|project|workflow)$",
        description="Provenance: tenant | project | workflow",
    )
    origin_project_id: UUID | None = Field(
        default=None, description="Required when origin_kind='project'"
    )
    origin_workflow_run_id: str | None = Field(
        default=None,
        max_length=200,
        description="Required when origin_kind='workflow' (n8n run id)",
    )
    created_by_user_id: str = Field(
        default="",
        max_length=255,
        description="Subject id of the creator (empty for legacy rows)",
    )

    @model_validator(mode="after")
    def check_origin_consistency(self) -> ArtifactIn:
        validate_origin_consistency(
            self.origin_kind, self.origin_project_id, self.origin_workflow_run_id
        )
        return self

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        """Validate and sanitize tags."""
        if len(v) > 20:
            raise ValueError("Maximum 20 tags allowed")
        return [tag.strip()[:50] for tag in v if tag.strip()]

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        """Validate filename doesn't contain path traversal."""
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Filename cannot contain path traversal characters")
        return v


class ArtifactOut(BaseModel):
    """Output model for artifact representation."""

    id: UUID = Field(..., description="Unique artifact identifier")
    version: int = Field(..., description="Artifact version number")
    filename: str = Field(..., description="Original filename")
    content_type: str = Field(..., description="MIME type")
    kind: ArtifactKind = Field(..., description="Artifact type")
    project_id: UUID = Field(..., description="Project UUID")
    card_id: UUID | None = Field(None, description="Associated card UUID (if any)")
    step: str | None = Field(None, description="Associated step identifier (if any)")
    container_name: str | None = Field(None, description="Container identifier (if any)")
    sensitivity: ArtifactSensitivity = Field(..., description="Sensitivity level")
    size: int = Field(..., description="File size in bytes")
    sha256: str = Field(..., description="SHA256 checksum of the file")
    storage_key: str = Field(..., description="Storage object key")
    created_at: datetime = Field(..., description="Creation timestamp (UTC)")
    created_by: str = Field(..., description="Username who created the artifact")
    tags: list[str] = Field(default_factory=list, description="Associated tags")
    status: ArtifactStatus = Field(
        ArtifactStatus.PENDING,
        description="Review status reflecting the latest review decision",
    )
    publish_status: PublishStatus = Field(
        PublishStatus.DRAFT,
        description=(
            "draft | published. A published SYSTEM-tenant artifact is readable by "
            "every tenant (is_system=true); drafts stay in the owning tenant."
        ),
    )
    is_system: bool = Field(
        False,
        description=(
            "True when this artifact is inherited from the system tenant (read-only "
            "for the caller). False for the caller's own artifacts, including the "
            "system tenant reading its own."
        ),
    )
    review_callback_url: str | None = Field(
        None,
        description=(
            "Optional webhook URL set by the producer (typically an n8n custom "
            "node). The fr BFF POSTs the review decision here when a human "
            "reviews the artifact. Never set by humans; ignored on user-facing "
            "uploads."
        ),
    )
    # Asset-bindings provenance (~/.claude/plans/fr-asset-bindings-and-reuse.md Phase G).
    origin_kind: str = Field(
        default="tenant", description="Provenance: tenant | project | workflow"
    )
    origin_project_id: UUID | None = Field(default=None)
    origin_workflow_run_id: str | None = Field(default=None, max_length=200)
    created_by_user_id: str = Field(default="", max_length=255)
    # Document metadata (DOC-1). null = not set by the producer.
    title: str | None = Field(default=None, description="Human title (null = not set)")
    doc_type: str | None = Field(default=None, description="Document type (null = not set)")
    phase: str | None = Field(default=None, description="Producing phase (null = not set)")
    summary: str | None = Field(default=None, description="One-line summary (null = not set)")
    planka_card_id: str | None = Field(default=None, description="Planka card id (null = not set)")

    model_config = ConfigDict(from_attributes=True)


class ReviewIn(BaseModel):
    """Input model for submitting a review decision against an artifact."""

    decision: ReviewDecision = Field(..., description="Review verb: approve, reject, or revise")
    comment: str | None = Field(
        None,
        max_length=4000,
        description="Optional reviewer comment (max 4000 chars)",
    )


class PublishStatusIn(BaseModel):
    """Body for PATCH /projects/{p}/artifacts/{id}/publish-status."""

    publish_status: PublishStatus = Field(..., description="draft | published")


class ReviewOut(BaseModel):
    """Output model for a single review record."""

    id: UUID = Field(..., description="Review record identifier")
    artifact_id: UUID = Field(..., description="Artifact being reviewed")
    decision: ReviewDecision = Field(..., description="Decision verb")
    comment: str | None = Field(None, description="Reviewer comment, if any")
    reviewer_id: str = Field(..., description="Subject UUID of the reviewer")
    reviewer_tenant_id: str = Field(..., description="Tenant the reviewer belongs to")
    reviewed_at: datetime = Field(..., description="When the decision was recorded (UTC)")

    model_config = ConfigDict(from_attributes=True)


class ReviewResponse(BaseModel):
    """Response after a review is submitted: updated artifact + the new review row."""

    artifact: ArtifactOut = Field(..., description="Artifact with refreshed status")
    review: ReviewOut = Field(..., description="The newly recorded review row")


class Manifest(BaseModel):
    """
    Manifest of artifacts for a specific scope.

    Groups all artifacts within a project, card, or step scope
    with aggregate statistics.
    """

    project_id: UUID = Field(..., description="Project UUID")
    scope: ManifestScope = Field(..., description="Scope type: project, card, or step")
    scope_ref: str | None = Field(
        None,
        description="Scope reference: card UUID for 'card' scope, step identifier for 'step' scope, null for 'project' scope",
        examples=["123e4567-e89b-12d3-a456-426614174000", "QA:validation"],
    )
    artifacts: list[ArtifactOut] = Field(
        ..., description="ONE PAGE of the artifacts in this scope (see `limit`/`offset`)"
    )
    total_count: int = Field(..., description="Total number of artifacts in this scope")
    total_size: int = Field(..., description="Total size of all artifacts in bytes")
    truncated: bool = Field(
        ...,
        description=(
            "True when `artifacts` does NOT cover the whole scope, i.e. "
            "`offset + len(artifacts) < total_count`. Raise `offset` (or `limit`) "
            "until this is false to read the scope in full. ⛔ A client that "
            "ignores this field is reading a partial manifest as if it were "
            "complete — which is why the flag exists as well as `total_count`: "
            "a number a caller never asked for is easy to miss, a boolean named "
            "`truncated` is not."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "project_id": "3f2e4d5c-6a7b-8c9d-0e1f-2a3b4c5d6e7f",
                    "scope": "card",
                    "scope_ref": "123e4567-e89b-12d3-a456-426614174000",
                    "artifacts": [],
                    "total_count": 5,
                    "total_size": 12458960,
                    "truncated": False,
                }
            ]
        }
    )


class UploadResponse(BaseModel):
    """
    Response model for successful artifact upload.

    Returned after file is uploaded through storage_service and
    artifact record is created in the database.
    """

    artifact_id: UUID = Field(..., description="Unique identifier for the created artifact")
    version: int = Field(..., description="Version number (1 for new artifacts)")
    storage_key: str = Field(..., description="Storage key where the file is stored")
    size: int = Field(..., description="Size of the uploaded file in bytes")
    sha256: str = Field(..., description="SHA256 checksum of the uploaded file")
    # Provenance ECHO. The producer sent these; we send back what was actually
    # PERSISTED. Without it a caller that supplies `card_id` has no way to tell
    # "the association was recorded" from "the field was silently dropped"
    # except by re-reading the row — and a contract nobody can check is the
    # state this service was already in (card_id NULL on 58,573 rows).
    card_id: UUID | None = Field(
        None, description="Card this artifact is the output of, as persisted (null = none supplied)"
    )
    origin_kind: str = Field(
        "tenant", description="Provenance as persisted: tenant|project|workflow"
    )
    origin_project_id: UUID | None = Field(None, description="Origin project, as persisted")
    origin_workflow_run_id: str | None = Field(None, description="Origin n8n run id, as persisted")
    created_by_user_id: str = Field("", description="Creator subject id, as persisted")
    publish_status: PublishStatus = Field(
        PublishStatus.DRAFT, description="draft | published, as persisted"
    )
    title: str | None = Field(None, description="Document title, as persisted")
    doc_type: str | None = Field(None, description="Document type, as persisted")
    phase: str | None = Field(None, description="Producing phase, as persisted")
    summary: str | None = Field(None, description="One-line summary, as persisted")
    planka_card_id: str | None = Field(None, description="Planka card id, as persisted")

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "artifact_id": "bb4f5a67-c12d-34e5-f678-9012a3b4c5d6",
                    "version": 1,
                    "storage_key": "projects/3f2.../card/1a3.../bb4.../v1/presentation.pptx",
                    "size": 2457600,
                    "sha256": "a3c5f7e9b2d4c6a8f0e1d3b5c7a9f1e3d5b7c9a1f3e5d7b9c1a3f5e7d9b1c3a5",
                    "card_id": "1a3b5c7d-9e0f-4a2b-8c6d-3e5f7a9b1c2d",
                    "origin_kind": "workflow",
                    "origin_project_id": None,
                    "origin_workflow_run_id": "n8n:exec:481922",
                    "created_by_user_id": "0198c2d4-7a10-7c3e-8b91-4f6a2d5e8c07",
                }
            ]
        }
    )


class ArtifactFilter(BaseModel):
    """Filter parameters for listing artifacts."""

    card_id: UUID | None = Field(None, description="OPTIONAL: Filter by card UUID")
    step: str | None = Field(None, description="OPTIONAL: Filter by step identifier")
    kind: ArtifactKind | None = Field(None, description="OPTIONAL: Filter by artifact type")
    sensitivity: ArtifactSensitivity | None = Field(
        None, description="OPTIONAL: Filter by sensitivity level"
    )
    tags: list[str] = Field(default_factory=list, description="OPTIONAL: Filter by tags (OR logic)")
    limit: int = Field(
        100, ge=1, le=1000, description="Maximum number of results (1-1000, default: 100)"
    )
    offset: int = Field(
        0, ge=0, description="Number of results to skip (for pagination, default: 0)"
    )
