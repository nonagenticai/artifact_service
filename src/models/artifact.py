"""SQLAlchemy database models for artifacts."""

import uuid as _uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base
from models.schemas import ArtifactKind, ArtifactSensitivity, ArtifactStatus, PublishStatus


class Artifact(Base):
    """Artifact database model."""

    __tablename__ = "artifacts"

    # Primary key
    id: Mapped[_uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid.uuid7)

    # Tenant isolation (CRITICAL for multi-tenancy)
    # as_uuid=False is LOAD-BEARING, not cosmetic — but NOT for the reason this
    # comment used to give. It claimed the hazard was `_autofill_subject_id` (the
    # before_insert listener below) pushing a `uuid.UUID` into the VARCHAR
    # `subject_id` / `tenant_name` columns. MEASURED with as_uuid=True: the
    # insert SUCCEEDS. psycopg adapts the UUID object to text and both columns
    # store the identical canonical spelling — a caller passing a str and a
    # caller passing a uuid.UUID produce byte-identical rows (one DISTINCT row
    # across both). So the listener is not the problem.
    #
    # THE REAL HAZARD is on the READ side, and it is a fail-closed outage. With
    # as_uuid=True a loaded row hands back `uuid.UUID`, while every tenant value
    # in the request path is the canonical `str` from `tenant_id.canonical_tenant_id`.
    # A bare `resource.tenant_id != tenant_id` is then `UUID != str`, which is
    # ALWAYS True — so `auth/tenant.py::get_resource_with_tenant_check` and
    # `verify_tenant_ownership` would 404 EVERY request, for the rightful owner,
    # and it would read as "the data is gone" rather than as a type bug.
    # Measured: `row.tenant_id != tid` -> True, `str(row.tenant_id) != tid` -> False.
    #
    # Both of those call sites already wrap the left-hand side in `str()`
    # precisely for this, so they survive the flip; the risk is any NEW bare
    # comparison. If this is ever changed to as_uuid=True, audit every `!=` and
    # `==` against a tenant value first — not the listener.
    # The index is declared by name in __table_args__ (idx_artifacts_tenant_id, the
    # name the live database actually uses) rather than via index=True, which would
    # emit ix_artifacts_tenant_id and drift from production.
    tenant_id: Mapped[str] = mapped_column(Uuid(as_uuid=False))
    # Human-readable tenant name injected by license-authz (X-Tenant-Name header).
    # Backfilled to tenant_id for callers that don't supply the header (Phase 3).
    # Phase 4 landed in alembic revision 20260826_0003: tenant_id is now a native
    # UUID column; tenant_name stays VARCHAR (it is the human display label and,
    # for the legacy rows, the only surviving provenance).
    tenant_name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    # Per-user-within-tenant scoping
    # subject_id: the user (Subject UUID from licenses) who uploaded this artifact.
    #   '' (empty string) means "no recorded creator" — applies to artifacts uploaded
    #   before this column was added; they keep visibility='tenant' and are readable by
    #   all tenant members exactly as before.
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    # visibility: 'tenant' (default — every tenant member can read/delete)
    #             'user' (only the uploader can read/delete)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, server_default="tenant")

    # Project references
    project_id: Mapped[_uuid.UUID] = mapped_column(Uuid, index=True)
    card_id: Mapped[_uuid.UUID | None] = mapped_column(Uuid, index=True)
    step: Mapped[str | None] = mapped_column(String(100), index=True)
    container_name: Mapped[str | None] = mapped_column(String(255), index=True)

    # Version control
    version: Mapped[int] = mapped_column(Integer, default=1)

    # File metadata
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(100))
    kind: Mapped[ArtifactKind] = mapped_column(Enum(ArtifactKind, native_enum=False), index=True)
    sensitivity: Mapped[ArtifactSensitivity] = mapped_column(
        Enum(ArtifactSensitivity, native_enum=False), index=True
    )

    # File data
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    storage_key: Mapped[str] = mapped_column(Text, unique=True)

    # Audit fields
    created_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
    )

    # Asset-bindings provenance (~/.claude/plans/fr-asset-bindings-and-reuse.md Phase G).
    # `created_by` already carries the human creator. The four origin columns
    # below capture WHERE the artifact came from in the asset-bindings model:
    # tenant (human library upload), project (created inside a project), or
    # workflow (auto-emitted by an n8n run, with run id preserved).
    # Existing rows backfill to origin_kind='tenant'; project-scoped artifacts
    # that pre-date this migration stay 'tenant' since we can't reconstruct
    # the original creator-intent retroactively.
    origin_kind: Mapped[str] = mapped_column(String(20), default="tenant", server_default="tenant")
    origin_project_id: Mapped[_uuid.UUID | None] = mapped_column(Uuid)
    origin_workflow_run_id: Mapped[str | None] = mapped_column(String(200))
    created_by_user_id: Mapped[str] = mapped_column(String(255), default="", server_default="")

    # Review status — last decision recorded against this artifact.
    # CHECK constraint enforces values: pending | approved | rejected | needs_revision.
    # Updated by POST /projects/{p}/artifacts/{id}/review; insert path leaves at
    # the 'pending' default. Pre-migration rows backfill to 'pending'.
    # Stored as VARCHAR (per migration 006); the CHECK constraint enforces
    # the four allowed values. We deliberately use a plain str rather than
    # SQLAlchemy's Enum() because the project already converted other enum
    # columns (kind, sensitivity) to VARCHAR (migration 20260115_1200_*) and
    # mixing native_enum=False with values_callable behaves inconsistently
    # across SQLAlchemy 2.0.x patch versions.
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=ArtifactStatus.PENDING.value,
        index=True,
    )
    # Publication state for SYSTEM-TENANT INHERITANCE. Deliberately NOT named
    # `status`: that column already exists above and carries the REVIEW
    # decision (pending|approved|rejected|needs_revision), which is a different
    # axis — an approved artifact is not thereby shared with every tenant.
    # 'draft' (default) is visible only inside the owning tenant; 'published'
    # on a SYSTEM-tenant row additionally makes it readable (never writable) by
    # every other tenant — see repositories/visibility.py. For non-system
    # tenants the value is recorded but changes nothing today.
    # CHECK + (tenant_id, publish_status) index: alembic 20260927_0001.
    publish_status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default=PublishStatus.DRAFT.value,
        server_default=PublishStatus.DRAFT.value,
    )
    # Optional webhook URL set by the producer (typically an n8n custom node).
    # POSTed to with the review decision when a human submits a review. Never
    # set by humans; the artifact upload form on the BFF rejects it from
    # browser-origin requests.
    review_callback_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Document metadata (DOC-1, alembic 20261027_0001). All four are nullable
    # and set by the producer (conveyor) on upload or via PATCH .../metadata;
    # a row without them is an ordinary file, not a "document". They are the
    # human-facing face of the artifact on fr's Outputs page: a title instead
    # of a filename, a type ("Analysis report"), the project phase that
    # produced it, and a one-line summary. Review state, publication and
    # version deliberately reuse `status`, `publish_status`, `version` and
    # `artifact_reviews` — no second copy of any of them lives here.
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    doc_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    phase: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Planka's own card id (a 19-digit snowflake, NOT a uuid — so it cannot live
    # in `card_id`). Filled from the `planka_card:<id>` tag when not sent.
    planka_card_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Relationships
    tags = relationship(
        "ArtifactTag",
        back_populates="artifact",
        cascade="all, delete-orphan",
    )
    reviews = relationship(
        "ArtifactReview",
        back_populates="artifact",
        cascade="all, delete-orphan",
        order_by="ArtifactReview.reviewed_at",
    )

    # Indexes - tenant_id first for query efficiency; keep ALL existing indexes
    __table_args__ = (
        # Names below are the names the LIVE database uses (measured against
        # artifact_registry on worker4). Keep them byte-identical to production.
        Index("idx_artifacts_tenant_id", "tenant_id"),  # 20251224_0001
        Index("idx_tenant_project", "tenant_id", "project_id"),
        Index("idx_tenant_project_card", "tenant_id", "project_id", "card_id"),
        Index("idx_tenant_project_step", "tenant_id", "project_id", "step"),
        Index("idx_tenant_project_kind", "tenant_id", "project_id", "kind"),
        Index("idx_artifacts_created_at_desc", created_at.desc()),
        # New visibility scoping indexes
        Index("ix_artifacts_tenant_subject", "tenant_id", "subject_id"),
        Index("ix_artifacts_tenant_visibility", "tenant_id", "visibility"),
        Index("ix_artifacts_tenant_status", "tenant_id", "status"),  # 20260519_0001
        Index("ix_artifacts_tenant_publish_status", "tenant_id", "publish_status"),  # 20260927_0001
        Index(
            "ix_artifacts_tenant_project_phase", "tenant_id", "project_id", "phase"
        ),  # 20261027_0001
        Index("ix_artifacts_tenant_planka_card", "tenant_id", "planka_card_id"),  # 20261027_0001
        CheckConstraint("visibility IN ('tenant', 'user')", name="ck_artifacts_visibility"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'needs_revision')",
            name="ck_artifacts_status",
        ),
        CheckConstraint(
            "publish_status IN ('draft', 'published')",
            name="ck_artifacts_publish_status",
        ),
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<Artifact(id={self.id}, filename={self.filename}, "
            f"project_id={self.project_id}, version={self.version})>"
        )


def _autofill_subject_id(mapper: object, connection: object, target: Artifact) -> None:
    """Auto-fill subject_id and tenant_name when caller didn't set them.

    - subject_id := tenant_id  (pre-Plan-2 legacy fallback)
    - tenant_name := tenant_id  (Phase 3 fallback; overridden once license-authz
      starts injecting X-Tenant-Name on every request)

    Eliminates the need for routers/services to apply the fallback at every
    write site. Matches pre-Plan-2 behavior bit-for-bit for tenant-only
    callers.
    """
    if not getattr(target, "subject_id", None):
        target.subject_id = target.tenant_id
    if not getattr(target, "tenant_name", None):
        target.tenant_name = target.tenant_id


event.listen(Artifact, "before_insert", _autofill_subject_id)


class ArtifactTag(Base):
    """Artifact tag database model."""

    __tablename__ = "artifact_tags"

    # Composite primary key
    artifact_id: Mapped[_uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    tag: Mapped[str] = mapped_column(String(50), primary_key=True)

    # Relationship
    artifact = relationship("Artifact", back_populates="tags")

    # Indexes
    __table_args__ = (Index("idx_tag_lookup", "tag"),)

    def __repr__(self) -> str:
        """String representation."""
        return f"<ArtifactTag(artifact_id={self.artifact_id}, tag={self.tag})>"


class ArtifactReview(Base):
    """Per-decision review history for an artifact.

    One row per human decision. The artifact's `status` column always
    reflects the latest review's decision (mapped via DECISION_TO_STATUS in
    the routes layer). Keeps full audit trail of who decided what when, plus
    the comment.
    """

    __tablename__ = "artifact_reviews"

    id: Mapped[_uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid.uuid7)

    artifact_id: Mapped[_uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Decision enum (CHECK constraint in migration): approve | reject | revise.
    # We persist the raw decision verb (not the resulting status) so a future
    # change to status semantics doesn't rewrite history.
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Subject UUID of the reviewer (from X-Subject-Id). Different from the
    # artifact's tenant when a super-admin reviews on behalf of another
    # tenant — reviewer_tenant_id records the reviewer's home tenant for audit.
    reviewer_id: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewer_tenant_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)

    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    artifact = relationship("Artifact", back_populates="reviews")

    __table_args__ = (
        Index("ix_artifact_reviews_artifact_id", "artifact_id"),
        Index("ix_artifact_reviews_reviewed_at", "reviewed_at"),
        CheckConstraint(
            "decision IN ('approve', 'reject', 'revise')",
            name="ck_artifact_reviews_decision",
        ),
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<ArtifactReview(id={self.id}, artifact_id={self.artifact_id}, "
            f"decision={self.decision})>"
        )
