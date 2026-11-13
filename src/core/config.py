"""Configuration management for Artifact Registry Service."""

import json
from functools import lru_cache
from typing import Annotated, ClassVar, Literal

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Module scope, and it stays that way. ``tenant_id`` deliberately lives at the
# TOP LEVEL rather than inside ``auth/``: importing anything from the ``auth``
# package executes ``auth/__init__.py``, which eagerly imports
# ``auth.middleware``, which reads Settings AT IMPORT TIME — so an
# ``auth.*`` import from here re-enters ``Settings()`` while it is still being
# constructed. Measured: nesting depth 2, two Settings objects per cold start
# (the INNER one wins the ``get_settings`` lru_cache), and a missing env var
# renders as the nonsense ``default_tenant_id.jwt_secret_key — Field required``.
# A top-level module has no ``__init__`` to execute, so there is nothing to
# re-enter. Same shape as ``procedure_management``.
from tenant_id import canonical_tenant_id


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    environment: Literal["development", "staging", "production"] = "production"
    service_name: str = "artifact-service"
    log_level: str = "INFO"
    enable_docs: bool = False
    # Must be a uuid — see src/tenant_id.py. Deployments normally set
    # DEFAULT_TENANT_ID explicitly; the default here keeps a bare local run
    # working without one.
    default_tenant_id: str = "0195f48b-d000-7000-8000-000000000001"
    # The SYSTEM+IMPROVEMENT tenant. Its PUBLISHED, tenant-visible artifacts are
    # inherited READ-ONLY by every other tenant (repositories/visibility.py
    # `include_system=True`, read paths only). Deliberately a SEPARATE setting
    # from `default_tenant_id`: that one is the trusted-network fallback scope
    # for requests without X-Tenant-Id, this one names whose rows are shared.
    # They happen to hold the same uuid today; they are not the same concept.
    # Mirrors procedure_management's `system_tenant_id`.
    system_tenant_id: str = "0195f48b-d000-7000-8000-000000000001"
    # PLATFORM tenants — the ONLY tenants whose reads may widen to (inherit) the
    # SYSTEM tenant's published rows. Owner's ruling 2026-09-30: system and
    # improvement data live on their own tenants and must NEVER be visible to a
    # customer tenant. Every other tenant reads its OWN rows only:
    # include_system is a no-op for it (scope() never adds the system clause).
    # DEFAULT IS NON-EMPTY ON PURPOSE: the n8n conveyor (019de842…) reads
    # system-published artifacts, so an empty default would break it on any
    # deploy that lands before the env var does.
    #   …0001 system · …0002 workflow-improvement · …0003 execution ·
    #   …0004 prompt-improvement · …0005 procedure-improvement ·
    #   019de842… n8n-dev / AA conveyor tenant.
    # Mirrors procedure_management's `procedures_platform_tenant_ids`.
    # Env ARTIFACTS_PLATFORM_TENANT_IDS: a JSON list or comma-separated uuids.
    artifacts_platform_tenant_ids: Annotated[list[str], NoDecode] = [
        "0195f48b-d000-7000-8000-000000000001",
        "0195f48b-d000-7000-8000-000000000002",
        "0195f48b-d000-7000-8000-000000000003",
        "0195f48b-d000-7000-8000-000000000004",
        "0195f48b-d000-7000-8000-000000000005",
        "019de842-c92a-7e37-8fdd-eb0d8c5396f9",
    ]
    # What AuthMiddleware does with a token-less request that sends NO
    # X-Tenant-Id (trusted-network branch AND the AUTH_ENABLED=false bypass
    # branch). Env AUTH_TENANT_FALLBACK_MODE.
    #   enforce (default) — 401 TENANT_REQUIRED, counted as
    #     tenant_resolution_total{source="refused_missing_tenant"}. Owner's
    #     ruling (strict tenant separation): a request that names no tenant must
    #     never land silently in DEFAULT_TENANT_ID, which is the SYSTEM tenant.
    #   observe — the pre-2026-10 behaviour: serve as DEFAULT_TENANT_ID, tagged
    #     source="fallback_default". Break-glass / local dev only.
    # Same switch, same values as requirements_management's
    # AUTH_TENANT_FALLBACK_MODE.
    auth_tenant_fallback_mode: Literal["observe", "enforce"] = "enforce"
    # artifact_service#53: what AuthMiddleware does when a TRUSTED-network peer
    # names a uuid X-Tenant-Id without proving it (a licence in
    # `Authorization: Bearer` whose tenant equals the header). Env
    # AUTH_TENANT_PROOF_MODE.
    #   observe (default) — admit as before, counted as
    #     tenant_proof_total{outcome="explicit_header_unproven"}.
    #   enforce — 401 TENANT_PROOF_REQUIRED.
    # A licence for a DIFFERENT tenant: observe admits it and counts
    # outcome="explicit_header_mismatch"; enforce returns 403
    # TENANT_PROOF_MISMATCH. Owner's ruling: observe first, flip to enforce
    # once the unproven and mismatch populations are measured.
    auth_tenant_proof_mode: Literal["observe", "enforce"] = "observe"
    # TENANT_RLS_MODE (art#49): `enforce` binds `app.current_tenant` per
    # transaction (see src/tenant_guc.py); `off` (default) leaves the connection
    # untouched; empty/blank means unset (`off`). Any other value FAILS STARTUP — a typo must not silently turn
    # the RLS backstop off (it used to mean `off`).
    tenant_rls_mode: Literal["off", "enforce"] = "off"
    # Effective-tenant DELEGATION (RM #222/#223, worker_management). Env
    # AUTH_DELEGATING_SUBJECTS: comma-separated (or JSON list) licence SUBJECT
    # uuids — the introspected ``subject_id``, never a header — whose licence may
    # act for another tenant named in ``X-Effective-Tenant-Id`` (or, with the
    # licence in ``Authorization``, in a plain ``X-Tenant-Id``). EMPTY (the
    # default) disables delegation: the service then behaves exactly as before.
    # A non-uuid entry is a startup crash, never a silently ignored entry.
    auth_delegating_subjects: Annotated[list[str], NoDecode] = []
    enable_auth: bool = True  # Set ENABLE_AUTH=false to disable auth middleware
    port: int = 8556
    # DEDICATED plaintext Prometheus listener (env METRICS_PORT). ⛔ NEVER the
    # API port: the scrape relax (PeerAuthentication + allow-prometheus-scrape
    # NetworkPolicy) is PORT-scoped, so relaxing 8556 would expose the whole
    # API. Changing it must land together with the Deployment/Service port and
    # the gitops scrape policies. See src/metrics_server.py.
    metrics_port: int = Field(default=9556, gt=0)
    temp_dir: str = "/tmp/artifact_uploads"  # nosec B108 — standard temp directory usage

    # Security
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Database — host has no default; provided by gitops Deployment env.
    postgres_host: str = ""
    postgres_port: int = 5432
    postgres_db: str = "artifact_registry"
    postgres_user: str = "artifact_service"
    postgres_password: str = Field(..., min_length=8)
    postgres_sslmode: str = "prefer"
    postgres_sslcert: str | None = None
    postgres_sslkey: str | None = None
    postgres_sslrootcert: str | None = None

    # Storage Service (proxies to MinIO) — URL provided by gitops env.
    storage_service_url: str = ""
    storage_bucket: str = "artifacts"

    # ClamAV — host provided by gitops env.
    enable_virus_scanning: bool = True
    clamav_host: str = ""
    clamav_port: int = 3310
    clamav_timeout: float = 30.0
    quarantine_infected_files: bool = True

    # File Upload
    max_file_size_mb: int = 500
    allowed_content_types: str = "application/pdf,application/json,application/xml,text/plain,text/markdown,text/x-markdown,text/csv,image/png,image/jpeg,image/gif,image/webp,image/svg+xml,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/zip,application/gzip"

    # Largest SOURCE the render route will read into memory (DOC-1). A document
    # is a few hundred KB; this bounds what one render request can make the pod
    # parse and lay out, independent of the much larger upload cap above.
    render_max_source_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    # Renders allowed to run at once per process (CPU-bound, in worker threads);
    # the next one gets 503 + Retry-After rather than queueing.
    render_max_concurrency: int = Field(default=2, gt=0)

    @property
    def allowed_mimes(self) -> list[str]:
        """Parse allowed MIME types from config."""
        return [m.strip() for m in self.allowed_content_types.split(",")]

    # Keycloak — server URL provided by gitops env.
    keycloak_enabled: bool = True
    keycloak_server_url: str = ""
    keycloak_realm: str = "workflow-system"
    keycloak_client_id: str = "artifact-service"
    keycloak_client_secret: str | None = None

    # License introspection — full URL provided by gitops env.
    license_introspect_url: str = ""

    # OTLP traces — endpoint provided by gitops env.
    otlp_traces_endpoint: str = ""

    # CORS — comma-separated list of allowed origins; provided by gitops env.
    # Localhost dev origins are appended automatically when environment != production.
    cors_allowed_origins: str = ""

    @property
    def allowed_cors_origins(self) -> list[str]:
        """Parse the configured CORS origins, appending dev origins outside production."""
        configured = [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]
        if self.environment != "production":
            configured.extend(
                [
                    "http://localhost:3000",
                    "https://localhost:3000",
                ]
            )
        return configured

    # Retention
    intermediate_artifact_retention_days: int = 30
    cleanup_job_schedule: str = "0 2 * * *"

    # Fields that MUST be set via env in production; otherwise startup fails loud.
    _REQUIRED_IN_PRODUCTION: ClassVar[tuple[str, ...]] = (
        "postgres_host",
        "storage_service_url",
        "license_introspect_url",
        "otlp_traces_endpoint",
        "cors_allowed_origins",
    )

    def model_post_init(self, __context: object) -> None:
        if self.environment != "production":
            return
        missing: list[str] = []
        for name in self._REQUIRED_IN_PRODUCTION:
            if not getattr(self, name):
                missing.append(name)
        # clamav_host only required when virus scanning is enabled
        if self.enable_virus_scanning and not self.clamav_host:
            missing.append("clamav_host")
        # keycloak_server_url only required when keycloak is enabled
        if self.keycloak_enabled and not self.keycloak_server_url:
            missing.append("keycloak_server_url")
        if missing:
            raise RuntimeError(
                f"artifact-service settings missing required fields in production: {missing}. "
                "Set them as environment variables on the deployment."
            )

    @property
    def database_url(self) -> str:
        """Construct PostgreSQL connection URL for psycopg3.

        Note: psycopg3 supports SSL parameters in the URL query string via libpq.
        For PgBouncer connections, SSL is handled at the PgBouncer level.
        """
        base_url = (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

        # Add SSL parameters as query string (psycopg3 uses libpq, not connect_args)
        ssl_params = []
        if self.postgres_sslmode:
            ssl_params.append(f"sslmode={self.postgres_sslmode}")
        if self.postgres_sslcert:
            ssl_params.append(f"sslcert={self.postgres_sslcert}")
        if self.postgres_sslkey:
            ssl_params.append(f"sslkey={self.postgres_sslkey}")
        if self.postgres_sslrootcert:
            ssl_params.append(f"sslrootcert={self.postgres_sslrootcert}")

        if ssl_params:
            return f"{base_url}?{'&'.join(ssl_params)}"
        return base_url

    @property
    def database_url_sync(self) -> str:
        """Construct synchronous PostgreSQL connection URL for Alembic."""
        base_url = (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

        # Add SSL parameters as query string
        ssl_params = []
        if self.postgres_sslmode:
            ssl_params.append(f"sslmode={self.postgres_sslmode}")
        if self.postgres_sslcert:
            ssl_params.append(f"sslcert={self.postgres_sslcert}")
        if self.postgres_sslkey:
            ssl_params.append(f"sslkey={self.postgres_sslkey}")
        if self.postgres_sslrootcert:
            ssl_params.append(f"sslrootcert={self.postgres_sslrootcert}")

        if ssl_params:
            return f"{base_url}?{'&'.join(ssl_params)}"
        return base_url

    @property
    def max_file_size_bytes(self) -> int:
        """Convert max file size from MB to bytes."""
        return self.max_file_size_mb * 1024 * 1024

    @field_validator("auth_tenant_fallback_mode", "auth_tenant_proof_mode", mode="before")
    @classmethod
    def _normalise_tenant_fallback_mode(cls, v: object) -> object:
        """`Enforce ` / `OBSERVE` from the env mean the same; anything else still
        fails the Literal — an unknown mode is a startup crash, never a silent
        fallback to either behaviour."""
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("tenant_rls_mode", mode="before")
    @classmethod
    def _normalise_tenant_rls_mode(cls, v: object) -> object:
        """Trim/lower-case; empty or whitespace-only means unset (``off``), as in
        requirements_management / tool_registry / procedure_management. Any other
        unknown value still fails the Literal — a startup crash, never ``off``."""
        if isinstance(v, str):
            v = v.strip().lower()
            return v or "off"
        return v

    @field_validator("auth_delegating_subjects", mode="before")
    @classmethod
    def _split_delegating_subjects(cls, v: object) -> object:
        """JSON list or comma-separated string; blank means none."""
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                return json.loads(s)
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @field_validator("auth_delegating_subjects")
    @classmethod
    def _delegating_subjects_must_be_uuids(cls, v: list[str], info: ValidationInfo) -> list[str]:
        """Canonical uuids or a startup crash — an entry that can never match an
        introspected subject is a misconfiguration, not a no-op."""
        out: list[str] = []
        for entry in v:
            canonical = canonical_tenant_id(str(entry))
            if canonical is None:
                raise ValueError(
                    f"{info.field_name} entries must be licence subject UUIDs (got {entry!r})."
                )
            out.append(canonical)
        return out

    @field_validator("artifacts_platform_tenant_ids", mode="before")
    @classmethod
    def _split_platform_tenant_ids(cls, v: object) -> object:
        """Accept a JSON list or a comma-separated string from the env."""
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                return json.loads(s)
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @field_validator("artifacts_platform_tenant_ids")
    @classmethod
    def _platform_tenant_ids_must_be_uuids(cls, v: list[str], info: ValidationInfo) -> list[str]:
        """Same contract as ``validate_default_tenant_id``: crash at import on junk.

        An explicitly EMPTY list would silently cut every platform tenant
        (including the AA conveyor 019de842…) off from system rows. Unset the
        env var to get the built-in default; never run with no platform.
        """
        out: list[str] = []
        for entry in v:
            canonical = canonical_tenant_id(str(entry))
            if canonical is None:
                raise ValueError(
                    f"{info.field_name} entries must be UUIDs "
                    f"(got {entry!r}); set valid UUIDs on the Deployment env."
                )
            out.append(canonical)
        if not out:
            raise ValueError(
                "artifacts_platform_tenant_ids must not be empty; unset "
                "ARTIFACTS_PLATFORM_TENANT_IDS to use the built-in default."
            )
        return out

    @field_validator("default_tenant_id", "system_tenant_id")
    @classmethod
    def validate_default_tenant_id(cls, v: str, info: ValidationInfo) -> str:
        """Refuse to start unless DEFAULT_TENANT_ID / SYSTEM_TENANT_ID is a uuid; return it canonical.

        A misconfigured default is not a soft failure: every trusted-network
        request that omits ``X-Tenant-Id`` is scoped to this value, so a
        non-uuid here would either mint a tenant on first write or explode on
        the ``tenant_id`` uuid column at query time. Fail at construction —
        Settings is built at import of ``main``/``auth.middleware``, so this is
        a startup crash, which is loud, instead of a per-request 500, which is
        not.
        """
        canonical = canonical_tenant_id(v)
        if canonical is None:
            raise ValueError(
                f"{info.field_name} must be a uuid, got {v!r}. A tenant id is a uuid, not a "
                f"name — see src/tenant_id.py. Set {str(info.field_name).upper()} on the "
                "Deployment."
            )
        return canonical

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
