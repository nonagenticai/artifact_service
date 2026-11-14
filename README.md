# Artifact Service

[![CI](https://github.com/nonagenticai/artifact_service/actions/workflows/ci.yml/badge.svg)](https://github.com/nonagenticai/artifact_service/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nonagenticai/artifact_service)](https://github.com/nonagenticai/artifact_service/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Multi-tenant storage and retrieval of project artifacts, proxied through a
[storage service](https://github.com/nonagenticai/storage_service) (which owns the MinIO
credentials) with optional ClamAV virus scanning.

| | |
|---|---|
| **Stack** | Python 3.14 · FastAPI · SQLAlchemy · Pydantic |
| **Database** | PostgreSQL 18 |
| **Licence** | Apache-2.0 |

This is a source release. The service is complete and runs standalone against PostgreSQL; the
licence-introspection gate described under [Authentication](#authentication) is **optional and off
by default** — a licence service is not required to run it.

## What Artifact Service Does

When a workflow step, card action, or user needs to store a binary file (presentations, PDFs, images, datasets, test results), they send a multipart upload to this service scoped to a project ID. The service validates the filename against path-traversal attacks, checks the MIME type against a configurable whitelist, and optionally scans the file with ClamAV before forwarding it to storage_service for MinIO persistence. The service never touches MinIO directly -- all file I/O is proxied through storage_service, which is the only component holding MinIO credentials.

Each artifact is recorded in PostgreSQL with full metadata: project, card, step, container, kind, sensitivity level, SHA256 checksum, and tags. Every query is scoped by tenant_id, providing hard multi-tenant isolation at the database layer. Retrieval supports filtering by card, step, kind, sensitivity, and tags with pagination, and manifests let consumers pull all artifacts for a given scope (project, card, or step) in a single request. Downloads stream file content directly from storage through the service -- no presigned URLs are exposed.

The service supports seven artifact kinds (doc, presentation, image, dataset, json, graph, other) and three sensitivity levels (public, internal, secret). Files up to 500 MB are accepted by default. An automatic retention policy removes intermediate artifacts after a configurable number of days (default 30). All operations are auditable through structured logging and OpenTelemetry instrumentation, and health probes check database, storage, and ClamAV connectivity in parallel with a 10-second overall timeout.

## Features

- **Storage proxy pattern** -- all file I/O goes through storage_service so MinIO credentials are centralized in one place and never duplicated across services
- **ClamAV virus scanning** -- scans uploads in-process before persisting so infected files are rejected at the gate rather than stored and discovered later
- **Multi-tenant isolation** -- every database query filters by tenant_id so tenants can never see or access each other's artifacts
- **Streaming downloads** -- files are streamed in 64 KB chunks directly from storage so large files don't require full buffering in memory
- **Path traversal protection** -- double-decodes filenames and rejects traversal patterns, null bytes, and encoded slashes so storage keys can't be manipulated
- **MIME type whitelist** -- only allows explicitly configured content types (14 by default) so unexpected file formats are blocked before upload
- **Manifest generation** -- groups artifacts by scope (project, card, or step) in a single query so consumers can inventory all files for a given context without pagination
- **Sensitivity classification** -- tags artifacts as public, internal, or secret so downstream systems can enforce access control based on classification
- **Tag-based filtering** -- supports up to 20 tags per artifact with OR-logic queries so artifacts can be discovered by category without knowing exact IDs
- **Automatic retention** -- removes intermediate artifacts after a configurable period (default 30 days) so storage doesn't grow unbounded

## Authentication

Auth is **enabled by default** (`ENABLE_AUTH=true`). You do **not** need a licence service to run
it locally: a request from a trusted peer (RFC 1918 / loopback, which includes `localhost` and a
docker network) is admitted without a token, and its tenant comes from the `X-Tenant-Id` header.

| Priority | Method | Details |
|----------|--------|---------|
| 1 | Licence token | `X-Tenant-Id: Bearer <token>` only (the `Authorization` header is never read as a licence), validated by POSTing the token to `LICENSE_INTROSPECT_URL` |
| 2 | Trusted network | RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback skip token validation; tenant from the `X-Tenant-Id` header, which must be a tenant UUID (a name is 400 `INVALID_TENANT_ID`) |

⛔ `ENABLE_AUTH=false` does **not** mean "open": it removes the middleware entirely, so nothing
resolves a tenant and every protected route answers 401 `Missing tenant context`. It exists for
deployments that authenticate in front of the service and inject `X-Tenant-Id` themselves — not as
a local shortcut.

**A tenant is required.** A token-less request to a protected path (`/projects/*`, `/artifacts/*`, `/api/artifacts/*`) that sends **no** `X-Tenant-Id` is refused with **401 `TENANT_REQUIRED`** — on the trusted-network path and with `ENABLE_AUTH=false` alike — and counted as `artifact_service_tenant_resolution_total{source="refused_missing_tenant"}`. This is `AUTH_TENANT_FALLBACK_MODE=enforce`, the default. `AUTH_TENANT_FALLBACK_MODE=observe` is a break-glass that restores the old behaviour: the request is served as `DEFAULT_TENANT_ID` and counted as `source="fallback_default"`; such a caller still cannot publish.

From `localhost`, send any tenant UUID:
`-H "X-Tenant-Id: 0198c2d4-7a10-7c3e-8b91-4f6a2d5e8c07"`.

Health endpoints (`/`, `/health`, `/health/*`), docs, and metrics are always exempt.

## Quick Start

```bash
# 1. A database (or just: docker compose up -d db)
docker run -d --name artifact-pg -p 5432:5432 \
  -e POSTGRES_DB=artifact_registry -e POSTGRES_USER=artifact_service \
  -e POSTGRES_PASSWORD=changeme postgres:18

export POSTGRES_HOST=localhost POSTGRES_PASSWORD=changeme \
       JWT_SECRET_KEY=$(openssl rand -hex 32) \
       ENVIRONMENT=development ENABLE_VIRUS_SCANNING=false
uv sync
PYTHONPATH=src uv run alembic upgrade head

# The RLS revision revokes the runtime role's DML on purpose — re-grant it, as the
# schema owner, or every query will fail with "permission denied". In compose this is
# docker/grant-dml.py; here the database user is already the owner:
PGPASSWORD=$POSTGRES_PASSWORD psql -h localhost -U artifact_service -d artifact_registry \
  -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO artifact_service;"

PYTHONPATH=src uv run uvicorn main:app --host 0.0.0.0 --port 8556

# 2. Ask it something (any tenant UUID; loopback is a trusted peer)
curl -H "X-Tenant-Id: 0198c2d4-7a10-7c3e-8b91-4f6a2d5e8c07" \
     http://localhost:8556/api/artifacts

# 3. Tests and lint
uv run pytest tests/ -v --cov=src
uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/
```

`docker compose up` brings up PostgreSQL and the service together — see
[`docker-compose.yml`](docker-compose.yml). Uploads additionally need a running
[storage service](https://github.com/nonagenticai/storage_service); without one, the
metadata, manifest and health routes work and `/upload` fails at the storage call.

## API Endpoints

### Artifacts `/projects/{project_id}/artifacts`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/upload` | Upload artifact (multipart form with virus scan) |
| GET | `/` | List artifacts with card/step/kind/sensitivity/tag filters |
| GET | `/{artifact_id}` | Get artifact metadata |
| GET | `/{artifact_id}/download` | Download artifact (streaming) |
| DELETE | `/{artifact_id}` | Delete artifact from storage and database |
| GET | `/manifests/{scope}` | Get manifest by scope (project/card/step) |

### Cross-project `/api/artifacts` (tenant-scoped, no project id)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List artifacts across all projects in the caller's tenant |
| GET | `/by-card/{card_id}` | List artifacts for a card across all projects (`X-Total-Count`) |
| GET | `/{artifact_id}` | Get artifact metadata by id; 404 if missing or not visible (never 403) |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info and endpoint listing |
| GET | `/health` | Health check (database + storage + ClamAV) |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe (database only) |

## API Reference

### Upload Artifact

**`POST /projects/{project_id}/artifacts/upload`**

Upload an artifact file directly using multipart form data. The file is proxied through storage_service for MinIO storage. Virus scanning (if enabled) runs in-process before upload.

**Request:** Multipart form data

| Field           | Type       | Required | Default    | Description                                              |
|-----------------|------------|----------|------------|----------------------------------------------------------|
| `file`          | binary     | Yes      | -          | The file to upload                                       |
| `filename`      | string     | Yes      | -          | Filename (max 255 chars). Cannot contain `/`, `\`, `..` |
| `content_type`  | string     | Yes      | -          | MIME type (must be in allowed whitelist)                |
| `kind`          | enum       | Yes      | -          | Artifact type: `doc`, `presentation`, `image`, `dataset`, `json`, `graph`, `other` |
| `card_id`       | UUID       | No       | `null`     | **The card this artifact is the output of.** Send it whenever the upload happens with a card in context — it is what makes `GET /api/artifacts/by-card/{card_id}` able to find the artifact afterwards. Omit it only for uploads that genuinely have no card. |
| `step`          | string     | No       | `null`     | Step identifier (e.g., `QA:validation`)                 |
| `container_name`| string     | No       | `null`     | Container identifier for grouping                        |
| `sensitivity`   | enum       | No       | `internal` | Sensitivity: `public`, `internal`, `secret`             |
| `tags`          | string     | No       | `""`       | Comma-separated tags (max 20, each max 50 chars)        |
| `origin_kind`   | enum       | No       | `tenant`   | Provenance: `tenant` (human library upload), `project`, `workflow` |
| `origin_project_id` | UUID   | No       | `null`     | Required when `origin_kind=project`; must be absent otherwise |
| `origin_workflow_run_id` | string | No  | `null`     | Required when `origin_kind=workflow` (n8n run id, max 200 chars); must be absent when `origin_kind=project` |
| `created_by_user_id` | string | No      | X-Subject-Id | Creator subject id. Defaults to the authenticated subject. ⚠️ A multipart field sent EMPTY is reported by FastAPI as absent, so an empty value also falls back to the subject — this endpoint cannot record a deliberately-empty creator for a caller that has a subject. |

⚠️ `card_id` and `step` are **not** mutually exclusive; both may be sent. They
only compete for the storage-key scope, where `card_id` wins.

The origin triple is validated at the boundary and mirrors the DB CHECK
constraint `ck_artifacts_origin_consistency`, so an inconsistent combination is
a `400` before the file is read — not a `500` on COMMIT with the object already
in MinIO.

**Response (200 OK):**

| Field          | Type   | Description                           |
|----------------|--------|---------------------------------------|
| `artifact_id`  | UUID   | Unique artifact identifier            |
| `version`      | int    | Version number (always 1 for new)     |
| `storage_key`  | string | Internal storage key                  |
| `size`         | int    | File size in bytes                    |
| `sha256`       | string | SHA256 checksum (64 char hex)         |
| `card_id`      | UUID?  | The card association **as persisted** (`null` when none) |
| `origin_kind`  | string | Provenance as persisted               |
| `origin_project_id` | UUID? | Origin project as persisted      |
| `origin_workflow_run_id` | string? | Origin run id as persisted |
| `created_by_user_id` | string | Creator as persisted            |

The provenance fields in the response are read back off the stored row, not
echoed from the request, so a producer can tell "recorded" from "silently
dropped" without a second call.

**Error Responses:**
- `400` - Invalid filename (path traversal), content-type not in whitelist, or an inconsistent/over-long provenance field
- `401` - Missing or invalid license token, or no `X-Tenant-Id` at all (`TENANT_REQUIRED`)
- `403` - Virus detected in file
- `413` - File exceeds max size (default: 500 MB)
- `415` - Content-type not in allowed whitelist

**Example:**

```bash
curl -X POST "http://localhost:8556/projects/3f2e4d5c-6a7b/artifacts/upload" \
  -H "X-Tenant-Id: Bearer YOUR_LICENSE_TOKEN" \
  -F "file=@presentation.pptx" \
  -F "filename=presentation.pptx" \
  -F "content_type=application/vnd.openxmlformats-officedocument.presentationml.presentation" \
  -F "kind=presentation" \
  -F "card_id=123e4567-e89b-12d3-a456-426614174000" \
  -F "sensitivity=internal" \
  -F "tags=demo,q4-2024"
```

### List Artifacts

**`GET /projects/{project_id}/artifacts`**

| Parameter     | Type     | Required | Default | Description                              |
|---------------|----------|----------|---------|------------------------------------------|
| `card_id`     | UUID     | No       | -       | Filter by card UUID                      |
| `step`        | string   | No       | -       | Filter by step identifier                |
| `kind`        | enum     | No       | -       | Filter by artifact type                  |
| `sensitivity` | enum     | No       | -       | Filter by sensitivity level              |
| `tags`        | string[] | No       | -       | Filter by tags (OR logic)                |
| `limit`       | int      | No       | `100`   | Max results (1-1000)                     |
| `offset`      | int      | No       | `0`     | Pagination offset                        |

### Download Artifact

**`GET /projects/{project_id}/artifacts/{artifact_id}/download`**

Streams file content directly. Response headers include `Content-Disposition`, `Content-Length`, `X-Artifact-Id`, and `X-Artifact-SHA256`.

### Get Manifest

**`GET /projects/{project_id}/artifacts/manifests/{scope}`**

Scope values: `project`, `card`, `step`. Optional `scope_ref` query parameter for card UUID or step identifier.

Paginated: `limit` (default `1000`, max `1000`) and `offset`. `artifacts` holds ONE PAGE; `total_count` and `total_size` are computed in the database over the whole scope, and the boolean `truncated` states whether the page covers the scope (`offset + len(artifacts) < total_count`). Page by raising `offset` until `truncated` is false.

⚠️ The default is the cap (1000) rather than the list endpoints' 100 **on purpose**: a client that
sends no pagination and reads no headers must still receive a complete scope. Do not "harmonise" it
downwards before such a client pages — `tests/test_openapi.py::test_manifest_default_limit_stays_at_the_cap` guards it.

### List Artifact Reviews

**`GET /projects/{project_id}/artifacts/{artifact_id}/reviews`**

Review history, oldest-first. Paginated with `limit` (default `100`, max `1000`) and `offset`; the pre-pagination row count is in the `X-Total-Count` response header.

### List Artifacts by Card (cross-project)

**`GET /api/artifacts/by-card/{card_id}`**

Every artifact with the given `card_id` that the caller can see, across all projects in the tenant. Optional `name_prefix` filter. Paginated with `limit` (default `100`, max `1000`) and `offset`; the pre-pagination match count is returned in the `X-Total-Count` response header, so the caller is truncated exactly when `offset + len(body) < X-Total-Count`.

## Configuration

All configuration via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8556` | Listen port |
| `ENVIRONMENT` | `production` | Environment (`development`, `staging`, `production`) |
| `LOG_LEVEL` | `INFO` | Log level |
| `ENABLE_DOCS` | `false` | Enable /docs and /redoc |
| `ENABLE_AUTH` | `true` | License token auth middleware |
| `AUTH_TENANT_FALLBACK_MODE` | `enforce` | `enforce`: a token-less request without `X-Tenant-Id` is 401 `TENANT_REQUIRED`. `observe`: it is served as `DEFAULT_TENANT_ID` (break-glass only) |
| `DEFAULT_TENANT_ID` | `0195f48b-d000-7000-8000-000000000001` | Must be a UUID (startup fails otherwise). Tenant for header-less trusted-network requests, used **only** when `AUTH_TENANT_FALLBACK_MODE=observe` |
| `JWT_SECRET_KEY` | *(required)* | Secret for token validation (min 32 chars) |
| `POSTGRES_HOST` | *(required)* | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `artifact_registry` | Database name |
| `POSTGRES_USER` | `artifact_service` | Database user |
| `POSTGRES_PASSWORD` | *(required)* | Database password (min 8 chars) |
| `POSTGRES_SSLMODE` | `prefer` | SSL mode |
| `STORAGE_SERVICE_URL` | `""` | Storage service base URL (e.g. `http://localhost:8391`) |
| `STORAGE_BUCKET` | `artifacts` | MinIO bucket name |
| `ENABLE_VIRUS_SCANNING` | `true` | Enable ClamAV scanning on upload |
| `CLAMAV_HOST` | `""` | ClamAV daemon host |
| `CLAMAV_PORT` | `3310` | ClamAV daemon port |
| `CLAMAV_TIMEOUT` | `30.0` | ClamAV scan timeout (seconds) |
| `MAX_FILE_SIZE_MB` | `500` | Maximum upload size in MB |
| `ALLOWED_CONTENT_TYPES` | *(17 MIME types, incl. `application/xml`)* | Comma-separated allowed MIME whitelist |
| `LICENSE_INTROSPECT_URL` | `""` | Licence validation endpoint; empty disables token validation |
| `INTERMEDIATE_ARTIFACT_RETENTION_DAYS` | `30` | Auto-cleanup period in days |

## Architecture

```
src/
├── main.py                    # FastAPI app, CORS, auth middleware, routers
├── core/
│   ├── config.py              # Pydantic settings (30+ env vars)
│   └── database.py            # SQLAlchemy async engine + session factory
├── auth/
│   ├── middleware.py           # License token auth + trusted network bypass
│   ├── dependencies.py        # FastAPI dependency helpers (get_tenant_id)
│   ├── models.py              # User model for request state
│   └── tenant.py              # Tenant isolation helpers
├── routes/
│   ├── artifacts.py           # CRUD + upload + manifest endpoints
│   └── health.py              # Health/liveness/readiness probes
├── services/
│   ├── storage_service.py     # HTTP client for storage_service API
│   └── virus_scanner.py       # ClamAV TCP client
├── models/
│   ├── artifact.py            # SQLAlchemy ORM model (artifacts + artifact_tags)
│   └── schemas.py             # Pydantic request/response DTOs
├── logging_config.py          # Structured logging setup
└── telemetry.py               # OpenTelemetry instrumentation
alembic/
└── versions/                  # Database migrations
```

## Storage Key Format

Artifacts are stored in MinIO (via storage_service) using this key structure:

```
projects/{project_id}/{scope}/{scope_ref}/{artifact_id}/v{version}/{filename}
```

Examples:
```
projects/3f.../card/1a.../bb.../v1/marketing-plan.pptx
projects/3f.../step/QA:validation/cc.../v1/test-results.json
projects/3f.../project/_/dd.../v2/architecture-diagram.png
```

## Database Schema

### `artifacts` Table

| Column           | Type        | Description                          |
|------------------|-------------|--------------------------------------|
| id               | UUID        | Primary key                          |
| tenant_id        | VARCHAR     | Tenant identifier (isolation key)    |
| project_id       | UUID        | Project reference                    |
| card_id          | UUID        | Optional card reference              |
| step             | VARCHAR(100)| Optional step identifier             |
| container_name   | VARCHAR(255)| Optional container identifier        |
| version          | INTEGER     | Artifact version                     |
| filename         | VARCHAR(255)| Original filename                    |
| content_type     | VARCHAR(100)| MIME type                            |
| kind             | ENUM        | doc, presentation, image, etc.       |
| sensitivity      | ENUM        | public, internal, secret             |
| size             | BIGINT      | File size in bytes                   |
| sha256           | VARCHAR(64) | SHA256 checksum                      |
| storage_key      | TEXT        | Storage object key                   |
| created_by       | VARCHAR(255)| User who created artifact            |
| created_at       | TIMESTAMP   | Creation timestamp                   |
| origin_kind      | VARCHAR(20) | Provenance: `tenant` / `project` / `workflow` (CHECK) |
| origin_project_id| UUID        | Origin project, when `origin_kind=project` |
| origin_workflow_run_id | VARCHAR(200) | Origin n8n run id, when `origin_kind=workflow` |
| created_by_user_id | VARCHAR(255) | Subject id of the creator (`''` = none recorded) |

⛔ The four `origin_*` / `created_by_user_id` columns landed in alembic
`20260519_0002` and, until this endpoint learned to write them, were set by
NOTHING — every pre-existing row carries the server default, and `card_id` is
NULL on all of them. **Those legacy rows are not backfilled and cannot be**: the
card association was never recorded anywhere, so there is nothing to recover it
from. Reading provenance off a pre-existing row tells you only that nobody
declared any.

### `artifact_tags` Table

| Column      | Type        | Description                     |
|-------------|-------------|---------------------------------|
| artifact_id | UUID        | Foreign key to artifacts        |
| tag         | VARCHAR(50) | Tag value                       |

## Testing

```bash
uv run pytest tests/ -v --cov=src          # All tests with coverage
uv run pytest tests/unit/ -v               # Unit tests (11 files)
uv run pytest tests/integration/ -v        # Integration tests (health, manifests, upload)
uv run ruff check src/ tests/              # Lint
uv run ruff format --check src/ tests/     # Format check
uv run ty check .                          # Type check
```

Coverage threshold: 80% (enforced in pyproject.toml).

## CI

`.github/workflows/ci.yml` runs on GitHub-hosted runners only:
`gitleaks` → `private-refs` → `ruff` + `pytest` (against a `postgres:18` service container) → a
Docker build. It is deliberately self-contained and does **not** deploy: this repository is a source
release, and a public repo must never hold a credential that can push an image into a private
registry.

## Docker

```bash
docker build -t artifact-service .
docker run -p 8556:8556 \
  -e ENVIRONMENT=development \
  -e JWT_SECRET_KEY=$(openssl rand -hex 32) -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_HOST=<your database host> artifact-service
```

`ENVIRONMENT=development` matters: with `ENVIRONMENT=production` the service refuses to start
unless `STORAGE_SERVICE_URL`, `LICENSE_INTROSPECT_URL`, `OTLP_TRACES_ENDPOINT` and
`CORS_ALLOWED_ORIGINS` are all set.

## Dependencies

- **[storage_service](https://github.com/nonagenticai/storage_service)** — proxies all file I/O to MinIO; this service never touches object storage directly
- **PostgreSQL 18** — persistent storage
- **ClamAV** (port 3310) — optional virus scanning on upload
- **A licence service** — optional; only when `ENABLE_AUTH=true` and a real token must be validated
- **FastAPI** · **Uvicorn** · **SQLAlchemy** (async ORM, psycopg3) · **Pydantic** · **httpx** ·
  **structlog** · **OpenTelemetry**

## Known Issues

- **Schemathesis contract tests disabled** — `tests/contract/` exists with hooks but no CI step runs it.
- **No `/health/startup` endpoint** — `/health`, `/health/live` and `/health/ready` exist; use `/health/live` for a startup probe.

## Troubleshooting

### Storage Service Connection Issues

```bash
# Check the storage service is reachable (default in compose: http://localhost:8391)
curl "$STORAGE_SERVICE_URL/health"
```

### ClamAV Issues

```bash
# Check ClamAV connectivity (TCP port 3310)
nc -zv "$CLAMAV_HOST" 3310
```

### Database Migration Issues

```bash
# Check current migration version
PYTHONPATH=src uv run alembic current

# View migration history
PYTHONPATH=src uv run alembic history

# Downgrade if needed
PYTHONPATH=src uv run alembic downgrade -1
```

## Security

Report vulnerabilities privately through the repository's Security tab — see
[`SECURITY.md`](SECURITY.md). Do not open a public issue for a security problem.

## Contributing

Issues and pull requests are welcome. See
[`CONTRIBUTING.md`](https://github.com/nonagenticai/.github/blob/main/CONTRIBUTING.md) for the
organisation-wide rules; setup, test and lint commands are in this README. Commits carry DCO
sign-off.

## Licensing

The code in this repository is Apache-2.0 and needs no licence key to build, test or run.
Licence tokens are an **optional** identity source: with `LICENSE_INTROSPECT_URL` unset (the
default), a `Bearer` licence cannot be introspected, and callers authenticate through the
trusted-network path instead. With the URL set, every licence token is
introspected against the licences service, and an unreachable service yields no identity
(401) — never an admission.

The licensing stack is public too — [`licenses`](https://github.com/nonagenticai/licenses)
(entitlements, plans and tokens) and
[`license-authz`](https://github.com/nonagenticai/license-authz) (the Envoy `ext_authz`
enforcement point). Neither is required to run this code.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
