# ==============================================================================
# Artifact Registry Service - Multi-stage Dockerfile
# ==============================================================================

# -----------------------------------------------------------------------------
# Base Stage - Common dependencies
# -----------------------------------------------------------------------------
ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/library/python:3.14-slim AS base

# Install system dependencies
# WeasyPrint runtime libraries (GET .../render?format=pdf, DOC-1): pango (text
# layout, pulls in harfbuzz + fontconfig + freetype), the harfbuzz subsetter
# (font embedding) and one font family. Same approach as w2v analysis_service;
# no cairo/gdk-pixbuf — WeasyPrint >= 53 does not use them. `fc-cache` bakes the
# font cache into the image: the pod runs readOnlyRootFilesystem, so fontconfig
# could not write one at runtime and would rescan fonts on every render.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    netcat-openbsd \
    ca-certificates \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    fontconfig \
    fonts-liberation \
    && fc-cache -f \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy UV from official image (multi-arch compatible)
COPY --from=ghcr.io/astral-sh/uv:0.10.10 /uv /usr/local/bin/uv

ENV PATH="/usr/local/bin:$PATH"

# Configure uv environment
ENV UV_SYSTEM_PYTHON=1

# -----------------------------------------------------------------------------
# Dependencies Stage
# -----------------------------------------------------------------------------
FROM base AS dependencies

COPY pyproject.toml README.md uv.lock* ./

# Install dependencies only (cached layer - not invalidated by code changes)
RUN uv sync --frozen --no-dev --no-install-project

# -----------------------------------------------------------------------------
# Development Stage
# -----------------------------------------------------------------------------
FROM base AS development

COPY pyproject.toml README.md uv.lock* ./

# Install dependencies only (cached layer - not invalidated by code changes)
RUN uv sync --frozen --no-install-project

COPY . .

# Install the local project and create directories
RUN uv sync --frozen && \
    mkdir -p /app/logs /app/data /tmp/artifact_uploads

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8556", "--reload"]

# -----------------------------------------------------------------------------
# Production Stage
# -----------------------------------------------------------------------------
FROM base AS production

# Create user before copies + non-recursive chown: a trailing `chown -R /app`
# here measured 72.2s cache-cold (full tree walk + a second non-dedupable
# layer). --chown= on each COPY makes ownership free at copy time instead.
RUN useradd -m -u 1000 artifact && \
    mkdir -p /app && \
    chown artifact:artifact /app

# Copy virtual environment from dependencies stage
COPY --from=dependencies --chown=artifact:artifact /app/.venv /app/.venv

# Copy application code
COPY --chown=artifact:artifact src /app/src
COPY --chown=artifact:artifact alembic.ini /app/
COPY --chown=artifact:artifact alembic /app/alembic
COPY --chown=artifact:artifact docker /app/docker

# Runtime-writable dirs created after the copies — no trailing chown -R to
# catch these anymore, so each gets its own explicit non-recursive chown.
RUN mkdir -p /app/logs /app/data /tmp/artifact_uploads && \
    chown artifact:artifact /app/logs /app/data /tmp/artifact_uploads

# Switch to application user
USER artifact

# Set Python path
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH=/app/src

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
    CMD curl -f http://localhost:8556/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8556"]
