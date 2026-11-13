"""Alembic environment configuration."""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

from alembic import context

# Ensure src/ is on the import path when running alembic directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

# ⛔ SUPPLY THE SETTINGS FIELDS A MIGRATION DOES NOT NEED, BEFORE IMPORTING.
#
# `from core.database import Base` executes `core/database.py`, which builds a
# real engine AT IMPORT (`settings = get_settings()`, line 14). So constructing
# the full application `Settings` is a hard precondition of importing the
# models — and `Settings` requires `jwt_secret_key` and `postgres_password`.
#
# The archetype's "Run alembic migrations" step (gitops python-service.yml
# :1832-1837) exports ONLY PG_HOST/PG_PORT/PG_USER/PG_PASSWORD. So the gate died
# on two fields a schema migration has no business needing:
#
#     pydantic_core.ValidationError: 2 validation errors for Settings
#     jwt_secret_key    Field required
#     postgres_password Field required
#
# `setdefault` is the load-bearing choice: it NEVER overrides a value the
# environment already provides, so the init container — which receives the real
# secrets from the Deployment — is completely unaffected. These placeholders can
# only ever apply where the variable was absent, i.e. schema work, and they
# never reach a served request: this module runs under `alembic`, not uvicorn.
#
# The proper fix is to stop `core/database.py` building an engine at import.
# That is a production import-order change with real blast radius and belongs in
# its own PR; doing it inside a tenant-typing PR is how an unrelated outage gets
# shipped. Filed as a follow-up.
# NOT the real PG_PASSWORD. Settings enforces min_length=8 on
# postgres_password, and the CI sidecar's password is `ci_test` — SEVEN
# characters. Copying it across satisfied the "field required" error and then
# failed the length floor:
#     String should have at least 8 characters [input_value='ci_test']
# This value is never used to connect: the DSN comes from _database_url() and
# is set on sqlalchemy.url directly, while `core/database.py`'s engine is built
# but never dialled by alembic. So a placeholder is correct, and reusing the
# real password would only re-couple us to a floor we do not control.
if os.getenv("PG_PASSWORD") or os.getenv("POSTGRES_CI_PASSWORD"):
    os.environ.setdefault("POSTGRES_PASSWORD", "alembic-schema-work-only")
if os.getenv("PG_HOST") or os.getenv("POSTGRES_CI_HOST"):
    os.environ.setdefault(
        "POSTGRES_HOST", os.getenv("PG_HOST") or os.getenv("POSTGRES_CI_HOST") or ""
    )
    os.environ.setdefault("JWT_SECRET_KEY", "alembic-schema-work-only-no-runtime")

# Import your models (must come after sys.path modification)
from core.database import Base  # noqa: E402


def _database_url() -> str:
    """The DSN, preferring what the environment actually exports.

    ⛔ DO NOT go straight to ``get_settings()``. Building the full ``Settings``
    requires ``jwt_secret_key`` and ``postgres_password``, and the archetype's
    "Run alembic migrations" step (gitops python-service.yml:1832-1837) exports
    only ``PG_HOST``/``PG_PORT``/``PG_USER``/``PG_PASSWORD``. So the CI gate died
    on two fields a migration has no business needing:

        pydantic_core.ValidationError: 2 validation errors for Settings
        jwt_secret_key    Field required
        postgres_password Field required

    A migration needs a DSN, not an application. Reading the DSN the surrounding
    environment provides, and only falling back to ``Settings`` when it provides
    none, is what makes ``alembic: true`` a gate this repo can actually pass —
    and it is the same defect class as the test suite that skipped for months
    because it read ``TEST_DATABASE_URL``, a name nothing sets.
    """
    explicit = os.getenv("DATABASE_URL")
    if explicit:
        return explicit.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)

    host = os.getenv("PG_HOST") or os.getenv("POSTGRES_CI_HOST")
    if host:
        port = os.getenv("PG_PORT") or os.getenv("POSTGRES_CI_PORT") or "5432"
        user = os.getenv("PG_USER") or os.getenv("POSTGRES_CI_USER") or "postgres"
        pwd = os.getenv("PG_PASSWORD") or os.getenv("POSTGRES_CI_PASSWORD") or ""
        db = os.getenv("PG_DATABASE") or os.getenv("POSTGRES_DB") or "artifact_registry"
        return f"postgresql+psycopg://{user}:{pwd}@{host}:{port}/{db}"

    from core.config import get_settings  # noqa: PLC0415

    return str(get_settings().database_url_sync)


# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Get database URL from the environment, falling back to Settings (see above)
config.set_main_option("sqlalchemy.url", _database_url())

# Add your model's MetaData object here for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        do_run_migrations(connection)

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
