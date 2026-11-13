"""Tests for configuration module."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from core.config import Settings, get_settings


class TestSettings:
    """Test Settings model."""

    @pytest.fixture
    def base_env(self):
        """Minimum required env vars for Settings."""
        return {
            "JWT_SECRET_KEY": "x" * 32,
            "POSTGRES_PASSWORD": "x" * 8,
            "POSTGRES_HOST": "localhost",
        }

    def test_default_values(self, base_env):
        # Note: tests run with ENVIRONMENT=development (set in conftest.py) so
        # the production validator stays out of the way. We confirm the rest of
        # the defaults are intact.
        env = {**base_env, "ENABLE_AUTH": "true", "ENABLE_VIRUS_SCANNING": "true"}
        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            s = Settings()
            assert s.environment == "development"
            assert s.service_name == "artifact-service"
            assert s.port == 8556
            assert s.enable_auth is True
            assert s.enable_virus_scanning is True

    def test_production_validator_rejects_missing_urls(self, base_env):
        """In production, missing service URLs must fail loud at startup."""
        env = {**base_env, "ENVIRONMENT": "production"}
        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            with pytest.raises(RuntimeError, match="missing required fields in production"):
                Settings()
        get_settings.cache_clear()

    def test_production_validator_passes_when_urls_set(self, base_env):
        """In production, with all required env vars set, Settings loads cleanly."""
        env = {
            **base_env,
            "ENVIRONMENT": "production",
            "POSTGRES_HOST": "db.example.com",
            "STORAGE_SERVICE_URL": "https://storage.example.com",
            "LICENSE_INTROSPECT_URL": "https://licenses.example.com/introspect",
            "OTLP_TRACES_ENDPOINT": "https://alloy.example.com:4318/v1/traces",
            "CORS_ALLOWED_ORIGINS": "https://app.example.com",
            "CLAMAV_HOST": "clamav.example.com",
            "KEYCLOAK_SERVER_URL": "https://keycloak.example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            s = Settings()
            assert s.environment == "production"
            assert s.allowed_cors_origins == ["https://app.example.com"]
        get_settings.cache_clear()

    def test_allowed_mimes(self, base_env):
        with patch.dict(os.environ, base_env, clear=False):
            s = Settings()
            mimes = s.allowed_mimes
            assert "application/pdf" in mimes
            assert "text/plain" in mimes

    def test_max_file_size_bytes(self, base_env):
        with patch.dict(os.environ, base_env, clear=False):
            s = Settings()
            assert s.max_file_size_bytes == 500 * 1024 * 1024

    def test_database_url(self, base_env):
        with patch.dict(os.environ, base_env, clear=False):
            s = Settings()
            url = s.database_url
            assert "postgresql+psycopg://" in url
            assert "localhost" in url
            assert "sslmode=prefer" in url

    def test_database_url_sync(self, base_env):
        with patch.dict(os.environ, base_env, clear=False):
            s = Settings()
            url = s.database_url_sync
            assert "postgresql+psycopg://" in url

    def test_database_url_with_ssl_params(self, base_env):
        env = {
            **base_env,
            "POSTGRES_SSLCERT": "/path/cert",
            "POSTGRES_SSLKEY": "/path/key",
            "POSTGRES_SSLROOTCERT": "/path/ca",
        }
        with patch.dict(os.environ, env, clear=False):
            s = Settings()
            url = s.database_url
            assert "sslcert=/path/cert" in url
            assert "sslkey=/path/key" in url
            assert "sslrootcert=/path/ca" in url

    def test_database_url_no_ssl(self, base_env):
        env = {**base_env, "POSTGRES_SSLMODE": ""}
        with patch.dict(os.environ, env, clear=False):
            s = Settings()
            url = s.database_url
            # When sslmode is empty, no query params should be present
            assert "sslmode=" not in url
            assert url.endswith(f"/{s.postgres_db}")

    def test_validate_log_level_valid(self, base_env):
        env = {**base_env, "LOG_LEVEL": "debug"}
        with patch.dict(os.environ, env, clear=False):
            s = Settings()
            assert s.log_level == "DEBUG"

    def test_validate_log_level_invalid(self, base_env):
        env = {**base_env, "LOG_LEVEL": "TRACE"}
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(ValidationError):
                Settings()


class TestGetSettings:
    """Test cached settings getter."""

    def test_returns_settings_instance(self):
        s = get_settings()
        assert isinstance(s, Settings)

    def test_cached(self):
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
