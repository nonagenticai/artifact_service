"""Unit tests for the non-local target guard used by the integration suites."""

import pytest

from tests.integration.target_guard import (
    ALLOW_PROD_VAR,
    ProdTargetRefused,
    assert_not_prod,
    integration_target,
    is_prod_host,
    refusal,
)


@pytest.mark.parametrize(
    "host",
    [
        # public names and private DNS zones
        "db.example.com",
        "api.other.example.org",
        "pgbouncer.pgbouncer",
        "DB.EXAMPLE.COM.",
        # short service names (resolve through a pod's search path)
        "postgres",
        "pgbouncer2",
        # LAN, pod-network and CGNAT addresses
        "10.0.0.1",
        "10.42.0.1",
        "10.43.0.10",
        "192.168.1.110",
        "172.16.5.4",
        "198.51.100.20",
        "185.199.108.153",
        "[2001:db8::1]",
        "::ffff:203.0.113.10",
    ],
)
def test_remote_hosts_are_recognised(host):
    assert is_prod_host(host)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "localhost.",
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "[::1]",
        "api.example.test",
        "db.invalid",
        "app.localhost",
        "something.local",
    ],
)
def test_local_hosts_are_not_prod(host):
    assert not is_prod_host(host)


def test_unset_target_means_skip_never_a_remote_default():
    assert integration_target("SOME_URL", env={}) is None
    assert integration_target("SOME_URL", env={"SOME_URL": "  "}) is None


def test_local_target_is_returned():
    env = {"SOME_URL": "http://localhost:8400"}
    assert integration_target("SOME_URL", env=env) == "http://localhost:8400"


def test_remote_target_is_refused():
    with pytest.raises(ProdTargetRefused, match=r"non-local host 'db\.example\.com'"):
        integration_target("SOME_URL", env={"SOME_URL": "https://db.example.com"})


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql+psycopg://u:p@db.example.com:6432/db",
        "postgresql://u:p@203.0.113.11:5432/db",
        "postgresql://u:p@postgres:5432/db",
        "postgresql://u:p@10.43.12.34:6432/db",
        "postgresql://u:p@[2001:db8::5]:5432/db",
        "postgresql://u:p@localhost:5432,db.example.com:5432/db",
        "postgresql://u:p@/db?host=pgbouncer.pgbouncer",
        "host=db.example.com port=5432 dbname=db",
        "host=localhost,185.199.108.153 dbname=db",
    ],
)
def test_remote_database_urls_are_refused_in_url_and_keyword_form(dsn):
    with pytest.raises(ProdTargetRefused, match="non-local host"):
        assert_not_prod("DATABASE_URL", dsn, env={})


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql+psycopg://u:p@127.0.0.1:5442/db",
        "postgresql://u:p@[::1]:5432/db",
        "postgresql://u:p@/db?host=/var/run/postgresql",
        "host=localhost port=5432 dbname=db",
    ],
)
def test_local_database_urls_pass(dsn):
    assert_not_prod("DATABASE_URL", dsn, env={})


def test_unparseable_target_is_refused_not_assumed_local():
    reason = refusal("X", "not a url", env={})
    assert reason is not None
    assert "no parseable host" in reason


def test_only_exactly_1_lifts_the_refusal():
    url = "https://db.example.com"
    assert refusal("X", url, env={ALLOW_PROD_VAR: "true"}) is not None
    assert refusal("X", url, env={ALLOW_PROD_VAR: "1"}) is None
