"""The DEDICATED metrics-only listener (``metrics_server.py``).

Prometheus is outside the ambient mesh and the scrape relax is PORT-scoped, so
metrics must be served on their own port and NEVER on the API port. Pinned:

* ``start_metrics_server`` serves the tenant-source counter on its own port;
* the API app has no ``/metrics`` route (404 on the API port);
* a port already in use is fail-soft: a WARNING, no raise, no handle;
* the lifespan starts the listener on ``settings.metrics_port`` and stops it;
* ``metrics_port`` defaults to 9556 and reads ``METRICS_PORT``.
"""

from __future__ import annotations

import logging
import socket
import urllib.request

import httpx
import pytest
from fastapi import FastAPI

import main
from core.config import Settings
from metrics import TENANT_SOURCES
from metrics_server import start_metrics_server, stop_metrics_server

METRIC = "artifact_service_tenant_resolution_total"
TRUSTED_PEER = ("10.42.7.9", 40000)


def _scrape(port: int) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:  # noqa: S310
        assert resp.status == 200
        return resp.read().decode()


def test_metrics_server_serves_the_counter_on_its_own_port() -> None:
    app = FastAPI()
    start_metrics_server(app, 0)  # 0 = ephemeral; the real port is on the handle
    httpd = app.state.metrics_httpd
    try:
        body = _scrape(httpd.server_port)
    finally:
        stop_metrics_server(app)
    assert f"# TYPE {METRIC} counter" in body
    for source in TENANT_SOURCES:
        assert f'{METRIC}{{source="{source}"}}' in body
    assert getattr(app.state, "metrics_httpd", None) is None


def test_stop_releases_the_port() -> None:
    app = FastAPI()
    start_metrics_server(app, 0)
    port = app.state.metrics_httpd.server_port
    stop_metrics_server(app)
    with socket.socket() as s, pytest.raises(OSError):
        s.settimeout(2)
        s.connect(("127.0.0.1", port))


async def test_api_app_serves_no_metrics() -> None:
    paths = [getattr(r, "path", "") for r in main.app.routes]
    assert not [p for p in paths if p.startswith("/metrics")], paths
    transport = httpx.ASGITransport(app=main.app, client=TRUSTED_PEER)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/metrics")
    assert resp.status_code == 404, resp.text
    assert METRIC not in resp.text


def test_port_in_use_is_fail_soft(caplog: pytest.LogCaptureFixture) -> None:
    with socket.socket() as holder:
        holder.bind(("0.0.0.0", 0))  # noqa: S104 - same wildcard bind the server uses
        holder.listen(1)
        port = holder.getsockname()[1]
        app = FastAPI()
        with caplog.at_level(logging.WARNING, logger="metrics_server"):
            start_metrics_server(app, port)  # must not raise
    assert getattr(app.state, "metrics_httpd", None) is None
    assert any(
        r.levelno == logging.WARNING and str(port) in r.getMessage() for r in caplog.records
    ), caplog.text
    stop_metrics_server(app)  # no-op without a handle


async def test_lifespan_starts_and_stops_the_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "metrics_port", 0)
    app = FastAPI()
    async with main.lifespan(app):
        httpd = app.state.metrics_httpd
        assert METRIC in _scrape(httpd.server_port)
    assert getattr(app.state, "metrics_httpd", None) is None


def test_metrics_port_default_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("METRICS_PORT", raising=False)
    assert Settings().metrics_port == 9556
    monkeypatch.setenv("METRICS_PORT", "9999")
    assert Settings().metrics_port == 9999
    assert Settings().metrics_port != Settings().port
