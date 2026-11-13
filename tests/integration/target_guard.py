"""Refuse to aim an integration run at a non-local host unless explicitly asked to.

Live-service integration suites are dangerous by default: a bare
``pytest tests/integration`` with a stale URL left in the environment writes real
rows into real data. A teardown ``DELETE`` is not a guarantee -- any crash
between create and delete leaves the row behind.

Rules enforced here:

* no target configured  -> the caller SKIPS (nothing defaults to a live host);
* a non-local host      -> refused, unless ``ALLOW_PROD_INTEGRATION=1``;
* an unparseable target -> refused, never assumed to be local.

"Local" is decided from the literal host, never by resolving it:

* the exact name ``localhost``, and any name under a reserved TLD
  (``.localhost``, ``.local``, ``.test``, ``.example``, ``.invalid``);
* loopback addresses ``127.0.0.0/8`` and ``::1`` (IPv4-mapped forms included).

Everything else is treated as remote: a bare service name (``postgres``), an
``<svc>.<ns>`` pair, a LAN / CGNAT / pod-network address, or any public name.
Inside a pod, short names resolve through the cluster search path; a
docker-compose service name is indistinguishable from those, so publish it on
``localhost`` instead.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping

ALLOW_PROD_VAR = "ALLOW_PROD_INTEGRATION"

_LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".example", ".invalid")
_LOOPBACK_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128"))
_KEYWORD_HOST = re.compile(r"(?:^|\s)host\s*=\s*'?([^\s']+)")


class ProdTargetRefused(RuntimeError):  # noqa: N818 -- same name in every repo's guard
    """Raised when a test run would write to a non-local host."""


def is_prod_host(host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h.split("%", 1)[0])
    except ValueError:
        ip = None
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return not any(ip in net for net in _LOOPBACK_NETWORKS)
    return not (h == "localhost" or h.endswith(_LOCAL_SUFFIXES))


def _hosts_of(target: str) -> list[str] | None:
    """Network hosts named by a URL or libpq keyword DSN; ``None`` if none is parseable.

    A path-valued host (``host=/var/run/postgresql``) is a local unix socket and
    is dropped; a target naming only sockets returns ``[]`` (parseable, local).
    """
    parts = urlsplit(target)
    hosts: list[str] = []
    if parts.scheme and parts.netloc:
        for hostport in parts.netloc.rpartition("@")[2].split(","):
            if hostport.startswith("["):
                hosts.append(hostport[1 : hostport.find("]")])
            elif hostport:
                hosts.append(hostport.split(":", 1)[0])
        for value in parse_qs(parts.query).get("host", []):
            hosts.extend(value.split(","))
    else:
        for value in _KEYWORD_HOST.findall(target):  # libpq keyword DSN: "host=... dbname=..."
            hosts.extend(value.split(","))
    hosts = [h for h in hosts if h]
    if not hosts:
        return None
    return [h for h in hosts if not h.startswith("/")]


def refusal(name: str, target: str, env: Mapping[str, str] | None = None) -> str | None:
    """Why ``target`` must not be used, or ``None`` when it is safe."""
    env = os.environ if env is None else env
    if env.get(ALLOW_PROD_VAR) == "1":
        return None
    hosts = _hosts_of(target)
    if hosts is None:
        return f"{name} has no parseable host -- refusing rather than guessing it is local"
    for host in hosts:
        if is_prod_host(host):
            return (
                f"{name} points at non-local host {host!r}; set {ALLOW_PROD_VAR}=1 only if "
                "writing test data there is really intended"
            )
    return None


def assert_not_prod(name: str, target: str, env: Mapping[str, str] | None = None) -> None:
    reason = refusal(name, target, env)
    if reason is not None:
        raise ProdTargetRefused(reason)


def integration_target(var: str, env: Mapping[str, str] | None = None) -> str | None:
    """The URL in ``var``; ``None`` when unset (caller skips). Never a remote default."""
    env = os.environ if env is None else env
    url = (env.get(var) or "").strip()
    if not url:
        return None
    assert_not_prod(var, url, env)
    return url
