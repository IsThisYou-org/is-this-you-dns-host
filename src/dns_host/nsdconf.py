"""NSD configuration generated from the secondary list and ``axfr_allow``.

``notify`` is emitted for secondaries only. ``provide-xfr`` is emitted for
each secondary and, with ``NOKEY``, for each ``axfr_allow`` network. TSIG
material comes from ``config.yaml`` (or a secret file it names). Zone-upload
JSON is not an input.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from dns_host.config import (
    DNS_BIND,
    DNS_PORT,
    NSD_BIND,
    NSD_CONTROL_HOST,
    NSD_CONTROL_PORT,
    NSD_PORT,
    data_dir,
)
from dns_host.shard import canonical_zone
from dns_host.zonesync import atomic_write

# How often NSD writes a changed secondary zone to its zonefile. The file is
# what NSD reads after a restart; the next SOA check decides whether to AXFR.
ZONEFILES_WRITE_SECONDS = 60

# Member zones come from the catalog. NSD expands this pattern itself:
# %1 and %2 are the first and second characters of the zone name, %s is
# the whole name. A missing character, and a real ".", both become the
# path component "." (the current directory), so "a" and "a.example" are
# written as a/./<name>.zone, which is a/<name>.zone. NSD creates the
# parent directories when it writes the file (dbcreate.c create_dirs).
MEMBER_ZONEFILE = "%1/%2/%s.zone"
CATALOG_ZONEFILE = "catalog.zone"


def nsd_conf_path(settings) -> Path:
    del settings
    return data_dir() / "nsd" / "nsd.conf"


def _endpoint(host: str, port: int) -> str:
    if port and int(port) != 53:
        return f"{host}@{int(port)}"
    return host


def _key_token(secondary) -> str:
    name = getattr(secondary, "tsig_key_name", "") or ""
    secret = getattr(secondary, "tsig_secret", "") or ""
    if name and secret:
        return name
    return "NOKEY"


def render_nsd(settings) -> str:
    """Render nsd.conf. Member zones are learned from the catalog only."""

    lines = [
        "server:",
        "    server-count: 1",
        "    hide-version: yes",
        f"    ip-address: {NSD_BIND}",
        f"    port: {int(NSD_PORT)}",
        "    do-ip4: yes",
        "    do-ip6: no",
        "    verbosity: 2",
        "    log-only-syslog: yes",
        f'    zonesdir: "{data_dir() / "nsd" / "zones"}"',
        f"    zonefiles-write: {ZONEFILES_WRITE_SECONDS}",
        f'    xfrdir: "{data_dir() / "nsd" / "xfr"}"',
        f'    cookie-secret-file: "{data_dir() / "nsd" / "cookiesecrets.txt"}"',
        '    pidfile: "/run/nsd/nsd.pid"',
        f'    xfrdfile: "{data_dir() / "nsd" / "xfrd.state"}"',
        f'    zonelistfile: "{data_dir() / "nsd" / "zone.list"}"',
        "    username: nsd",
        "",
        "remote-control:",
        "    control-enable: yes",
        f"    control-interface: {NSD_CONTROL_HOST}",
        f"    control-port: {int(NSD_CONTROL_PORT)}",
        f'    server-key-file: "{data_dir() / "nsd" / "nsd_server.key"}"',
        f'    server-cert-file: "{data_dir() / "nsd" / "nsd_server.pem"}"',
        f'    control-key-file: "{data_dir() / "nsd" / "nsd_control.key"}"',
        f'    control-cert-file: "{data_dir() / "nsd" / "nsd_control.pem"}"',
        "",
    ]
    seen_keys: set[str] = set()
    for secondary in settings.secondaries:
        name = getattr(secondary, "tsig_key_name", "") or ""
        secret = getattr(secondary, "tsig_secret", "") or ""
        algo = getattr(secondary, "tsig_algo", "") or "hmac-sha256"
        if not name or not secret or name in seen_keys:
            continue
        seen_keys.add(name)
        lines.extend([
            "key:",
            f'    name: "{name}"',
            f"    algorithm: {algo}",
            f'    secret: "{secret}"',
            "",
        ])
    # AXFR (not IXFR) from the fixed internal listener. That transfer is
    # always allowed. Only the catalog zone is listed here. NSD adds and
    # removes member zones from the catalog; their files use the pattern.
    master = "AXFR " + _endpoint(DNS_BIND, DNS_PORT)
    lines.extend([
        "pattern:",
        '    name: "catalog-member"',
        f'    zonefile: "{MEMBER_ZONEFILE}"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
    ])
    _transfer_acl(lines, settings)
    catalog_name = canonical_zone(settings.catalog_zone.to_text())
    lines.extend([
        "",
        "zone:",
        f'    name: "{catalog_name}"',
        f'    zonefile: "{CATALOG_ZONEFILE}"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
        "    catalog: consumer",
        '    catalog-member-pattern: "catalog-member"',
    ])
    _transfer_acl(lines, settings)
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _transfer_acl(lines: list[str], settings) -> None:
    """Secondaries may AXFR and are NOTIFY targets. ``axfr_allow`` may AXFR."""

    for secondary in settings.secondaries:
        host, port = secondary[0], secondary[1]
        token = _key_token(secondary)
        endpoint = _endpoint(host, port)
        lines.append(f"    provide-xfr: {endpoint} {token}")
        lines.append(f"    notify: {endpoint} {token}")
    for network in settings.axfr_allow:
        lines.append(f"    provide-xfr: {network} NOKEY")


def write_nsd_config(settings) -> Path:
    """Write nsd.conf. Members are not listed; the catalog zone adds them."""

    path = nsd_conf_path(settings)
    atomic_write(path, render_nsd(settings))
    return path


def ensure_control_keys(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "nsd_server.key").is_file() and (
            directory / "nsd_control.key").is_file():
        return
    setup = "/usr/sbin/nsd-control-setup"
    if not os.path.isfile(setup):
        return
    subprocess.run([setup, "-d", str(directory)], check=False, timeout=20)
