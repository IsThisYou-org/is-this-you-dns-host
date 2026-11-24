"""NSD configuration generated from the single secondary list.

``provide-xfr`` and ``notify`` are emitted from that list only, so they
cannot drift. TSIG material comes from ``config.yaml`` (or a secret file it
names). Zone-upload JSON is not an input.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from dns_host.config import DNS_BIND, DNS_PORT, NSD_BIND, NSD_PORT, data_dir
from dns_host.zonesync import atomic_write


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


def render_nsd(settings, zone_names: list[str] | None = None) -> str:
    """Render nsd.conf. ``zone_names`` are the catalog plus member apexes."""

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
        f'    xfrdir: "{data_dir() / "nsd" / "xfr"}"',
        f'    cookie-secret-file: "{data_dir() / "nsd" / "cookiesecrets.txt"}"',
        '    pidfile: "/run/nsd/nsd.pid"',
        f'    xfrdfile: "{data_dir() / "nsd" / "xfrd.state"}"',
        f'    zonelistfile: "{data_dir() / "nsd" / "zone.list"}"',
        "    username: nsd",
        "",
        "remote-control:",
        "    control-enable: yes",
        "    control-interface: /run/nsd/nsd.control",
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
    # One catalog zone. NSD creates member zones from it; nothing here is
    # rewritten when a user zone is added, and NSD is not reloaded.
    # AXFR (not IXFR) from the fixed internal listener. That transfer is
    # always allowed.
    master = "AXFR " + _endpoint(DNS_BIND, DNS_PORT)
    lines.extend([
        "pattern:",
        '    name: "catalog-member"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
    ])
    _transfer_acl(lines, settings)
    catalog_name = settings.catalog_zone.to_text().rstrip(".")
    lines.extend([
        "",
        "zone:",
        f'    name: "{catalog_name}"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
        "    catalog: consumer",
        '    catalog-member-pattern: "catalog-member"',
    ])
    _transfer_acl(lines, settings)
    lines.append("")
    # zone_names is intentionally unused: members come from the catalog zone.
    del zone_names
    return "\n".join(lines).rstrip() + "\n"


def _transfer_acl(lines: list[str], settings) -> None:
    for secondary in settings.secondaries:
        host, port = secondary[0], secondary[1]
        token = _key_token(secondary)
        endpoint = _endpoint(host, port)
        lines.append(f"    provide-xfr: {endpoint} {token}")
        lines.append(f"    notify: {endpoint} {token}")


def write_nsd_config(settings, zone_names: list[str] | None = None) -> Path:
    """Write the static NSD config. Members are not listed and NSD is not reloaded."""

    path = nsd_conf_path(settings)
    atomic_write(path, render_nsd(settings, zone_names))
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
