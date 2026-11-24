"""NSD configuration generated from the secondary list and ``axfr_allow``.

``notify`` is emitted for secondaries only. ``provide-xfr`` is emitted for
each secondary and, with ``NOKEY``, for each ``axfr_allow`` network. TSIG
material comes from ``config.yaml`` (or a secret file it names). Zone-upload
JSON is not an input.
"""

from __future__ import annotations

import os
import pwd
import shutil
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
from dns_host.shard import canonical_zone, relative_zonefile
from dns_host.zonesync import atomic_write

# How often NSD writes a changed secondary zone to its zonefile. The file is
# what NSD reads after a restart; the next SOA check decides whether to AXFR.
ZONEFILES_WRITE_SECONDS = 60


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
    # always allowed. NSD zonefile patterns expand %s, %1, %2, %3, %z, %y,
    # and %x (characters and labels). None of those is the FNV shard, so
    # each zone gets an explicit zonefile path. The member pattern itself
    # has no zonefile; the zone blocks below name the file.
    master = "AXFR " + _endpoint(DNS_BIND, DNS_PORT)
    lines.extend([
        "pattern:",
        '    name: "catalog-member"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
    ])
    _transfer_acl(lines, settings)
    catalog_name = canonical_zone(settings.catalog_zone.to_text())
    lines.extend([
        "",
        "zone:",
        f'    name: "{catalog_name}"',
        f'    zonefile: "{relative_zonefile(catalog_name)}"',
        f"    request-xfr: {master} NOKEY",
        f"    allow-notify: {DNS_BIND} NOKEY",
        "    catalog: consumer",
        '    catalog-member-pattern: "catalog-member"',
    ])
    _transfer_acl(lines, settings)
    lines.append("")
    for name in _member_names(catalog_name, zone_names):
        lines.extend([
            "zone:",
            f'    name: "{name}"',
            '    include-pattern: "catalog-member"',
            f'    zonefile: "{relative_zonefile(name)}"',
            "",
        ])
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


def _member_names(catalog_name: str,
                  zone_names: list[str] | None) -> list[str]:
    seen = {catalog_name}
    members: list[str] = []
    for name in zone_names or []:
        try:
            canon = canonical_zone(name)
            if not canon or canon in seen:
                continue
            # Reject a name that cannot be a zonefile basename.
            relative_zonefile(canon)
        except ValueError:
            continue
        seen.add(canon)
        members.append(canon)
    return sorted(members)


def nsd_zones_dir() -> Path:
    return data_dir() / "nsd" / "zones"


def ensure_nsd_zone_dirs(names: list[str]) -> None:
    """Create ``hh/ll`` under the NSD zonesdir and give them to the nsd user.

    NSD writes the zonefile at the configured relative path. Those parent
    directories have to exist first, and the nsd user has to be able to
    create the file after it drops privileges.
    """

    root = nsd_zones_dir()
    root.mkdir(parents=True, exist_ok=True)
    _chown_nsd(root)
    seen: set[Path] = set()
    for name in names:
        try:
            relative = relative_zonefile(name)
        except ValueError:
            continue
        directory = (root / relative).parent
        if directory in seen:
            continue
        seen.add(directory)
        directory.mkdir(parents=True, exist_ok=True)
        _chown_nsd(directory.parent)
        _chown_nsd(directory)


def _chown_nsd(path: Path) -> None:
    try:
        account = pwd.getpwnam("nsd")
    except KeyError:
        return
    try:
        os.chown(path, account.pw_uid, account.pw_gid)
    except OSError:
        return


def write_nsd_config(settings, zone_names: list[str] | None = None) -> Path:
    """Write nsd.conf, including an explicit zonefile path for each member."""

    path = nsd_conf_path(settings)
    atomic_write(path, render_nsd(settings, zone_names))
    names = [settings.catalog_zone.to_text()]
    if zone_names:
        names.extend(zone_names)
    ensure_nsd_zone_dirs(names)
    return path


def reload_nsd() -> bool:
    """Ask a running NSD to reread nsd.conf. Missing control socket is fine."""

    binary = shutil.which("nsd-control")
    conf = data_dir() / "nsd" / "nsd.conf"
    if binary is None or not conf.is_file():
        return False
    try:
        result = subprocess.run(
            [binary, "-c", str(conf), "reload"],
            check=False,
            timeout=5,
            capture_output=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_reload(str(exc))
        return False
    if result.returncode != 0:
        detail = (result.stderr or result.stdout
                  or b"").decode("utf-8", "replace").strip()
        log_reload(detail or f"exit {result.returncode}")
        return False
    from dns_host.logutil import log

    log("info", "nsd reloaded")
    return True


def log_reload(error: str) -> None:
    from dns_host.logutil import log

    log("info", "nsd reload did not apply", error=error)


def ensure_control_keys(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "nsd_server.key").is_file() and (
            directory / "nsd_control.key").is_file():
        return
    setup = "/usr/sbin/nsd-control-setup"
    if not os.path.isfile(setup):
        return
    subprocess.run([setup, "-d", str(directory)], check=False, timeout=20)
