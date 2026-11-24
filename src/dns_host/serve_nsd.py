"""Wait for nsd.conf, install control keys, and exec NSD in the foreground.

NSD binds port 53 as root, then drops to the ``nsd`` user. State it must
write after that drop lives under ``/opt/data/nsd``, which is chowned first.
The pid file stays on the ``/run`` tmpfs. Remote control listens on
127.0.0.1 only.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from dns_host.config import Settings, log_effective
from dns_host.nsdconf import ensure_control_keys, nsd_conf_path, write_nsd_config
from dns_host.shard import discard_nsd_fnv_zonefiles


def _chown_tree(directory: Path, user: str) -> None:
    account = pwd.getpwnam(user)
    for root, dirs, files in os.walk(directory):
        os.chown(root, account.pw_uid, account.pw_gid)
        for name in dirs + files:
            os.chown(os.path.join(root, name), account.pw_uid, account.pw_gid)


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    path = nsd_conf_path(settings)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    zones = directory / "zones"
    xfr = directory / "xfr"
    zones.mkdir(parents=True, exist_ok=True)
    xfr.mkdir(parents=True, exist_ok=True)
    # Drop hash-layout copies. NSD transfers those zones once into %1/%2.
    discard_nsd_fnv_zonefiles(zones)
    runtime = Path("/run/nsd")
    runtime.mkdir(parents=True, exist_ok=True)
    write_nsd_config(settings)
    ensure_control_keys(directory)
    _chown_tree(directory, "nsd")
    _chown_tree(runtime, "nsd")
    os.execvp("nsd", ["nsd", "-d", "-c", str(path)])


if __name__ == "__main__":
    main()
