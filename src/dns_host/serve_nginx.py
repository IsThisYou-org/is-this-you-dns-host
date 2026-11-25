"""Write nginx.conf on tmpfs and check it.

The file is regenerated at every start. The path is fixed at
``/run/nginx/nginx.conf``. ``/run`` is a symlink to ``/dev/shm``.
``bin/start_nginx`` execs nginx after this succeeds, or ``sleep 1001``
when the check fails.
"""

from __future__ import annotations

from pathlib import Path

from dns_host.checkconf import validate_generated
from dns_host.config import Settings, log_effective
from dns_host.render_nginx import render
from dns_host.zonesync import atomic_write

# Regenerated every start. /run is the /dev/shm tmpfs.
NGINX_CONF = Path("/run/nginx/nginx.conf")

# nginx -t opens the pid path and the temp paths. They stay on tmpfs so the
# check works when the root filesystem is read-only. /tmp/nginx-log is the
# compiled-in error log (the image points /var/log/nginx at it); nginx opens
# that file before it reads this config.
NGINX_TEMP_DIRS = (
    Path("/tmp/nginx-body"),
    Path("/tmp/nginx-proxy"),
    Path("/tmp/nginx-fastcgi"),
    Path("/tmp/nginx-uwsgi"),
    Path("/tmp/nginx-scgi"),
    Path("/tmp/nginx-log"),
)


def write_nginx_config(settings, conf_path: Path | None = None) -> Path:
    path = NGINX_CONF if conf_path is None else conf_path
    text = render(
        settings.max_body_bytes,
        list(settings.trusted_proxies),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    for directory in NGINX_TEMP_DIRS:
        directory.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text)
    validate_generated(path, ["nginx", "-t", "-c", str(path)])
    return path


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    write_nginx_config(settings)


if __name__ == "__main__":
    main()
