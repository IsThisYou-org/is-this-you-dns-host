"""Write nginx.conf on tmpfs and exec nginx in the foreground.

The file is regenerated at every start. The path is fixed at
``/run/nginx/nginx.conf``. ``/run`` is a symlink to ``/dev/shm``.
"""

from __future__ import annotations

import os
from pathlib import Path

from dns_host.config import Settings, log_effective
from dns_host.render_nginx import render
from dns_host.zonesync import atomic_write

# Regenerated every start. /run is the /dev/shm tmpfs.
NGINX_CONF = Path("/run/nginx/nginx.conf")


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    text = render(
        settings.max_body_bytes,
        list(settings.trusted_proxies),
    )
    NGINX_CONF.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(NGINX_CONF, text)
    os.execvp("nginx", [
        "nginx", "-e", "/tmp/nginx-startup.log", "-c",
        str(NGINX_CONF), "-g", "daemon off;"
    ])


if __name__ == "__main__":
    main()
