"""Gunicorn logging, bind address, and the control socket.

Alpine 3.24 ships gunicorn 25.2, which opens a control socket. The default
path is ``$XDG_RUNTIME_DIR/gunicorn.ctl`` or ``$HOME/.gunicorn/gunicorn.ctl``.
``/run`` is a symlink to ``/dev/shm``, so the socket stays on that tmpfs
when the root filesystem is read-only. The setting name is ``control_socket``
(command line ``--control-socket``), added in gunicorn 25.1.

gunicorn listens on ``127.0.0.1:8000``. That address is fixed.

``log_level`` in ``/opt/data/etc/config.yaml`` sets the level of the
gunicorn error logger, the access logger, and the root logger. ``notice``
is INFO, ``err`` is ERROR, and ``crit``, ``alert`` and ``emerg`` are
CRITICAL.
"""

from dns_host.config import GUNICORN_BIND, Settings
from dns_host.logutil import python_level_name

bind = GUNICORN_BIND
control_socket = "/run/gunicorn.ctl"

_level = python_level_name(Settings.load().log_level)

logconfig_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "msg": {
            "format": "dns-api: %(message)s"
        }
    },
    "handlers": {
        "syslog": {
            "class": "logging.handlers.SysLogHandler",
            "address": "/dev/log",
            "formatter": "msg",
        }
    },
    "loggers": {
        "gunicorn.error": {
            "level": _level,
            "handlers": ["syslog"],
            "propagate": False,
        },
        "gunicorn.access": {
            "level": _level,
            "handlers": ["syslog"],
            "propagate": False,
        },
    },
    "root": {
        "level": _level,
        "handlers": ["syslog"]
    },
}
accesslog = None
errorlog = None
capture_output = False
