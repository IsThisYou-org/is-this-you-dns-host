"""Gunicorn logging and the control socket.

Alpine 3.24 ships gunicorn 25.2, which opens a control socket. The default
path is ``$XDG_RUNTIME_DIR/gunicorn.ctl`` or ``$HOME/.gunicorn/gunicorn.ctl``.
``/run`` is a symlink to ``/dev/shm``, so the socket stays on that tmpfs
when the root filesystem is read-only. The setting name is ``control_socket``
(command line ``--control-socket``), added in gunicorn 25.1.
"""

control_socket = "/run/gunicorn.ctl"

logconfig_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"msg": {"format": "dns-api: %(message)s"}},
    "handlers": {
        "syslog": {
            "class": "logging.handlers.SysLogHandler",
            "address": "/dev/log",
            "formatter": "msg",
        }
    },
    "loggers": {
        "gunicorn.error": {"level": "INFO", "handlers": ["syslog"], "propagate": False},
        "gunicorn.access": {"level": "INFO", "handlers": ["syslog"], "propagate": False},
    },
    "root": {"level": "INFO", "handlers": ["syslog"]},
}
accesslog = None
errorlog = None
capture_output = False
