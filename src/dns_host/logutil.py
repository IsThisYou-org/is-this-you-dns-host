"""One-line JSON logs.

Records go to syslog only. The container's busybox syslogd writes
``/opt/data/log/messages`` by default. Messages below the configured
``log_level`` are dropped.
"""

from __future__ import annotations

import json
import syslog
from datetime import datetime, timezone
from typing import Any

# Least severe to most severe. ``warn`` and ``error`` are accepted aliases.
_ORDER = (
    "debug",
    "info",
    "notice",
    "warning",
    "err",
    "crit",
    "alert",
    "emerg",
)
_ALIASES = {
    "warn": "warning",
    "error": "err",
}
_CANONICAL = {name: name for name in _ORDER}
_CANONICAL.update(_ALIASES)
_RANK = {name: index for index, name in enumerate(_ORDER)}
_ALLOWED = ", ".join(_ORDER)

_SYSLOG = {
    "debug": syslog.LOG_DEBUG,
    "info": syslog.LOG_INFO,
    "notice": syslog.LOG_NOTICE,
    "warning": syslog.LOG_WARNING,
    "err": syslog.LOG_ERR,
    "crit": syslog.LOG_CRIT,
    "alert": syslog.LOG_ALERT,
    "emerg": syslog.LOG_EMERG,
}
# Python has no NOTICE level. crit, alert and emerg share CRITICAL.
_PYTHON_NAME = {
    "debug": "DEBUG",
    "info": "INFO",
    "notice": "INFO",
    "warning": "WARNING",
    "err": "ERROR",
    "crit": "CRITICAL",
    "alert": "CRITICAL",
    "emerg": "CRITICAL",
}

_threshold = _RANK["info"]
_opened = False


def parse_log_level(value: object) -> str:
    """Return the canonical syslog name for ``value``.

    Matching is case-insensitive. ``warn`` is ``warning`` and ``error`` is
    ``err``. An unrecognised value raises ``ValueError``.
    """

    text = str(value).strip().lower()
    canonical = _CANONICAL.get(text)
    if canonical is None:
        raise ValueError(
            f"invalid log_level {value!r}: expected one of {_ALLOWED} "
            "(warn and error are also accepted)")
    return canonical


def set_log_level(level: str) -> None:
    """Apply ``level`` to later ``log`` calls in this process."""

    global _threshold
    _threshold = _RANK[parse_log_level(level)]


def python_level_name(level: str) -> str:
    """Map a syslog ``log_level`` onto a Python logging level name."""

    return _PYTHON_NAME[parse_log_level(level)]


def _canonical(level: str) -> str | None:
    return _CANONICAL.get(str(level).strip().lower())


def _quiet_health(level: str) -> bool:
    """True when this line is routine noise from a health-check request.

    Warnings and errors are kept, including a health check that failed.
    """

    canonical = _canonical(level)
    if canonical is None or _RANK[canonical] >= _RANK["warning"]:
        return False
    try:
        from flask import has_request_context, request
    except ImportError:
        return False
    if not has_request_context():
        return False
    from dns_host.healthlog import is_health_path

    return is_health_path(request.path)


def log(level: str, msg: str, **fields: Any) -> None:
    global _opened
    canonical = _canonical(level)
    if canonical is not None and _RANK[canonical] < _threshold:
        return
    if _quiet_health(level):
        return
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "level": level,
        "msg": msg,
    }
    for key, value in fields.items():
        if value is not None:
            record[key] = value
    line = json.dumps(record, default=str, separators=(",", ":"))
    try:
        if not _opened:
            syslog.openlog("dns-host", syslog.LOG_PID, syslog.LOG_DAEMON)
            _opened = True
        priority = _SYSLOG.get(canonical or "", syslog.LOG_INFO)
        syslog.syslog(priority, line)
    except OSError:
        pass
