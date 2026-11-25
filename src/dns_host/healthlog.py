"""Drop successful health-check lines from access logs.

``/health``, ``/ext/health`` and ``/int/health`` are probed on a timer.
A 2xx or 3xx for those paths is not logged. A 4xx or 5xx still is, and so
is any record that is not an access line.
"""

from __future__ import annotations

import logging
import re

_HEALTH_PATHS = frozenset({"/health", "/ext/health", "/int/health"})
_ACCESS = re.compile(
    r'"(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP/[^"]+"\s+(\d{3})'
)


def is_health_path(path: str) -> bool:
    bare = (path or "").split("?", 1)[0]
    if len(bare) > 1:
        bare = bare.rstrip("/")
    return bare in _HEALTH_PATHS


def access_path_and_status(
        record: logging.LogRecord) -> tuple[str | None, object]:
    """Path and status from a gunicorn or werkzeug access record."""

    args = record.args
    if isinstance(args, dict):
        path = args.get("U")
        request = args.get("r")
        if not path and isinstance(request, str):
            parts = request.split()
            path = parts[1] if len(parts) >= 2 else None
        if path:
            return str(path), args.get("s")
    match = _ACCESS.search(record.getMessage())
    if match is None:
        return None, None
    return match.group(1), match.group(2)


class SkipSuccessfulHealth(logging.Filter):
    """Logging filter for gunicorn's access logger and werkzeug."""

    def filter(self, record: logging.LogRecord) -> bool:
        path, status = access_path_and_status(record)
        if path is None or not is_health_path(path) or status is None:
            return True
        try:
            code = int(status)
        except (TypeError, ValueError):
            return True
        return code >= 400
