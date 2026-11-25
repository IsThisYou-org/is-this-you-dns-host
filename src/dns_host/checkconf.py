"""Run a daemon's own checker on a generated config file.

A rejected file is logged once. The start script then ``exec sleep`` with a
distinct argument, so BusyBox init does not respawn the service every second
and ``ps`` shows which check failed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from dns_host.logutil import log


def validate_generated(path: Path, argv: list[str]) -> None:
    """Exit the process when ``argv`` rejects ``path``."""

    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _stop(path, argv[0], str(exc))
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        _stop(path, argv[0], detail)


def _stop(path: Path, checker: str, detail: str) -> None:
    log(
        "error",
        f"{path} failed {checker}: {detail}; config.yaml is the likely cause",
        file=str(path),
        checker=checker,
        stderr=detail,
    )
    raise SystemExit(1)
