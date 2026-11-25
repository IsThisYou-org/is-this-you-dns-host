"""Run a daemon's own checker on a generated config file.

BusyBox init (``deploy/inittab``) uses ``respawn``. After a program exits,
init waits about a second (``sleep(1)`` in its main loop) and starts it
again. It does not give up. A bad ``config.yaml`` would otherwise write the
same error on every restart. The failure is logged once for a given file
and checker output, then the process exits non-zero and the daemon is not
started.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from dns_host.logutil import log

# /run is the /dev/shm tmpfs, so the stamp does not touch the read-only root.
STAMP_DIR = Path("/run/config-check")


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
    if completed.returncode == 0:
        _stamp_path(path).unlink(missing_ok=True)
        return
    detail = (completed.stderr or completed.stdout or "").strip()
    _stop(path, argv[0], detail)


def _stamp_path(path: Path) -> Path:
    safe = path.as_posix().lstrip("/").replace("/", "_")
    return STAMP_DIR / f"{safe}.stamp"


def _stop(path: Path, checker: str, detail: str) -> None:
    stamp = _stamp_path(path)
    try:
        previous = stamp.read_text(
            encoding="utf-8") if stamp.is_file() else None
    except OSError:
        previous = None
    if previous != detail:
        log(
            "error",
            f"{path} failed {checker}: {detail}; config.yaml is the likely cause",
            file=str(path),
            checker=checker,
            stderr=detail,
        )
        try:
            stamp.parent.mkdir(parents=True, exist_ok=True)
            temporary = stamp.with_name(stamp.name + ".tmp")
            temporary.write_text(detail, encoding="utf-8")
            os.replace(temporary, stamp)
        except OSError:
            pass
    raise SystemExit(1)
