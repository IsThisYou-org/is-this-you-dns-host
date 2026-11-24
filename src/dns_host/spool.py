"""Spool of validated zones between the API workers and the controller.

The API creates an empty uniquely named file in the spool directory, writes
the wire payload under ``spool/tmp`` with its own temporary name, then
``rename()``s that file over the empty one. Readers therefore see either an
empty file or a complete one. JSON is not stored; the payload is wire-format
AXFR data plus a short header the controller needs.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"DHAXFR1\n"


@dataclass
class SpoolJob:
    path: Path
    apex: str
    serial: int
    expires_at: int
    parent_zone: str
    soa: str
    soa_ttl: int
    wire: bytes


def encode_job(
    *,
    apex: str,
    serial: int,
    expires_at: int,
    parent_zone: str,
    soa: str,
    soa_ttl: int,
    wire: bytes,
) -> bytes:
    header = "\n".join(
        [
            apex,
            str(int(serial)),
            str(int(expires_at)),
            parent_zone,
            str(int(soa_ttl)),
            soa.replace("\n", " "),
        ]
    )
    return MAGIC + header.encode("utf-8") + b"\n\n" + wire


def decode_job(path: Path, data: bytes) -> SpoolJob:
    if not data.startswith(MAGIC):
        raise ValueError("spool file is not wire-format AXFR data")
    rest = data[len(MAGIC) :]
    marker = rest.find(b"\n\n")
    if marker < 0:
        raise ValueError("spool file header is truncated")
    lines = rest[:marker].decode("utf-8").split("\n")
    if len(lines) != 6:
        raise ValueError("spool file header is incomplete")
    apex, serial, expires_at, parent_zone, soa_ttl, soa = lines
    return SpoolJob(
        path=path,
        apex=apex,
        serial=int(serial),
        expires_at=int(expires_at),
        parent_zone=parent_zone,
        soa=soa,
        soa_ttl=int(soa_ttl),
        wire=rest[marker + 2 :],
    )


def submit(spool_dir: Path, payload: bytes) -> Path:
    """Publish one complete spool file. The final name is the empty placeholder."""

    spool_dir.mkdir(parents=True, exist_ok=True)
    temporary_dir = spool_dir / "tmp"
    temporary_dir.mkdir(parents=True, exist_ok=True)
    placeholder_fd, placeholder_name = tempfile.mkstemp(prefix="job", dir=spool_dir)
    os.close(placeholder_fd)
    data_fd, data_name = tempfile.mkstemp(prefix="data", dir=temporary_dir)
    try:
        with os.fdopen(data_fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(data_name, placeholder_name)
    except Exception:
        if os.path.exists(data_name):
            os.unlink(data_name)
        if os.path.exists(placeholder_name):
            os.unlink(placeholder_name)
        raise
    return Path(placeholder_name)


def pending(spool_dir: Path) -> list[Path]:
    """Oldest non-empty regular files. Empty files, directories and hidden names are ignored."""

    if not spool_dir.is_dir():
        return []
    found: list[Path] = []
    for entry in spool_dir.iterdir():
        if entry.name.startswith("."):
            continue
        if not entry.is_file():
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        if size <= 0:
            continue
        found.append(entry)
    found.sort(key=lambda item: (item.stat().st_mtime_ns, item.name))
    return found
