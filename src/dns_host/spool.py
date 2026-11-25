"""Spool of validated zones between the API workers and the controller.

The API creates an empty uniquely named file in the spool directory, writes
the zone document under ``spool/tmp`` with its own temporary name, then
``rename()``s that file over the empty one. Readers therefore see either an
empty file or a complete one. The body is the stored JSON document, not
AXFR wire.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"DHZONE1\n"


@dataclass
class SpoolJob:
    path: Path
    apex: str
    serial: int
    expires_at: int
    parent_zone: str
    soa: str
    soa_ttl: int
    document: dict


def encode_job(
    *,
    apex: str,
    serial: int,
    expires_at: int,
    parent_zone: str,
    soa: str,
    soa_ttl: int,
    document: dict,
) -> bytes:
    payload = {
        "apex": apex,
        "serial": int(serial),
        "expires_at": int(expires_at),
        "parent_zone": parent_zone,
        "soa": soa.replace("\n", " "),
        "soa_ttl": int(soa_ttl),
        "document": document,
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return MAGIC + body.encode("utf-8")


def decode_job(path: Path, data: bytes) -> SpoolJob:
    if not data.startswith(MAGIC):
        raise ValueError("spool file is not a zone document")
    try:
        payload = json.loads(data[len(MAGIC):].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("spool file is not a zone document") from exc
    document = payload.get("document")
    if not isinstance(document, dict) or "rrsets" not in document:
        raise ValueError("spool file document is incomplete")
    try:
        return SpoolJob(
            path=path,
            apex=str(payload["apex"]),
            serial=int(payload["serial"]),
            expires_at=int(payload["expires_at"]),
            parent_zone=str(payload["parent_zone"]),
            soa=str(payload["soa"]),
            soa_ttl=int(payload["soa_ttl"]),
            document=document,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("spool file header is incomplete") from exc


def submit(spool_dir: Path, payload: bytes) -> Path:
    """Publish one complete spool file. The final name is the empty placeholder."""

    spool_dir.mkdir(parents=True, exist_ok=True)
    temporary_dir = spool_dir / "tmp"
    temporary_dir.mkdir(parents=True, exist_ok=True)
    placeholder_fd, placeholder_name = tempfile.mkstemp(prefix="job",
                                                        dir=spool_dir)
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
