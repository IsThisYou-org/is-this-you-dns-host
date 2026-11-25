"""Zone files and the internal zone catalogue under ``/opt/data/zones``.

The API is the only writer. It writes a zone file, then the catalogue, each
via a temp file in the same directory and ``os.replace``. The DNS side polls
the catalogue mtime about once a second and re-reads only when it changes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import dns.name

from dns_host.shard import locate_zone_file, zone_file_name, zone_path
from dns_host.zone import document_to_zone


def zones_dir_for(db_path: Path) -> Path:
    return Path(db_path).parent / "zones"


def zone_filename(apex: str) -> str:
    return zone_file_name(apex, ".json")


def member_path(directory: Path, apex: str) -> Path:
    return zone_path(directory, apex, zone_filename(apex))


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def write_member(directory: Path, apex: str, document: dict) -> None:
    atomic_write(
        member_path(directory, apex),
        json.dumps(document, separators=(",", ":"), sort_keys=True),
    )


def read_member(directory: Path, apex: str) -> dict | None:
    """The on-disk zone document, or ``None`` when the file is absent."""

    path = member_path(directory, apex)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_catalogue(directory: Path, catalog_serial: int,
                    zones: list[dict]) -> None:
    payload = {
        "catalog_serial": int(catalog_serial),
        "zones": sorted(zones, key=lambda item: item["apex"]),
    }
    atomic_write(
        directory / "catalogue.json",
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
    )


def read_catalogue(directory: Path) -> dict | None:
    path = directory / "catalogue.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


class ZoneIndex:
    """In-memory wire zones, refreshed from the catalogue file."""

    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self.directory = zones_dir_for(store.path)
        self._mtime: int | None = None
        self.loaded = False
        self.catalog_serial = 0
        self.zones: dict = {}
        self.serials: dict[str, int] = {}

    def refresh(self) -> bool:
        path = self.directory / "catalogue.json"
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            return False
        if mtime == self._mtime:
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            serials = {
                item["apex"]: int(item["serial"])
                for item in data.get("zones", [])
            }
            zones = {}
            for apex, serial in serials.items():
                if self.serials.get(apex) == serial and apex in self.zones:
                    zones[apex] = self.zones[apex]
                    continue
                member = locate_zone_file(self.directory, apex,
                                          zone_filename(apex))
                if member is None:
                    raise FileNotFoundError(apex)
                document = json.loads(member.read_text(encoding="utf-8"))
                zones[apex] = document_to_zone(dns.name.from_text(apex),
                                               document)
        except Exception:
            # Leave the previous snapshot in place and retry on the next poll.
            return False
        self.zones = zones
        self.serials = serials
        self.catalog_serial = int(data.get("catalog_serial") or 0)
        self._mtime = mtime
        self.loaded = True
        return True

    def member_names(self) -> list[str]:
        return sorted(self.serials)
