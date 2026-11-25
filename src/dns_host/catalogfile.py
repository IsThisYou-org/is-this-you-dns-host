"""Catalog file owned by the zone-master controller.

The file lists member zone names and their full SOA records. The catalog
SOA serial is stored in the file and is ``max(now, last + 1)`` when catalog
content changes (a member is added or removed, or another catalog RR
changes). A member content update rewrites that member's metadata without
changing the serial. When the serial is bumped, the file mtime is set to
that serial. The UDP and TCP services use mtime only to notice a rewrite,
and they answer catalog SOA from the serial stored in the file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dns_host.config import data_dir
from dns_host.zonesync import atomic_write


def next_catalog_serial(last: int, now: int) -> int:
    return max(int(now), int(last) + 1)


@dataclass
class Member:
    apex: str
    serial: int
    soa: str
    ttl: int
    expires_at: int
    parent_zone: str = ""


@dataclass
class Catalog:
    settings: object
    serial: int = 0
    zones: dict = field(default_factory=dict)
    mtime_ns: int | None = None

    @property
    def path(self) -> Path:
        return data_dir() / "catalog" / "catalog.json"

    @property
    def wire_path(self) -> Path:
        return self.path.with_suffix(".axfr")

    @property
    def loaded(self) -> bool:
        """True once a real catalog file has been read."""

        return self.mtime_ns is not None

    def has(self, apex: str) -> bool:
        return apex in self.zones

    def serial_of(self, apex: str) -> int | None:
        member = self.zones.get(apex)
        if member is None:
            return None
        return int(member.serial)

    def load(self) -> None:
        if not self.path.is_file():
            self.serial = 0
            self.zones = {}
            self.mtime_ns = None
            return
        # Take the mtime before and after the read. A replace in between
        # would pair old member data with the new mtime, and readers that
        # compare mtimes would then keep the stale member list.
        for _attempt in range(5):
            before = self.path.stat().st_mtime_ns
            text = self.path.read_text(encoding="utf-8")
            if self.path.stat().st_mtime_ns == before:
                break
        data = json.loads(text)
        zones = {}
        for item in data.get("zones", []):
            zones[item["apex"]] = Member(
                apex=item["apex"],
                serial=int(item["serial"]),
                soa=item.get("soa", ""),
                ttl=int(item.get("ttl") or 300),
                expires_at=int(item.get("expires_at") or 0),
                parent_zone=item.get("parent_zone") or "",
            )
        self.zones = zones
        # The served catalog SOA serial is the value stored in the file.
        # mtime is only a change signal: a member update rewrites the file
        # without bumping the serial, so the two can differ.
        stored = data.get("serial")
        if stored is not None:
            self.serial = int(stored)
        else:
            self.serial = int(before // 1_000_000_000)
        self.mtime_ns = before

    def save(self, now: int, bump: bool = True) -> int:
        if bump:
            self.serial = next_catalog_serial(self.serial, now)
        payload = {
            "serial":
            self.serial,
            "zones": [{
                "apex": member.apex,
                "serial": member.serial,
                "soa": member.soa,
                "ttl": member.ttl,
                "expires_at": member.expires_at,
                "parent_zone": member.parent_zone,
            } for member in sorted(self.zones.values(),
                                   key=lambda item: item.apex)],
        }
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        atomic_write(self.path, text)
        if bump:
            # Keep mtime equal to the new serial, as before.
            os.utime(self.path, (self.serial, self.serial))
        self.mtime_ns = self.path.stat().st_mtime_ns
        return self.serial

    def member_names(self) -> list[str]:
        return sorted(self.zones)

    def snapshot(self) -> tuple:
        return (
            int(self.serial),
            tuple(
                sorted((apex, int(member.serial))
                       for apex, member in self.zones.items())),
        )
