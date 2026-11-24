"""Catalog file owned by the zone-master controller.

The file lists member zone names and their full SOA records. Its own SOA
serial is ``max(now, last + 1)``. That value is also the file mtime, which is
what the UDP and TCP services read when they answer catalog SOA.
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
        data = json.loads(self.path.read_text(encoding="utf-8"))
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
        # The served catalog SOA serial is the file mtime. ``save`` sets that
        # mtime to max(now, last+1), so the two stay equal.
        self.serial = int(self.path.stat().st_mtime)
        self.mtime_ns = self.path.stat().st_mtime_ns

    def save(self, now: int) -> int:
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
