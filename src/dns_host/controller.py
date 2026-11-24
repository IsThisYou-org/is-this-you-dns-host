"""Zone-master controller. One process owns the catalog and the zone files.

It polls the spool directory mtime, takes the oldest non-empty file, and
ignores empty files, directories and hidden names. The SOA serial is checked
again here: the API's check only fails fast. Zone bytes are installed with a
temporary file and ``rename``. Zones whose signatures have been expired for
more than the grace period are removed.
"""

from __future__ import annotations

import base64
import os
import time
from pathlib import Path

import dns.message
import dns.rdatatype

from dns_host.catalogfile import Catalog, Member
from dns_host.config import data_dir
from dns_host.logutil import log
from dns_host.notifyplan import plan_notifies, send_plan
from dns_host.shard import remove_zone_file, zone_file_name, zone_path
from dns_host.spool import decode_job, pending
from dns_host.wireaxfr import catalog_tcp_bytes


def zone_wire_path(settings, apex: str) -> Path:
    del settings
    return zone_path(data_dir() / "zones", apex, zone_file_name(apex, ".axfr"))


def discard_zone_wire(settings, apex: str) -> None:
    del settings
    remove_zone_file(data_dir() / "zones", apex, zone_file_name(apex, ".axfr"))


class Controller:

    def __init__(self, settings, store, notifier=None):
        self.settings = settings
        self.store = store
        self.notifier = notifier
        self.catalog = Catalog(settings)
        self._spool_mtime = None

    @property
    def spool_dir(self) -> Path:
        return data_dir() / "spool"

    def ensure_catalog(self) -> None:
        self.catalog.load()
        if self.catalog.path.is_file():
            self._write_catalog_wire()
            return
        self.catalog.serial = 0
        self.catalog.zones = {}
        self.catalog.save(self.settings.now())
        self._write_catalog_wire()

    def serve_forever(self) -> None:
        self.ensure_catalog()
        while True:
            try:
                self.run_once()
            except Exception as exc:
                log("error", "zone controller failed", error=str(exc))
            time.sleep(0.5)

    def run_once(self) -> list[str]:
        self.catalog.load()
        before = self.catalog.snapshot()
        changed = False
        for path in pending(self.spool_dir):
            if self._consume(path):
                changed = True
        if self._age_out():
            changed = True
        if not changed:
            return []
        self.catalog.save(self.settings.now())
        self._write_catalog_wire()
        messages = plan_notifies(self.settings, before, self.catalog)
        send_plan(self.notifier, messages)
        return [zone for zone, _soa in messages]

    def remove(self, apex: str, now: int) -> int | None:
        self.catalog.load()
        had = apex in self.catalog.zones
        self.catalog.zones.pop(apex, None)
        sql_serial = self.store.delete_zone(apex, now)
        discard_zone_wire(self.settings, apex)
        if not had and sql_serial is None:
            return None
        if had:
            self.catalog.save(now)
            self._write_catalog_wire()
        return self.catalog.serial

    def _consume(self, path: Path) -> bool:
        try:
            job = decode_job(path, path.read_bytes())
        except Exception as exc:
            log("warning",
                "dropping unreadable spool file",
                path=str(path),
                error=str(exc))
            path.unlink(missing_ok=True)
            return False
        held = self.catalog.serial_of(job.apex)
        if held is not None and job.serial <= held:
            log(
                "info",
                "dropping spool file whose SOA serial is not higher",
                apex=job.apex,
                serial=job.serial,
                held=held,
            )
            path.unlink(missing_ok=True)
            return False
        self._install_wire(job.apex, job.wire)
        self.catalog.zones[job.apex] = Member(
            apex=job.apex,
            serial=job.serial,
            soa=job.soa,
            ttl=job.soa_ttl,
            expires_at=job.expires_at,
            parent_zone=job.parent_zone,
        )
        self._remember_sqlite(job)
        path.unlink(missing_ok=True)
        log("info",
            "zone installed from spool",
            apex=job.apex,
            serial=job.serial)
        return True

    def _install_wire(self, apex: str, wire: bytes) -> None:
        destination = zone_wire_path(self.settings, apex)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
        temporary.write_bytes(wire)
        os.replace(temporary, destination)

    def _remember_sqlite(self, job) -> None:
        document, min_expiry, max_expiry = _document_from_wire(
            job.apex, job.wire)
        if max_expiry <= 0:
            max_expiry = job.expires_at
            min_expiry = job.expires_at
        self.store.replace_zone(
            apex=job.apex,
            serial=job.serial,
            document=document,
            now=self.settings.now(),
            rrsig_min_expiry=min_expiry,
            rrsig_max_expiry=max_expiry,
            parent_zone=job.parent_zone or ".",
        )

    def _age_out(self) -> bool:
        now = self.settings.now()
        limit = self.settings.grace_seconds
        removed = []
        for apex, member in list(self.catalog.zones.items()):
            if member.expires_at and now > int(member.expires_at) + limit:
                removed.append(apex)
        if not removed:
            return False
        for apex in removed:
            self.catalog.zones.pop(apex, None)
            discard_zone_wire(self.settings, apex)
            self.store.delete_zone(apex, now)
            log("info",
                "zone aged out",
                apex=apex,
                reason="rrsig grace elapsed")
        return True

    def _write_catalog_wire(self) -> None:
        blob = catalog_tcp_bytes(self.settings, self.catalog.serial,
                                 self.catalog.member_names())
        atomic_write_bytes(self.catalog.wire_path, blob)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _document_from_wire(apex: str, wire: bytes) -> tuple[dict, int, int]:
    grouped: dict[tuple[str, str], dict] = {}
    expiries: list[int] = []
    offset = 0
    seen_soa = False
    while offset + 2 <= len(wire):
        length = int.from_bytes(wire[offset:offset + 2], "big")
        offset += 2
        message = dns.message.from_wire(wire[offset:offset + length])
        offset += length
        for rrset in message.answer:
            if int(rrset.rdtype) == int(dns.rdatatype.SOA):
                if seen_soa:
                    continue
                seen_soa = True
            type_name = dns.rdatatype.to_text(rrset.rdtype)
            if int(rrset.rdtype) == int(dns.rdatatype.RRSIG):
                pieces = {}
                for rdata in rrset:
                    pieces.setdefault(int(rdata.type_covered),
                                      []).append(rdata)
                    expiries.append(int(rdata.expiration))
                encoded_groups = [((rrset.name.to_text(), type_name, covered),
                                   rdatas, int(rrset.ttl))
                                  for covered, rdatas in pieces.items()]
            else:
                encoded_groups = [((rrset.name.to_text(), type_name),
                                   list(rrset), int(rrset.ttl))]
            for key, rdatas, ttl in encoded_groups:
                encoded = [
                    base64.b64encode(rdata.to_wire()).decode("ascii")
                    for rdata in rdatas
                ]
                bucket = grouped.get(key)
                if bucket is None:
                    grouped[key] = {
                        "name": rrset.name.to_text(),
                        "type": type_name,
                        "ttl": ttl,
                        "wire": encoded,
                    }
                    continue
                if int(bucket["ttl"]) != ttl:
                    raise ValueError(
                        f"{rrset.name.to_text()} {type_name} has more than one TTL"
                    )
                for item in encoded:
                    if item not in bucket["wire"]:
                        bucket["wire"].append(item)
    document = {
        "apex": apex,
        "rrsets": [grouped[key] for key in sorted(grouped)]
    }
    if not expiries:
        return document, 0, 0
    return document, min(expiries), max(expiries)


def main() -> None:
    from dns_host.config import Settings, log_effective
    from dns_host.storage import Store

    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    from dns_host.shard import migrate_flat_zone_files

    migrate_flat_zone_files(data_dir() / "zones")
    store = Store(settings.db_path)
    store.ensure_catalog(settings.now())
    Controller(settings, store).serve_forever()


if __name__ == "__main__":
    main()
