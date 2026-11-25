"""Zone-master controller. One process owns the catalog and the zone files.

It polls the spool directory mtime, takes the oldest non-empty file, and
ignores empty files, directories and hidden names. The SOA serial is checked
again here: the API's check only fails fast. The spooled document is stored
as the per-zone JSON file and as SQLite metadata. Zones whose signatures
have been expired for more than the grace period are removed.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from dns_host.catalogfile import Catalog, Member
from dns_host.config import data_dir
from dns_host.logutil import log
from dns_host.notifyplan import plan_notifies, send_plan
from dns_host.spool import decode_job, pending
from dns_host.wireaxfr import catalog_tcp_bytes
from dns_host.zone import document_to_zone


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
        # Member metadata (SOA serial, expiry) lives in catalog.json, but
        # the catalog zone RRs are only membership PTRs plus the catalog
        # SOA/NS/version. A content update of an existing member must not
        # bump the catalog serial or NOTIFY the catalog.
        bump = _membership_changed(before, self.catalog)
        self.catalog.save(self.settings.now(), bump=bump)
        if bump:
            self._write_catalog_wire()
        messages = plan_notifies(self.settings, before, self.catalog)
        send_plan(self.notifier, messages)
        return [zone for zone, _soa in messages]

    def remove(self, apex: str, now: int) -> int | None:
        self.catalog.load()
        had = apex in self.catalog.zones
        if had:
            log("error", "removing zone from the catalog", apex=apex)
        self.catalog.zones.pop(apex, None)
        sql_serial = self.store.delete_zone(apex, now)
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
            # The API accepted this upload, so not installing it is an error.
            log(
                "error",
                "accepted zone not installed: SOA serial is not higher",
                apex=job.apex,
                serial=job.serial,
                held=held,
            )
            path.unlink(missing_ok=True)
            return False
        try:
            self._remember_sqlite(job)
        except Exception as exc:
            # Leaving the file would retry it every poll for ever.
            log("error",
                "accepted zone not installed",
                apex=job.apex,
                serial=job.serial,
                error=str(exc))
            path.unlink(missing_ok=True)
            return False
        self.catalog.zones[job.apex] = Member(
            apex=job.apex,
            serial=job.serial,
            soa=job.soa,
            ttl=job.soa_ttl,
            expires_at=job.expires_at,
            parent_zone=job.parent_zone,
        )
        path.unlink(missing_ok=True)
        log("info",
            "zone installed from spool",
            apex=job.apex,
            serial=job.serial)
        return True

    def _remember_sqlite(self, job) -> None:
        import dns.name

        zone = document_to_zone(dns.name.from_text(job.apex), job.document)
        expiries = zone.rrsig_expiries()
        if expiries:
            min_expiry, max_expiry = min(expiries), max(expiries)
        else:
            min_expiry = max_expiry = job.expires_at
        self.store.replace_zone(
            apex=job.apex,
            serial=job.serial,
            document=job.document,
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
            self.store.delete_zone(apex, now)
            log("error",
                "zone aged out",
                apex=apex,
                reason="rrsig grace elapsed")
        return True

    def _write_catalog_wire(self) -> None:
        blob = catalog_tcp_bytes(self.settings, self.catalog.serial,
                                 self.catalog.member_names())
        atomic_write_bytes(self.catalog.wire_path, blob)


def _membership_changed(before: tuple, catalog) -> bool:
    _serial, old_zones = before
    return {apex for apex, _member_serial in old_zones} != set(catalog.zones)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    temporary.write_bytes(data)
    os.replace(temporary, path)


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
