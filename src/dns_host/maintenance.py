"""Retention: RRSIG expiry and parent DS/NS drift share one grace period.

A failed parent re-check starts the grace clock and keeps the last stored
zone. Restoring a matching DS clears it. A resolver outage (503) does not
move the clock. When the grace period ends the zone is removed from the
catalog and secondaries are notified of the catalog change only.
"""

from __future__ import annotations

import threading

from dns_host.catalog import catalog_soa
from dns_host.chain import _keys_matching_ds, authenticate_parent
from dns_host.config import GUNICORN_BIND, data_dir
from dns_host.doh import DohClient
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.names import normalise_name
from dns_host.notify import UdpNotifier
from dns_host.zone import document_to_zone


class Maintenance:

    def __init__(self, settings, store, lookup=None, notifier=None):
        self.settings = settings
        self.store = store
        self.lookup = lookup or DohClient(settings.resolver_base_url,
                                          settings.doh_timeout_seconds)
        self.notifier = notifier or UdpNotifier(settings, store)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop,
                                        name="maintenance",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                log("error", "maintenance failed", error=str(exc))
            self._stop.wait(self.settings.maintenance_interval_seconds)

    def run_once(self) -> None:
        if not self._lock.acquire(blocking=False):
            return
        try:
            now = self.settings.now()
            for row in self.store.list_zones():
                if now > row.rrsig_max_expiry + self.settings.grace_seconds:
                    self._drop(row.apex, now, "rrsig grace elapsed")
                    continue
                self._recheck_parent(row, now)
        finally:
            self._lock.release()

    def _recheck_parent(self, row, now: int) -> None:
        try:
            apex = normalise_name(row.apex)
            zone = _zone_from_disk(row.apex)
            if zone is None:
                log("warning", "zone file missing", apex=row.apex)
                return
            delegation = authenticate_parent(self.lookup, self.settings, apex)
            if _delegation_matches(zone, delegation, self.settings):
                if row.parent_drift_since is not None or not row.parent_ok:
                    log("info", "parent match restored", apex=row.apex)
                self.store.set_parent_state(row.apex,
                                            now=now,
                                            ok=True,
                                            drift_since=None)
                return
            self._note_drift(row, now, "parent DS or NS no longer matches")
        except ApiError as exc:
            if exc.status == 503 or exc.error == "parent_lookup_unavailable":
                log("warning",
                    "parent recheck unavailable",
                    apex=row.apex,
                    error=exc.error,
                    message=exc.message)
                return
            self._note_drift(row, now, exc.error)

    def _note_drift(self, row, now: int, reason: str) -> None:
        since = row.parent_drift_since if row.parent_drift_since is not None else now
        self.store.set_parent_state(row.apex,
                                    now=now,
                                    ok=False,
                                    drift_since=since)
        log("warning",
            "parent drift",
            apex=row.apex,
            reason=reason,
            since=since)
        if now > since + self.settings.grace_seconds:
            self._drop(row.apex, now, "parent drift grace elapsed")

    def _drop(self, apex: str, now: int, reason: str) -> None:
        from dns_host.controller import Controller

        serial = Controller(self.settings, self.store).remove(apex, now)
        if serial is None:
            return
        self.store.incr("zones_dropped")
        log("error",
            "zone dropped",
            apex=apex,
            reason=reason,
            catalog_serial=serial)
        try:
            self.notifier.notify(self.settings.catalog_zone.to_text(),
                                 catalog_soa(self.settings, serial))
        except Exception as exc:
            log("warning",
                "catalog NOTIFY after drop failed",
                apex=apex,
                error=str(exc))


def _zone_from_disk(apex: str):
    from dns_host.zonesync import read_member

    document = read_member(data_dir() / "zones", apex)
    if document is None:
        return None
    return document_to_zone(normalise_name(apex), document)


def _delegation_matches(zone, delegation, settings) -> bool:
    parent_ns = {name.canonicalize() for name in delegation.ns_names}
    apex_ns = {name.canonicalize() for name in zone.apex_ns_names()}
    service = {name.canonicalize() for name in settings.service_ns}
    if not service <= parent_ns or parent_ns != apex_ns:
        return False
    if delegation.proved_ds_absent or delegation.ds_rrset is None or len(
            delegation.ds_rrset) == 0:
        return False
    matched = _keys_matching_ds(zone.apex, zone.get(dns_dnskey()),
                                list(delegation.ds_rrset),
                                settings.ds_digest_types)
    return bool(matched)


def dns_dnskey():
    import dns.rdatatype

    return dns.rdatatype.DNSKEY


class RemoteMaintenance:
    """90-day clear-out running on the DNS side.

    Decisions are made here. Deletes and parent-state updates are POSTed to
    the API, which is the only writer of zone files and the catalogue.
    """

    def __init__(self, settings, lookup=None):
        from dns_host.doh import DohClient

        self.settings = settings
        self.lookup = lookup or DohClient(settings.resolver_base_url,
                                          settings.doh_timeout_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop,
                                        name="maintenance",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                log("error", "maintenance failed", error=str(exc))
            self._stop.wait(self.settings.maintenance_interval_seconds)

    def run_once(self) -> None:
        meta = _api("GET", "/int/zones/meta")
        now = self.settings.now()
        for row in meta.get("zones", []):
            if now > int(
                    row["rrsig_max_expiry"]) + self.settings.grace_seconds:
                _api(
                    "POST",
                    "/int/zones/drop",
                    {
                        "apexes": [row["apex"]],
                        "reason": "rrsig grace elapsed"
                    },
                )
                continue
            self._recheck(row, now)

    def _recheck(self, row, now: int) -> None:
        import json

        from dns_host.chain import authenticate_parent
        from dns_host.names import normalise_name
        from dns_host.shard import locate_zone_file
        from dns_host.zone import document_to_zone
        from dns_host.zonesync import zone_filename

        path = locate_zone_file(data_dir() / "zones", row["apex"],
                                zone_filename(row["apex"]))
        if path is None:
            return
        document = json.loads(path.read_text(encoding="utf-8"))
        apex = normalise_name(row["apex"])
        zone = document_to_zone(apex, document)
        try:
            delegation = authenticate_parent(self.lookup, self.settings, apex)
        except ApiError as exc:
            if exc.status == 503 or exc.error == "parent_lookup_unavailable":
                log("warning",
                    "parent recheck unavailable",
                    apex=row["apex"],
                    error=exc.error)
                return
            self._drift(row, now, exc.error)
            return
        if _delegation_matches(zone, delegation, self.settings):
            _api(
                "POST",
                "/int/zones/parent-state",
                {
                    "apex": row["apex"],
                    "ok": True,
                    "drift_since": None
                },
            )
            return
        self._drift(row, now, "parent DS or NS no longer matches")

    def _drift(self, row, now: int, reason: str) -> None:
        since = row["parent_drift_since"] if row.get(
            "parent_drift_since") is not None else now
        _api(
            "POST",
            "/int/zones/parent-state",
            {
                "apex": row["apex"],
                "ok": False,
                "drift_since": since
            },
        )
        log("warning",
            "parent drift",
            apex=row["apex"],
            reason=reason,
            since=since)
        if now > int(since) + self.settings.grace_seconds:
            _api(
                "POST",
                "/int/zones/drop",
                {
                    "apexes": [row["apex"]],
                    "reason": "parent drift grace elapsed"
                },
            )


def _api(method: str, path: str, payload: dict | None = None):
    import json
    import urllib.request

    url = "http://" + GUNICORN_BIND + path
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))
