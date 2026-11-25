"""DNS UDP process: SOA answers and NOTIFY.

SOA answers for the catalog and for member zones come from the catalog file.
Zone files are not read. The catalog SOA serial is the value stored in the file.
The file is polled by mtime; NOTIFY is sent to the local NSD for the catalog
when that serial changes, and for new or updated members. At start-up, once the catalog has
loaded, the catalog alone is notified, because NSD may hold an old catalog
from before a restart. The send waits until the AXFR listener accepts a
connection: NSD transfers immediately, and a refused connection on a zone
it has never loaded waits about 20 to 40 seconds. A NOTIFY that NSD does
not acknowledge is retried with backoff.
"""

from __future__ import annotations

import socket
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dns_host.catalog import catalog_soa
from dns_host.catalogfile import Catalog
from dns_host.config import DNS_BIND, DNS_PORT
from dns_host.logutil import log
from dns_host.notify import UdpNotifier
from dns_host.notifyplan import plan_notifies

NOTIFY_RETRY_MAX_SECONDS = 60


class UdpService:

    def __init__(self, settings, notifier=None):
        self.settings = settings
        self.catalog = Catalog(settings)
        self.notifier = notifier if notifier is not None else UdpNotifier(
            settings, _NullStore())
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.port = DNS_PORT
        self._snapshot = (0, ())
        # zone -> (soa, attempts, next attempt time). Insertion order keeps
        # the catalog ahead of its members.
        self._pending: dict[str, tuple] = {}
        self._pending_lock = threading.Lock()
        self._axfr_wait_logged = False

    def start(self) -> int:
        # Load first, then bind: nothing listens until the real catalog
        # has been read, so an empty catalog can never be served.
        wait_for_catalog(self.catalog)
        self._snapshot = self.catalog.snapshot()
        # Start-up: NOTIFY the catalog only. The send waits until AXFR is
        # accepting; NSD then transfers the catalog if it is behind.
        # Members are notified when they change.
        self._queue([(self.settings.catalog_zone.to_text(),
                      catalog_soa(self.settings, self.catalog.serial))])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((DNS_BIND, DNS_PORT))
        self.port = sock.getsockname()[1]
        sock.settimeout(0.5)
        self._sock = sock
        threading.Thread(target=self._loop, name="dns-udp",
                         daemon=True).start()
        # NOTIFY has its own thread so a slow or absent NSD never delays
        # SOA answers.
        threading.Thread(target=self._notify_loop,
                         name="dns-notify",
                         daemon=True).start()
        log("info", "DNS UDP service started", port=self.port, bind=DNS_BIND)
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def serve_forever(self) -> None:
        self.start()
        while not self._stop.is_set():
            time.sleep(0.5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._refresh_and_notify()
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            wire = self._handle(data)
            if wire:
                try:
                    self._sock.sendto(wire, addr)
                except OSError:
                    pass

    def _refresh_and_notify(self) -> None:
        previous_ns = self.catalog.mtime_ns
        self.catalog.load()
        if not self.catalog.loaded:
            log("error",
                "catalog file disappeared",
                path=str(self.catalog.path))
            return
        if self.catalog.mtime_ns == previous_ns:
            return
        current = self.catalog.snapshot()
        if current != self._snapshot:
            self._queue(
                plan_notifies(self.settings, self._snapshot, self.catalog))
            self._snapshot = current

    def _notify_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush_notifies()
            except Exception as exc:
                log("error", "NOTIFY loop failed", error=repr(exc))
            self._stop.wait(0.5)

    def _queue(self, messages) -> None:
        with self._pending_lock:
            for zone, soa in messages:
                # A newer SOA for the same zone replaces the queued one.
                self._pending.pop(zone, None)
                self._pending[zone] = (soa, 0, 0.0)

    def flush_notifies(self, now: float | None = None) -> None:
        """Send due NOTIFYs. Unacknowledged ones back off up to a minute."""

        now = time.monotonic() if now is None else now
        with self._pending_lock:
            due_now = [(zone, item) for zone, item in self._pending.items()
                       if item[2] <= now]
        if not due_now:
            return
        ready = getattr(self.notifier, "master_ready", None)
        if callable(ready) and not ready():
            # Leave the NOTIFY due. Counting this as a refusal would back
            # off the send, and NSD would still be inside its own wait.
            if not self._axfr_wait_logged:
                log("warning",
                    "waiting for the AXFR listener before NOTIFY",
                    bind=DNS_BIND,
                    port=DNS_PORT)
                self._axfr_wait_logged = True
            return
        self._axfr_wait_logged = False
        for zone, (soa, attempts, _due) in due_now:
            ok = self.notifier.notify(zone,
                                      soa,
                                      attempt=attempts + 1,
                                      will_retry=True)
            with self._pending_lock:
                if self._pending.get(zone, (None, ))[0] is not soa:
                    continue  # replaced by a newer SOA meanwhile
                if ok:
                    del self._pending[zone]
                    continue
                attempts += 1
                delay = min(NOTIFY_RETRY_MAX_SECONDS, 2**attempts)
                self._pending[zone] = (soa, attempts, now + delay)

    def _handle(self, data: bytes) -> bytes | None:
        self._refresh_and_notify()
        try:
            query = dns.message.from_wire(data)
        except Exception:
            return None
        if not query.question or len(query.question) != 1:
            return _error(query, dns.rcode.FORMERR).to_wire()
        question = query.question[0]
        if int(question.rdclass) != int(dns.rdataclass.IN):
            return _error(query, dns.rcode.REFUSED).to_wire()
        if question.rdtype == dns.rdatatype.IXFR:
            return _error(query, dns.rcode.NOTIMP).to_wire()
        if question.rdtype != dns.rdatatype.SOA:
            return _error(query, dns.rcode.REFUSED).to_wire()
        soa = self._soa(question.name)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if soa is None:
            log("error",
                "SOA refused: zone not in catalog",
                apex=question.name.to_text().lower(),
                catalog_serial=self.catalog.serial)
            response.set_rcode(dns.rcode.REFUSED)
        else:
            response.answer.append(soa)
        return response.to_wire()

    def _soa(self, name: dns.name.Name):
        text = name.to_text().lower()
        if text == self.settings.catalog_zone.to_text():
            return catalog_soa(self.settings, self.catalog.serial)
        member = self.catalog.zones.get(text)
        if member is None or not member.soa:
            return None
        return dns.rrset.from_text(text,
                                   int(member.ttl) or 300, "IN", "SOA",
                                   member.soa)


def wait_for_catalog(catalog, interval: float = 0.5) -> None:
    """Block until the controller has written the catalog file."""

    logged = False
    while True:
        catalog.load()
        if catalog.loaded:
            log("info",
                "catalog loaded",
                serial=catalog.serial,
                members=len(catalog.zones))
            return
        if not logged:
            log("warning",
                "waiting for the catalog file before listening",
                path=str(catalog.path))
            logged = True
        time.sleep(interval)


class _NullStore:

    def incr(self, _name: str, _amount: int = 1) -> None:
        return None


def _error(query, rcode):
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return response


def main() -> None:
    from dns_host.config import Settings, log_effective

    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    UdpService(settings).serve_forever()


if __name__ == "__main__":
    main()
