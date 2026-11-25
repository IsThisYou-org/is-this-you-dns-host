"""DNS UDP process: SOA answers and NOTIFY.

SOA answers for the catalog and for member zones come from the catalog file.
Zone files are not read. The catalog SOA serial is the catalog file's mtime.
The file is polled; NOTIFY is sent for the catalog and for new or updated
members when it changes.
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
from dns_host.notifyplan import plan_notifies, send_plan


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

    def start(self) -> int:
        self.catalog.load()
        self._snapshot = self.catalog.snapshot()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((DNS_BIND, DNS_PORT))
        self.port = sock.getsockname()[1]
        sock.settimeout(0.5)
        self._sock = sock
        threading.Thread(target=self._loop, name="dns-udp",
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
        if self.catalog.mtime_ns == previous_ns:
            return
        current = self.catalog.snapshot()
        if current != self._snapshot:
            send_plan(
                self.notifier,
                plan_notifies(self.settings, self._snapshot, self.catalog))
            self._snapshot = current

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
