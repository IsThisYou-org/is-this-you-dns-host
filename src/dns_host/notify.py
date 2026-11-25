"""NOTIFY (RFC 1996) to the local NSD.

Failures are logged at error level and retried by the UDP service. They do
not fail an upload that has already been stored.
"""

from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.opcode
import dns.rcode
import dns.rdatatype

from dns_host.config import NSD_PORT
from dns_host.logutil import log

# NSD's allow-notify is 127.0.0.1 NOKEY. Fixed, not configuration.
NSD_NOTIFY_HOST = "127.0.0.1"
NOTIFY_TIMEOUT_SECONDS = 1


class Notifier:

    def notify(self, zone: str, soa) -> bool:
        raise NotImplementedError


class RecordingNotifier(Notifier):

    def __init__(self):
        self.zones: list[str] = []

    def notify(self, zone: str, soa) -> bool:
        self.zones.append(zone)
        return True


class UdpNotifier(Notifier):
    """NOTIFY the local NSD, which then NOTIFYs the secondaries itself.

    NSD's ``allow-notify`` is ``127.0.0.1 NOKEY``, so the message goes to
    127.0.0.1 port 53 from 127.0.0.1. The secondaries are not notified from
    here: they transfer from NSD, and NSD sends their NOTIFY (with TSIG)
    once it has loaded the new serial.
    """

    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self.target = (NSD_NOTIFY_HOST, NSD_PORT)

    def notify(self, zone: str, soa) -> bool:
        """Send one NOTIFY. True when NSD answered NOERROR."""

        query = dns.message.make_query(zone, dns.rdatatype.SOA)
        query.set_opcode(dns.opcode.NOTIFY)
        query.flags |= dns.flags.AA
        if soa is not None:
            query.answer.append(soa)
        serial = _serial(soa)
        host, port = self.target
        try:
            response = dns.query.udp(query,
                                     host,
                                     port=port,
                                     source=NSD_NOTIFY_HOST,
                                     timeout=NOTIFY_TIMEOUT_SECONDS)
        except Exception as exc:
            self.store.incr("notify_fail")
            log("error",
                "NOTIFY failed",
                apex=zone,
                serial=serial,
                target=f"{host}@{port}",
                error=repr(exc))
            return False
        rcode = dns.rcode.to_text(response.rcode())
        if response.rcode() != dns.rcode.NOERROR:
            self.store.incr("notify_fail")
            log("error",
                "NOTIFY rejected",
                apex=zone,
                serial=serial,
                target=f"{host}@{port}",
                rcode=rcode)
            return False
        self.store.incr("notify_ok")
        log("info",
            "NOTIFY sent",
            apex=zone,
            serial=serial,
            target=f"{host}@{port}",
            rcode=rcode)
        return True


def _serial(soa) -> int | None:
    try:
        return int(next(iter(soa)).serial)
    except Exception:
        return None
