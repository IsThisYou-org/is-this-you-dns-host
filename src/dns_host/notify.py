"""NOTIFY (RFC 1996) to the local NSD.

A failed attempt that will be retried is logged at info, with the attempt
number. When that NOTIFY will not be tried again, one warning is logged.
A failure does not fail an upload that has already been stored.
"""

from __future__ import annotations

import socket

import dns.flags
import dns.message
import dns.query
import dns.opcode
import dns.rcode
import dns.rdatatype

from dns_host.config import DNS_BIND, DNS_PORT, NSD_PORT
from dns_host.logutil import log

# NSD's allow-notify is 127.0.0.1 NOKEY. Fixed, not configuration.
NSD_NOTIFY_HOST = "127.0.0.1"
NOTIFY_TIMEOUT_SECONDS = 1


class Notifier:

    def notify(self,
               zone: str,
               soa,
               *,
               attempt: int = 1,
               will_retry: bool = False) -> bool:
        raise NotImplementedError

    def master_ready(self) -> bool:
        """True when a NOTIFY can be sent without a refused transfer."""

        return True


class RecordingNotifier(Notifier):

    def __init__(self):
        self.zones: list[str] = []

    def notify(self,
               zone: str,
               soa,
               *,
               attempt: int = 1,
               will_retry: bool = False) -> bool:
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

    def master_ready(self) -> bool:
        """The AXFR listener must accept before NSD is told to transfer.

        NSD connects as soon as it accepts the NOTIFY. A refused connection
        on a zone it has never loaded is not tried again for about 20 to 40
        seconds, so the NOTIFY stays queued until this port accepts. A
        NOTIFY sent then starts the transfer at once.
        """

        return axfr_listener_open()

    def notify(self,
               zone: str,
               soa,
               *,
               attempt: int = 1,
               will_retry: bool = False) -> bool:
        """Send one NOTIFY. True when NSD answered NOERROR.

        ``attempt`` is the 1-based try. When ``will_retry`` is true, a
        failure is logged at info because another try will follow. When it
        is false, the retries are finished and the failure is one warning.
        """

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
            self._log_failure(zone, serial, f"{host}@{port}", exc, attempt,
                              will_retry)
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

    def _log_failure(self, zone: str, serial, target: str, exc: Exception,
                     attempt: int, will_retry: bool) -> None:
        """Log one failed send. A retry stays at info; the last try warns."""

        if will_retry:
            log("info",
                "NOTIFY failed",
                apex=zone,
                serial=serial,
                target=target,
                error=repr(exc),
                attempt=attempt)
            return
        log("warning",
            "NOTIFY failed",
            apex=zone,
            serial=serial,
            target=target,
            attempts=attempt,
            error=repr(exc))


def axfr_listener_open(timeout: float = 0.2) -> bool:
    """True when ``127.0.0.1:5353`` accepts a TCP connection."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((DNS_BIND, DNS_PORT))
    except OSError:
        return False
    else:
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _serial(soa) -> int | None:
    try:
        return int(next(iter(soa)).serial)
    except Exception:
        return None
