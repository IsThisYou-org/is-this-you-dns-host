"""DNS TCP AXFR process.

The listening socket is bound to 127.0.0.1 port 5353 and is non-blocking.
Localhost AXFR is always accepted. A parent forks the configured number of
children (default 5). Each child ``select``s the listening socket and then
``accept``s; a failed accept means a sibling took the connection, and the
child loops. Dead children are replaced.

User-zone AXFR is built from the stored JSON file on each transfer. The
catalog AXFR is the RFC 9432 payload written by the controller. Children
reload the catalog when its mtime changes so the list of valid zones stays
current. There is no wire cache.
"""

from __future__ import annotations

import os
import select
import socket
import threading

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from dns_host.catalogfile import Catalog
from dns_host.config import DNS_BIND, DNS_PORT, data_dir
from dns_host.logutil import log
from dns_host.wireaxfr import with_query_id


class CatalogView:
    """Valid zone names, refreshed when the catalog file changes."""

    def __init__(self, settings):
        self.settings = settings
        self.catalog = Catalog(settings)
        self._mtime_ns = None
        self.zones: set[str] = set()
        self.refresh()

    def refresh(self) -> bool:
        path = self.catalog.path
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return False
        if mtime_ns == self._mtime_ns:
            return False
        self.catalog.load()
        self.zones = set(self.catalog.zones)
        self.zones.add(self.settings.catalog_zone.to_text())
        self._mtime_ns = self.catalog.mtime_ns
        return True

    def wire_for(self, apex: str) -> bytes | None:
        if apex == self.settings.catalog_zone.to_text():
            from dns_host.wireaxfr import catalog_tcp_bytes

            return catalog_tcp_bytes(self.settings, self.catalog.serial,
                                     self.catalog.member_names())
        from dns_host.wireaxfr import tcp_bytes
        from dns_host.zone import document_to_zone
        from dns_host.zonesync import read_member

        import dns.name

        document = read_member(data_dir() / "zones", apex)
        if document is None:
            return None
        zone = document_to_zone(dns.name.from_text(apex), document)
        return tcp_bytes(zone.axfr_rrsets())


def bind_listener(settings) -> socket.socket:
    """Bind the fixed internal listener. ``settings`` is accepted for callers."""

    del settings
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DNS_BIND, DNS_PORT))
    sock.listen(64)
    sock.setblocking(False)
    return sock


def run_child(sock: socket.socket,
              settings,
              stop: threading.Event | None = None) -> None:
    view = CatalogView(settings)
    while stop is None or not stop.is_set():
        view.refresh()
        readable, _, _ = select.select([sock], [], [], 0.5)
        if not readable:
            continue
        try:
            conn, _addr = sock.accept()
        except BlockingIOError:
            continue
        except OSError:
            continue
        try:
            handle_connection(conn, view, settings)
        except Exception as exc:
            log("error", "AXFR connection failed", error=repr(exc))
        finally:
            try:
                conn.close()
            except OSError:
                pass


def handle_connection(conn: socket.socket, view: CatalogView,
                      settings) -> None:
    conn.settimeout(10)
    header = _read_exact(conn, 2)
    if header is None:
        return
    length = int.from_bytes(header, "big")
    data = _read_exact(conn, length)
    if data is None:
        return
    try:
        query = dns.message.from_wire(data)
    except Exception:
        return
    if not query.question or len(query.question) != 1:
        _send(conn, _error(query, dns.rcode.FORMERR))
        return
    question = query.question[0]
    if int(question.rdclass) != int(dns.rdataclass.IN):
        _send(conn, _error(query, dns.rcode.REFUSED))
        return
    if question.rdtype == dns.rdatatype.IXFR:
        _send(conn, _error(query, dns.rcode.NOTIMP))
        return
    if question.rdtype != dns.rdatatype.AXFR:
        _send(conn, _error(query, dns.rcode.REFUSED))
        return
    view.refresh()
    apex = question.name.to_text().lower()
    if apex not in view.zones:
        log("error",
            "AXFR refused: zone not in catalog",
            apex=apex,
            catalog_serial=view.catalog.serial)
        _send(conn, _error(query, dns.rcode.REFUSED))
        return
    try:
        blob = view.wire_for(apex)
    except Exception as exc:
        log("error", "AXFR build failed", apex=apex, error=repr(exc))
        _send(conn, _error(query, dns.rcode.SERVFAIL))
        return
    if not blob:
        log("error", "AXFR refused: zone file missing or empty", apex=apex)
        _send(conn, _error(query, dns.rcode.REFUSED))
        return
    conn.sendall(with_query_id(blob, query.id))


def supervise_once(pids: set[int], dead: int, spawn) -> set[int]:
    """Drop a dead child and fork a replacement. Used by the parent loop and tests."""

    pids = set(pids)
    pids.discard(dead)
    pids.add(int(spawn()))
    return pids


def prefork(settings, sock: socket.socket | None = None) -> None:
    own_socket = sock is None
    if sock is None:
        sock = bind_listener(settings)
    children = max(1, int(getattr(settings, "axfr_children", 5) or 5))
    log("info",
        "DNS AXFR service started",
        port=sock.getsockname()[1],
        children=children)

    def spawn() -> int:
        pid = os.fork()
        if pid == 0:
            try:
                run_child(sock, settings)
            finally:
                os._exit(0)
        return pid

    pids: set[int] = set()
    for _ in range(children):
        pids.add(spawn())
    while True:
        try:
            pid, _status = os.wait()
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        if not own_socket and pid not in pids:
            continue
        log("warning", "AXFR child exited", pid=pid)
        pids = supervise_once(pids, pid, spawn)


def _send(conn: socket.socket, message: dns.message.Message) -> None:
    wire = message.to_wire()
    conn.sendall(len(wire).to_bytes(2, "big") + wire)


def _error(query, rcode) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return response


def _read_exact(conn: socket.socket, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        try:
            chunk = conn.recv(count - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def main() -> None:
    import argparse

    from dns_host.config import Settings, log_effective

    parser = argparse.ArgumentParser(description="Local TCP AXFR service")
    parser.add_argument("--config", default="", help="Path to config.yaml")
    args = parser.parse_args()
    settings = Settings.load(args.config or None)
    settings.require_service_ns()
    log_effective(settings)
    from dns_host.shard import migrate_flat_zone_files

    migrate_flat_zone_files(data_dir() / "zones")
    prefork(settings)


if __name__ == "__main__":
    main()
