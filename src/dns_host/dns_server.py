"""In-process UDP and AXFR listeners for tests.

Production runs ``udp_service`` and ``axfr_service`` as separate processes.
This facade binds both to 127.0.0.1 port 5353 so the AXFR tests can talk to
the catalog and the pre-built zone wire.
"""

from __future__ import annotations

import threading

from dns_host.axfr_service import bind_listener, run_child
from dns_host.config import DNS_PORT
from dns_host.udp_service import UdpService


class DnsServer:

    def __init__(self, settings, store=None):
        self.settings = settings
        self.store = store
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._tcp = None
        self.udp: UdpService | None = None
        self.port = DNS_PORT

    def start(self) -> int:
        self._tcp = bind_listener(self.settings)
        self.port = self._tcp.getsockname()[1]
        self.udp = UdpService(self.settings)
        self.udp.start()
        self._thread = threading.Thread(target=run_child,
                                        args=(self._tcp, self.settings,
                                              self._stop),
                                        name="dns-axfr",
                                        daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self.udp is not None:
            self.udp.stop()
        if self._tcp is not None:
            try:
                self._tcp.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)


def main() -> None:
    from dns_host.udp_service import main as udp_main

    udp_main()


if __name__ == "__main__":
    main()
