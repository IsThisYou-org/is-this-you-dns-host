"""NOTIFY to the local NSD: every catalog change, start-up, retry, logging."""

import json

import dns.message
import dns.opcode
import dns.rcode

from dns_host.catalog import catalog_rrsets
from dns_host.catalogfile import Catalog, Member
from dns_host.notify import UdpNotifier
from dns_host.udp_service import UdpService


class Counter:

    def __init__(self):
        self.counts = {}

    def incr(self, key, amount=1):
        self.counts[key] = self.counts.get(key, 0) + amount


class Recorder:

    def __init__(self, ok=True):
        self.ok = ok
        self.sent = []

    def notify(self, zone, soa):
        self.sent.append((zone, int(next(iter(soa)).serial)))
        return self.ok


def _member(apex, serial):
    return Member(apex=apex,
                  serial=serial,
                  soa=f"ns1.svc.test. hostmaster.svc.test. {serial} 1 1 1 1",
                  ttl=300,
                  expires_at=0)


def _write_catalog(settings, members, now):
    catalog = Catalog(settings)
    catalog.load()
    catalog.zones = {m.apex: m for m in members}
    catalog.save(now)
    return catalog


def _service(settings, notifier):
    service = UdpService(settings, notifier=notifier)
    service.catalog.load()
    service._snapshot = service.catalog.snapshot()
    return service


def test_start_notifies_the_catalog_only_even_when_unchanged(settings, clock):
    catalog = _write_catalog(settings, [_member("a.example.", 7)], clock.t)
    recorder = Recorder()
    service = UdpService(settings, notifier=recorder)
    service.start()
    try:
        service.flush_notifies(now=1e12)
    finally:
        service.stop()
    assert recorder.sent == [(settings.catalog_zone.to_text(), catalog.serial)]


def test_member_update_notifies_catalog_and_member(settings, clock):
    _write_catalog(settings, [_member("a.example.", 7)], clock.t)
    recorder = Recorder()
    service = _service(settings, recorder)
    clock.t += 1
    after = _write_catalog(settings, [_member("a.example.", 8)], clock.t)
    service._refresh_and_notify()
    service.flush_notifies(now=0)
    assert recorder.sent == [(settings.catalog_zone.to_text(), after.serial),
                             ("a.example.", 8)]


def test_every_catalog_serial_change_is_notified(settings, clock):
    _write_catalog(settings, [], clock.t)
    recorder = Recorder()
    service = _service(settings, recorder)
    serials = []
    for step in range(3):
        clock.t += 1
        serials.append(
            _write_catalog(settings, [_member("a.example.", 10 + step)],
                           clock.t).serial)
        service._refresh_and_notify()
        service.flush_notifies(now=0)
    catalog_sent = [
        s for z, s in recorder.sent if z == settings.catalog_zone.to_text()
    ]
    assert catalog_sent == serials


def test_unacknowledged_notify_is_retried_with_backoff(settings, clock):
    _write_catalog(settings, [], clock.t)
    recorder = Recorder(ok=False)
    service = _service(settings, recorder)
    clock.t += 1
    _write_catalog(settings, [_member("a.example.", 1)], clock.t)
    service._refresh_and_notify()
    service.flush_notifies(now=0)
    first = len(recorder.sent)
    assert first == 2
    service.flush_notifies(now=0)  # not due yet
    assert len(recorder.sent) == first
    recorder.ok = True
    service.flush_notifies(now=1e12)
    assert len(recorder.sent) == first + 2
    service.flush_notifies(now=2e12)
    assert len(recorder.sent) == first + 2
    assert service._pending == {}


def test_notify_is_logged_and_failure_is_error(settings, monkeypatch, capsys):
    soa = catalog_rrsets(settings, 5, [])[0]

    def answered(query, host, port=53, source=None, timeout=1):
        assert query.opcode() == dns.opcode.NOTIFY
        return dns.message.make_response(query)

    monkeypatch.setattr("dns.query.udp", answered)
    notifier = UdpNotifier(settings, Counter())
    assert notifier.notify("catalog.svc.test.", soa) is True

    def refused(query, host, port=53, source=None, timeout=1):
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response

    monkeypatch.setattr("dns.query.udp", refused)
    assert notifier.notify("catalog.svc.test.", soa) is False

    def down(*_args, **_kwargs):
        raise ConnectionRefusedError("nsd is not listening")

    monkeypatch.setattr("dns.query.udp", down)
    assert notifier.notify("catalog.svc.test.", soa) is False
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(r["level"], r["msg"]) for r in lines] == [
        ("info", "NOTIFY sent"),
        ("error", "NOTIFY rejected"),
        ("error", "NOTIFY failed"),
    ]
    assert all(r["serial"] == 5 for r in lines)
    assert lines[0]["target"] == "127.0.0.1@53"


def test_catalog_soa_refresh_and_retry_are_60(settings):
    soa = next(iter(catalog_rrsets(settings, 1, [])[0]))
    assert soa.refresh == 60
    assert soa.retry == 60


def test_udp_does_not_bind_before_catalog_loads(settings, clock):
    import threading

    import dns.query

    recorder = Recorder()
    service = UdpService(settings, notifier=recorder)
    ports = []
    thread = threading.Thread(target=lambda: ports.append(service.start()),
                              daemon=True)
    thread.start()
    try:
        thread.join(0.5)
        assert thread.is_alive()
        assert service._sock is None
        catalog = _write_catalog(settings, [_member("a.example.", 3)], clock.t)
        thread.join(3)
        assert ports
        query = dns.message.make_query("a.example.", "SOA")
        answer = dns.query.udp(query, "127.0.0.1", port=ports[0], timeout=2)
        assert answer.rcode() == dns.rcode.NOERROR
        service.flush_notifies(now=0)
        assert recorder.sent == [(settings.catalog_zone.to_text(),
                                  catalog.serial)]
    finally:
        service.stop()


def test_axfr_does_not_listen_before_catalog_loads(settings, clock):
    import threading

    from dns_host.axfr_service import bind_listener

    socks = []
    thread = threading.Thread(
        target=lambda: socks.append(bind_listener(settings)), daemon=True)
    thread.start()
    try:
        thread.join(0.5)
        assert thread.is_alive()
        assert socks == []
        _write_catalog(settings, [], clock.t)
        thread.join(3)
        assert len(socks) == 1
        assert socks[0].getsockname()[1] > 0
    finally:
        for sock in socks:
            sock.close()


def test_wait_for_catalog_blocks_until_the_file_exists(settings, clock):
    import threading

    from dns_host.udp_service import wait_for_catalog

    catalog = Catalog(settings)
    done = threading.Event()

    def waiter():
        wait_for_catalog(catalog, interval=0.05)
        done.set()

    thread = threading.Thread(target=waiter, daemon=True)
    thread.start()
    assert not done.wait(0.3)
    _write_catalog(settings, [], clock.t)
    assert done.wait(2)
    assert catalog.loaded
