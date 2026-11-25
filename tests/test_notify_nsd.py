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

    def notify(self, zone, soa, **_extra):
        self.sent.append((zone, int(next(iter(soa)).serial)))
        return self.ok


def _member(apex, serial):
    return Member(apex=apex,
                  serial=serial,
                  soa=f"ns1.svc.test. hostmaster.svc.test. {serial} 1 1 1 1",
                  ttl=300,
                  expires_at=0)


def _write_catalog(settings, members, now, bump=True):
    catalog = Catalog(settings)
    catalog.load()
    catalog.zones = {m.apex: m for m in members}
    catalog.save(now, bump=bump)
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


def test_member_update_notifies_only_the_member(settings, clock):
    first = _write_catalog(settings, [_member("a.example.", 7)], clock.t)
    recorder = Recorder()
    service = _service(settings, recorder)
    clock.t += 1
    after = _write_catalog(settings, [_member("a.example.", 8)],
                           clock.t,
                           bump=False)
    service._refresh_and_notify()
    service.flush_notifies(now=0)
    assert after.serial == first.serial
    assert recorder.sent == [("a.example.", 8)]


def test_every_catalog_serial_change_is_notified(settings, clock):
    _write_catalog(settings, [], clock.t)
    recorder = Recorder()
    service = _service(settings, recorder)
    serials = []
    for step in range(3):
        clock.t += 1
        serials.append(
            _write_catalog(settings, [_member(f"z{step}.example.", 10)],
                           clock.t).serial)
        service._refresh_and_notify()
        service.flush_notifies(now=0)
    catalog_sent = [
        s for z, s in recorder.sent if z == settings.catalog_zone.to_text()
    ]
    assert catalog_sent == serials


def test_notify_is_held_until_the_axfr_listener_accepts(
        settings, clock, syslog_lines):
    """A closed AXFR port leaves the NOTIFY due. It is not a failed send."""

    _write_catalog(settings, [], clock.t)
    sent = []

    class Holding(Recorder):

        def master_ready(self):
            return self.ok

        def notify(self, zone, soa, **_extra):
            sent.append((zone, int(next(iter(soa)).serial)))
            return True

    holder = Holding(ok=False)
    service = _service(settings, holder)
    clock.t += 1
    after = _write_catalog(settings, [_member("a.example.", 1)], clock.t)
    service._refresh_and_notify()
    service.flush_notifies(now=10)
    assert sent == []
    catalog = settings.catalog_zone.to_text()
    soa, attempts, due = service._pending[catalog]
    assert attempts == 0
    assert due <= 10
    assert int(next(iter(soa)).serial) == after.serial
    assert "a.example." in service._pending
    lines = [json.loads(line) for line in syslog_lines]
    assert [row["msg"] for row in lines
            ] == ["waiting for the AXFR listener before NOTIFY"]
    assert lines[0]["bind"] == "127.0.0.1"
    assert lines[0]["port"] == 5353
    syslog_lines.clear()
    service.flush_notifies(now=10)
    assert sent == []
    assert syslog_lines == []
    holder.ok = True
    service.flush_notifies(now=10)
    assert sent == [(catalog, after.serial), ("a.example.", 1)]
    assert service._pending == {}


def test_axfr_listener_open_follows_the_accepting_socket():
    import socket

    from dns_host.config import DNS_BIND, DNS_PORT
    from dns_host.notify import axfr_listener_open

    assert axfr_listener_open(timeout=0.2) is False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DNS_BIND, DNS_PORT))
    sock.listen(1)
    try:
        assert axfr_listener_open(timeout=0.2) is True
    finally:
        sock.close()
    assert axfr_listener_open(timeout=0.2) is False


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


def test_notify_is_logged_and_a_final_failure_is_a_warning(
        settings, monkeypatch, syslog_lines):
    """A send that will not be retried is logged once at warning."""

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
    lines = [json.loads(line) for line in syslog_lines]
    assert [(r["level"], r["msg"]) for r in lines] == [
        ("info", "NOTIFY sent"),
        ("error", "NOTIFY rejected"),
        ("warning", "NOTIFY failed"),
    ]
    assert all(r["serial"] == 5 for r in lines)
    assert lines[0]["target"] == "127.0.0.1@53"
    assert "attempt" not in lines[0]
    failed = lines[2]
    assert failed["apex"] == "catalog.svc.test."
    assert failed["target"] == "127.0.0.1@53"
    assert failed["attempts"] == 1
    assert failed["error"] == "ConnectionRefusedError('nsd is not listening')"
    assert "attempt" not in failed


def test_notify_failure_is_warning_only_after_retries_run_out(
        settings, monkeypatch, syslog_lines):
    """The warning names the apex, serial, target, attempts and last error."""

    soa = catalog_rrsets(settings, 5, [])[0]

    def down(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("dns.query.udp", down)
    notifier = UdpNotifier(settings, Counter())
    assert notifier.notify("catalog.svc.test.",
                           soa,
                           attempt=4,
                           will_retry=False) is False
    lines = [json.loads(line) for line in syslog_lines]
    assert len(lines) == 1
    row = lines[0]
    assert row["level"] == "warning"
    assert row["msg"] == "NOTIFY failed"
    assert row["apex"] == "catalog.svc.test."
    assert row["serial"] == 5
    assert row["target"] == "127.0.0.1@53"
    assert row["attempts"] == 4
    assert row["error"] == "TimeoutError('timed out')"
    assert "attempt" not in row
    assert notifier.store.counts["notify_fail"] == 1


def test_retried_notify_failure_is_info_and_backoff_is_unchanged(
        settings, monkeypatch, syslog_lines):
    """Each try that will be sent again is info, with the same backoff."""

    monkeypatch.setattr(UdpNotifier, "master_ready", lambda self: True)

    def down(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("dns.query.udp", down)
    store = Counter()
    notifier = UdpNotifier(settings, store)
    service = UdpService(settings, notifier=notifier)
    zone = "catalog.svc.test."
    soa = catalog_rrsets(settings, 5, [])[0]
    service._queue([(zone, soa)])

    now = 0.0
    dues = []
    for _ in range(6):
        service.flush_notifies(now=now)
        _soa, attempts, due = service._pending[zone]
        dues.append((attempts, due))
        now = due
    assert dues == [(1, 2), (2, 6), (3, 14), (4, 30), (5, 62), (6, 122)]
    lines = [json.loads(line) for line in syslog_lines]
    assert len(lines) == 6
    for number, row in enumerate(lines, start=1):
        assert row["level"] == "info"
        assert row["msg"] == "NOTIFY failed"
        assert row["apex"] == zone
        assert row["serial"] == 5
        assert row["target"] == "127.0.0.1@53"
        assert row["error"] == "TimeoutError('timed out')"
        assert row["attempt"] == number
        assert "attempts" not in row
    assert store.counts["notify_fail"] == 6
    syslog_lines.clear()
    service.flush_notifies(now=dues[-1][1] - 1)
    assert syslog_lines == []

    def answered(query, host, port=53, source=None, timeout=1):
        return dns.message.make_response(query)

    monkeypatch.setattr("dns.query.udp", answered)
    service.flush_notifies(now=122)
    assert service._pending == {}
    sent = [json.loads(line) for line in syslog_lines]
    assert [(row["level"], row["msg"])
            for row in sent] == [("info", "NOTIFY sent")]
    assert sent[0]["serial"] == 5
    assert sent[0]["target"] == "127.0.0.1@53"
    assert "attempt" not in sent[0]
    assert store.counts["notify_ok"] == 1


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
