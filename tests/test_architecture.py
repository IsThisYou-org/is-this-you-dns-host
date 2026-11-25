"""Spool handoff, catalog serial, and TCP refresh of the valid-zone list."""

import json
import os
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from dns_host.axfr_service import supervise_once
from dns_host.catalogfile import Catalog, Member, next_catalog_serial
from dns_host.controller import Controller
from dns_host.dns_server import DnsServer
from dns_host.notify import RecordingNotifier
from dns_host.dnskey_cache import get_process_cache
from dns_host.spool import pending, submit
from tests.conftest import post
from tests.test_axfr_grace import _records, _xfr


def test_catalog_serial_is_max_of_now_and_last_plus_one_and_is_the_mtime(
        tmp_path, monkeypatch):
    settings = _settings(tmp_path, now=100, monkeypatch=monkeypatch)
    catalog = Catalog(settings)
    catalog.serial = 5000
    catalog.save(100)
    assert catalog.serial == 5001
    assert next_catalog_serial(5000, 100) == 5001
    assert int(catalog.path.stat().st_mtime) == 5001
    catalog.save(9000)
    assert catalog.serial == 9000
    assert int(catalog.path.stat().st_mtime) == 9000


def test_catalog_save_without_bump_keeps_serial_and_rewrites_the_file(
        tmp_path, monkeypatch):
    settings = _settings(tmp_path, now=100, monkeypatch=monkeypatch)
    catalog = Catalog(settings)
    catalog.serial = 5000
    catalog.save(100)
    assert catalog.serial == 5001
    bumped_mtime = catalog.path.stat().st_mtime_ns
    catalog.zones["a.example."] = _member("a.example.", 2)
    catalog.save(9000, bump=False)
    assert catalog.serial == 5001
    assert catalog.mtime_ns != bumped_mtime
    reader = Catalog(settings)
    reader.load()
    assert reader.serial == 5001
    assert reader.serial_of("a.example.") == 2
    assert reader.mtime_ns == catalog.mtime_ns
    # The rewrite must change mtime so watchers reload, without bumping serial.
    assert int(catalog.path.stat().st_mtime) != 5001


def test_existing_member_update_does_not_bump_or_notify_the_catalog(
        tmp_path, monkeypatch):
    clock = {"t": 1_700_000_000}
    settings = _settings(tmp_path,
                         now=clock["t"],
                         monkeypatch=monkeypatch,
                         clock=clock)
    store = _store(settings)
    notifier = RecordingNotifier()
    controller = Controller(settings, store, notifier=notifier)
    spool = Path(settings.db_path).parent / "spool"
    spool.mkdir(parents=True)
    far = clock["t"] + 365 * 86400
    submit(spool, _job(apex="user.example.", serial=10, expires_at=far))
    controller.run_once()
    catalog = Catalog(settings)
    catalog.load()
    first_serial = catalog.serial
    first_wire = catalog.wire_path.read_bytes()
    assert catalog.serial_of("user.example.") == 10
    assert notifier.zones == [settings.catalog_zone.to_text(), "user.example."]
    notifier.zones.clear()
    clock["t"] += 10
    submit(spool, _job(apex="user.example.", serial=11, expires_at=far))
    notified = controller.run_once()
    catalog.load()
    assert catalog.serial == first_serial
    assert catalog.serial_of("user.example.") == 11
    assert catalog.wire_path.read_bytes() == first_wire
    assert notifier.zones == ["user.example."]
    assert notified == ["user.example."]


def test_member_add_and_age_out_bump_and_notify_the_catalog(
        tmp_path, monkeypatch):
    clock = {"t": 1_700_000_000}
    settings = _settings(tmp_path,
                         now=clock["t"],
                         monkeypatch=monkeypatch,
                         clock=clock)
    store = _store(settings)
    notifier = RecordingNotifier()
    controller = Controller(settings, store, notifier=notifier)
    spool = Path(settings.db_path).parent / "spool"
    spool.mkdir(parents=True)
    expires_at = clock["t"] + 10
    submit(spool, _job(apex="user.example.", serial=10, expires_at=expires_at))
    controller.run_once()
    catalog = Catalog(settings)
    catalog.load()
    first_serial = catalog.serial
    assert notifier.zones == [settings.catalog_zone.to_text(), "user.example."]
    notifier.zones.clear()
    clock["t"] = expires_at + settings.grace_seconds + 5
    notified = controller.run_once()
    catalog.load()
    assert catalog.serial == next_catalog_serial(first_serial, clock["t"])
    assert catalog.zones == {}
    assert notifier.zones == [settings.catalog_zone.to_text()]
    assert notified == [settings.catalog_zone.to_text()]


def test_controller_ignores_empty_dirs_and_hidden_files_and_rechecks_serial(
        tmp_path, monkeypatch):
    settings = _settings(tmp_path, now=1_700_000_000, monkeypatch=monkeypatch)
    store = _store(settings)
    controller = Controller(settings, store)
    spool = Path(settings.db_path).parent / "spool"
    spool.mkdir(parents=True)
    (spool / "tmp").mkdir()
    (spool / "empty").write_bytes(b"")
    (spool / ".hidden").write_bytes(b"not a job")
    (spool / "subdir").mkdir()
    far = 1_700_000_000 + 365 * 86400
    stale = _job(apex="user.example.", serial=10, expires_at=far)
    older = submit(spool, stale)
    os.utime(older, (1_700_000_000, 1_700_000_000))
    newer = submit(spool, _job(apex="user.example.", serial=11,
                               expires_at=far))
    os.utime(newer, (1_700_000_100, 1_700_000_100))
    # A lower serial after a higher one must be dropped, not installed.
    low = submit(spool, _job(apex="user.example.", serial=9, expires_at=far))
    os.utime(low, (1_700_000_050, 1_700_000_050))
    assert [item.name
            for item in pending(spool)] == [older.name, low.name, newer.name]
    controller.run_once()
    catalog = Catalog(settings)
    catalog.load()
    assert catalog.serial_of("user.example.") == 11
    assert catalog.serial == next_catalog_serial(0, settings.now())
    assert int(catalog.path.stat().st_mtime) == catalog.serial
    assert not older.exists() and not low.exists() and not newer.exists()
    assert (spool / "empty").exists()
    assert (spool / ".hidden").exists()


def test_tcp_child_refreshes_valid_zones_when_the_catalog_changes(env):
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    server = DnsServer(env.settings, env.store)
    port = server.start()
    try:
        first = _records(_xfr(port, "catalog.svc.test."))
        assert any(rdtype == "PTR" and text == "user.example."
                   for _name, rdtype, text in first)
        path = env.settings.db_path.parent / "catalog" / "catalog.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["zones"] = []
        path.write_text(json.dumps(data), encoding="utf-8")
        second = _records(_xfr(port, "catalog.svc.test."))
        assert not any(rdtype == "PTR" for _name, rdtype, _text in second)
        denied = dns.query.tcp(
            dns.message.make_query("user.example.", dns.rdatatype.AXFR),
            "127.0.0.1",
            port=port,
            timeout=2,
        )
        assert denied.rcode() == dns.rcode.REFUSED
    finally:
        server.stop()


def test_dnskey_cache_skips_a_repeated_validated_lookup(env):
    get_process_cache().clear()
    from dns_host.chain import authenticate_parent

    authenticate_parent(env.lab, env.settings, env.lab.apex)
    first = sum(1 for call in env.lab.calls if call["type"] == "DNSKEY")
    env.lab.calls.clear()
    authenticate_parent(env.lab, env.settings, env.lab.apex)
    second = sum(1 for call in env.lab.calls if call["type"] == "DNSKEY")
    assert first > 0
    assert second < first


def test_dead_axfr_child_is_replaced():
    spawned = []

    def spawn():
        spawned.append(1)
        return 100 + len(spawned)

    pids = supervise_once({1, 2}, 1, spawn)
    assert 1 not in pids
    assert pids == {2, 101}


def _member(apex: str, serial: int):
    return Member(apex=apex,
                  serial=serial,
                  soa=f"ns1.example.net. hostmaster.{apex} {serial} 1 1 1 1",
                  ttl=300,
                  expires_at=0)


def _settings(tmp_path, now: int, monkeypatch, clock=None):
    from dns_host.config import Settings
    from dns_host.names import normalise_name

    monkeypatch.setattr("dns_host.config.DATA_DIR", tmp_path)
    if clock is None:
        clock = {"t": now}

    def now_fn():
        return clock["t"]

    return Settings(
        service_ns=[normalise_name("ns1.example.net.")],
        catalog_zone=normalise_name("catalog.example.net."),
        catalog_rname=normalise_name("hostmaster.example.net."),
        now_fn=now_fn,
    )


def _store(settings):
    from dns_host.storage import Store

    store = Store(settings.db_path)
    store.ensure_catalog(settings.now())
    return store


def _job(apex: str, serial: int, expires_at: int | None = None) -> bytes:
    from dns_host.spool import encode_job

    soa = f"ns1.example.net. hostmaster.{apex} {serial} 3600 600 864000 300"
    return encode_job(
        apex=apex,
        serial=serial,
        expires_at=serial + 86400 if expires_at is None else expires_at,
        parent_zone="example.",
        soa=soa,
        soa_ttl=300,
        document={
            "apex": apex,
            "rrsets": []
        },
    )
