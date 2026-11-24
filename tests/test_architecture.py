"""Spool handoff, catalog serial, and TCP refresh of the valid-zone list."""

import json
import os
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from dns_host.axfr_service import supervise_once
from dns_host.catalogfile import Catalog, next_catalog_serial
from dns_host.controller import Controller
from dns_host.dns_server import DnsServer
from dns_host.dnskey_cache import get_process_cache
from dns_host.spool import pending, submit
from tests.conftest import post
from tests.test_axfr_grace import _records, _xfr


def test_catalog_serial_is_max_of_now_and_last_plus_one_and_is_the_mtime(tmp_path):
    settings = _settings(tmp_path, now=100)
    catalog = Catalog(settings)
    catalog.serial = 5000
    catalog.save(100)
    assert catalog.serial == 5001
    assert next_catalog_serial(5000, 100) == 5001
    assert int(catalog.path.stat().st_mtime) == 5001
    catalog.save(9000)
    assert catalog.serial == 9000
    assert int(catalog.path.stat().st_mtime) == 9000


def test_controller_ignores_empty_dirs_and_hidden_files_and_rechecks_serial(tmp_path):
    settings = _settings(tmp_path, now=1_700_000_000)
    store = _store(settings)
    controller = Controller(settings, store)
    spool = Path(settings.data_dir) / "spool"
    spool.mkdir(parents=True)
    (spool / "tmp").mkdir()
    (spool / "empty").write_bytes(b"")
    (spool / ".hidden").write_bytes(b"not a job")
    (spool / "subdir").mkdir()
    far = 1_700_000_000 + 365 * 86400
    stale = _job(apex="user.example.", serial=10, expires_at=far)
    older = submit(spool, stale)
    os.utime(older, (1_700_000_000, 1_700_000_000))
    newer = submit(spool, _job(apex="user.example.", serial=11, expires_at=far))
    os.utime(newer, (1_700_000_100, 1_700_000_100))
    # A lower serial after a higher one must be dropped, not installed.
    low = submit(spool, _job(apex="user.example.", serial=9, expires_at=far))
    os.utime(low, (1_700_000_050, 1_700_000_050))
    assert [item.name for item in pending(spool)] == [older.name, low.name, newer.name]
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
        assert any(rdtype == "PTR" and text == "user.example." for _name, rdtype, text in first)
        path = env.settings.data_dir / "catalog" / "catalog.json"
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


def _settings(tmp_path, now: int):
    from dns_host.config import Settings
    from dns_host.names import normalise_name

    clock = {"t": now}

    def now_fn():
        return clock["t"]

    return Settings(
        service_ns=[normalise_name("ns1.example.net.")],
        catalog_zone=normalise_name("catalog.example.net."),
        catalog_rname=normalise_name("hostmaster.example.net."),
        data_dir=tmp_path,
        now_fn=now_fn,
    )


def _store(settings):
    from dns_host.storage import Store

    store = Store(settings.db_path)
    store.ensure_catalog(settings.now())
    return store


def _job(apex: str, serial: int, expires_at: int | None = None) -> bytes:
    from dns_host.spool import encode_job
    from dns_host.wireaxfr import tcp_bytes
    import dns.rrset

    soa = f"ns1.example.net. hostmaster.{apex} {serial} 3600 600 864000 300"
    rr = dns.rrset.from_text(apex, 300, "IN", "SOA", soa)
    return encode_job(
        apex=apex,
        serial=serial,
        expires_at=serial + 86400 if expires_at is None else expires_at,
        parent_zone="example.",
        soa=soa,
        soa_ttl=300,
        wire=tcp_bytes([rr]),
    )
