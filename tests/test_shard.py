"""FNV shard layout for the hidden primary, and NSD's catalog zonefiles."""

from pathlib import Path

import dns.name

from dns_host.config import Settings
from dns_host.logutil import set_log_level
from dns_host.nsdconf import render_nsd
from dns_host.shard import (
    canonical_zone,
    fnv1a_32,
    fnv_16,
    migrate_data_dirs,
    discard_nsd_fnv_zonefiles,
    migrate_flat_zone_files,
    zone_file_name,
    zone_path,
)


def test_fnv_vectors_and_james_shard():
    assert fnv1a_32(b"") == 0x811C9DC5
    assert fnv1a_32(b"a") == 0xE40C292C
    assert fnv1a_32(b"foobar") == 0xBF9CF968
    assert canonical_zone("  James.IsThisYou.Me.  ") == "james.isthisyou.me"
    assert canonical_zone("james.isthisyou.me.") == "james.isthisyou.me"
    assert fnv1a_32(b"james.isthisyou.me") == 0x9D00B292
    assert fnv_16("james.isthisyou.me") == 0x2F92
    assert fnv_16("James.IsThisYou.Me.") == 0x2F92
    filename = zone_file_name("james.isthisyou.me.", ".json")
    assert filename == "james.isthisyou.me.json"
    path = zone_path(Path("/opt/data/zones"), "james.isthisyou.me", filename)
    assert path == Path("/opt/data/zones/2f/92/james.isthisyou.me.json")


def test_render_nsd_lists_only_the_catalog_zone():
    settings = Settings(
        catalog_zone=dns.name.from_text("catalog.example.net."))
    text = render_nsd(settings)
    assert 'zonefile: "%1/%2/%s.zone"' in text
    assert 'zonefile: "catalog.zone"' in text
    assert 'name: "catalog.example.net"' in text
    assert "user.example" not in text
    assert 'catalog-member-pattern: "catalog-member"' in text
    assert text.count("\nzone:") == 1
    assert "zonefiles-write: 60" in text
    assert 'zonesdir: "/opt/data/nsd/zones"' in text


def test_migrate_flat_files_is_idempotent(tmp_path, capsys):
    set_log_level("info")
    zones = tmp_path / "zones"
    zones.mkdir()
    (zones / "james.isthisyou.me.axfr").write_bytes(b"wire")
    (zones / "other.example.json").write_bytes(b"{\"apex\":1}")
    (zones / "catalogue.json").write_text("{}", encoding="utf-8")
    (zones / ".hidden.axfr").write_bytes(b"no")
    (zones / "notes.txt").write_bytes(b"no")
    (zones / "xfr.9").write_bytes(b"temp")
    (zones / "subdir").mkdir()
    (zones / "subdir" / "other.axfr").write_bytes(b"leave")

    assert migrate_flat_zone_files(zones) == 1
    document = zone_path(zones, "other.example", "other.example.json")
    assert document.read_bytes() == b'{"apex":1}'
    assert (zones / "james.isthisyou.me.axfr").read_bytes() == b"wire"
    assert (zones / "catalogue.json").read_text(encoding="utf-8") == "{}"
    assert (zones / ".hidden.axfr").read_bytes() == b"no"
    assert (zones / "notes.txt").read_bytes() == b"no"
    assert (zones / "xfr.9").read_bytes() == b"temp"
    assert (zones / "subdir" / "other.axfr").read_bytes() == b"leave"
    logged = capsys.readouterr().out
    assert logged.count("moved flat zone file") == 1

    assert migrate_flat_zone_files(zones) == 0
    assert capsys.readouterr().out == ""
    assert document.read_bytes() == b'{"apex":1}'


def test_migrate_keeps_matching_shard_and_leaves_a_conflict(tmp_path, capsys):
    set_log_level("info")
    zones = tmp_path / "zones"
    dest = zones / "2f" / "92"
    dest.mkdir(parents=True)
    (dest / "james.isthisyou.me.json").write_bytes(b"wire")
    (zones / "james.isthisyou.me.json").write_bytes(b"wire")
    assert migrate_flat_zone_files(zones) == 1
    assert not (zones / "james.isthisyou.me.json").exists()
    assert "removed flat zone file already in shard" in capsys.readouterr().out

    (zones / "james.isthisyou.me.json").write_bytes(b"new")
    (dest / "james.isthisyou.me.json").write_bytes(b"old")
    assert migrate_flat_zone_files(zones) == 0
    assert (zones / "james.isthisyou.me.json").read_bytes() == b"new"
    assert (dest / "james.isthisyou.me.json").read_bytes() == b"old"
    assert "differs from shard copy" in capsys.readouterr().out


def test_old_nsd_hash_copies_are_deleted(tmp_path, capsys):
    set_log_level("info")
    zones = tmp_path / "nsd" / "zones"
    old = zones / "2f" / "92"
    old.mkdir(parents=True)
    (old / "james.isthisyou.me.axfr").write_bytes(b"stale")
    kept = zones / "j" / "a"
    kept.mkdir(parents=True)
    (kept / "james.isthisyou.me.zone").write_bytes(b"new")
    (zones / "catalog.zone").write_bytes(b"catalog")
    assert discard_nsd_fnv_zonefiles(zones) == 1
    assert not old.exists()
    assert (kept / "james.isthisyou.me.zone").read_bytes() == b"new"
    assert (zones / "catalog.zone").read_bytes() == b"catalog"
    assert "deleted NSD zone file from the hash layout" in capsys.readouterr(
    ).out
    assert discard_nsd_fnv_zonefiles(zones) == 0


def test_migrate_data_dirs_shards_zones_and_drops_nsd_hash_copies(tmp_path):
    (tmp_path / "zones").mkdir()
    (tmp_path / "zones" / "user.example.json").write_bytes(b"a")
    nsd_zones = tmp_path / "nsd" / "zones"
    old = nsd_zones / "c6" / "3c"
    old.mkdir(parents=True)
    (old / "user.example.axfr").write_bytes(b"b")
    xfr = tmp_path / "nsd" / "xfr"
    xfr.mkdir(parents=True)
    (xfr / "user.example.axfr").write_bytes(b"c")
    assert migrate_data_dirs(tmp_path) == 2
    assert (tmp_path / "zones" / "c6" / "3c" /
            "user.example.json").read_bytes() == b"a"
    assert not (nsd_zones / "c6").exists()
    assert (xfr / "user.example.axfr").read_bytes() == b"c"
    assert migrate_data_dirs(tmp_path) == 0


def test_controller_install_and_delete_use_the_shard(tmp_path, monkeypatch):
    from dns_host.controller import Controller
    from dns_host.shard import zone_file_name
    from dns_host.spool import submit
    from tests.test_architecture import _job, _settings, _store

    settings = _settings(tmp_path, now=1_700_000_000, monkeypatch=monkeypatch)
    store = _store(settings)
    controller = Controller(settings, store)
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "tmp").mkdir()
    submit(
        spool,
        _job(apex="james.isthisyou.me.",
             serial=10,
             expires_at=1_700_000_000 + 86400))
    controller.run_once()
    path = zone_path(tmp_path / "zones", "James.IsThisYou.Me.",
                     zone_file_name("James.IsThisYou.Me.", ".json"))
    assert path == tmp_path / "zones" / "2f" / "92" / "james.isthisyou.me.json"
    assert path.is_file()
    assert not (tmp_path / "zones" / "james.isthisyou.me.axfr").exists()
    assert not (tmp_path / "nsd" / "nsd.conf").exists()

    controller.remove("james.isthisyou.me.", settings.now())
    assert not path.exists()


def test_readme_and_cron_document_the_layout():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "0x9d00b292" in readme
    assert "0x2f92" in readme
    assert "2f/92/" in readme
    assert "FNV-1a" in readme
    assert 'zonefile: "%1/%2/%s.zone"' in readme or "%1/%2/%s.zone" in readme
    assert "catalog.zone" in readme
    assert "create_dirs" in readme
    assert "a.example" in readme
    assert "zonefiles-write: 60" in readme
    assert "127.0.0.1:5353" in readme
    assert "(hash >> 16) ^ (hash & 0xFFFF)" in readme
    assert "every 15 minutes" in readme.lower() or "Every 15 minutes" in readme
    assert "cron.log" not in readme
    start_cron = (root / "bin" / "start_cron").read_text(encoding="utf-8")
    assert "crond -f -S -c /etc/crontabs" in start_cron
    assert "cron.log" not in start_cron
    cron = (root / "deploy" / "crontabs" / "root").read_text(encoding="utf-8")
    assert cron.count("*/15 * * * *") == 2
    assert "-mmin +5" in cron
    assert "-maxdepth 1" in cron
    assert "* * * * *" not in cron
