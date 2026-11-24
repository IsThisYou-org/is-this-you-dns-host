"""FNV shard layout, startup migration, and explicit NSD zonefile paths."""

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
    migrate_flat_zone_files,
    relative_zonefile,
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
    filename = zone_file_name("james.isthisyou.me.", ".axfr")
    assert filename == "james.isthisyou.me.axfr"
    path = zone_path(Path("/opt/data/nsd/zones"), "james.isthisyou.me",
                     filename)
    assert path == Path("/opt/data/nsd/zones/2f/92/james.isthisyou.me.axfr")
    assert relative_zonefile("james.isthisyou.me.") == (
        "2f/92/james.isthisyou.me.axfr")


def test_render_nsd_emits_explicit_zonefile_paths():
    settings = Settings(
        catalog_zone=dns.name.from_text("catalog.example.net."))
    text = render_nsd(settings, ["catalog.example.net.", "user.example."])
    assert 'zonefile: "86/3d/catalog.example.net.axfr"' in text
    assert 'zonefile: "c6/3c/user.example.axfr"' in text
    assert 'name: "user.example"' in text
    assert 'include-pattern: "catalog-member"' in text
    assert text.count("\nzone:") == 2
    assert "zonefiles-write: 60" in text
    assert 'zonesdir: "/opt/data/nsd/zones"' in text
    assert "%1" not in text
    assert "%s" not in text


def test_migrate_flat_files_is_idempotent(tmp_path, capsys):
    set_log_level("info")
    zones = tmp_path / "zones"
    zones.mkdir()
    (zones / "james.isthisyou.me.axfr").write_bytes(b"wire")
    (zones / "james.isthisyou.me.json").write_bytes(b"{\"apex\":1}")
    (zones / "catalogue.json").write_text("{}", encoding="utf-8")
    (zones / ".hidden.axfr").write_bytes(b"no")
    (zones / "notes.txt").write_bytes(b"no")
    (zones / "xfr.9").write_bytes(b"temp")
    (zones / "subdir").mkdir()
    (zones / "subdir" / "other.axfr").write_bytes(b"leave")

    assert migrate_flat_zone_files(zones) == 2
    axfr = zones / "2f" / "92" / "james.isthisyou.me.axfr"
    document = zones / "2f" / "92" / "james.isthisyou.me.json"
    assert axfr.read_bytes() == b"wire"
    assert document.read_bytes() == b'{"apex":1}'
    assert not (zones / "james.isthisyou.me.axfr").exists()
    assert (zones / "catalogue.json").read_text(encoding="utf-8") == "{}"
    assert (zones / ".hidden.axfr").read_bytes() == b"no"
    assert (zones / "notes.txt").read_bytes() == b"no"
    assert (zones / "xfr.9").read_bytes() == b"temp"
    assert (zones / "subdir" / "other.axfr").read_bytes() == b"leave"
    logged = capsys.readouterr().out
    assert logged.count("moved flat zone file") == 2

    assert migrate_flat_zone_files(zones) == 0
    assert capsys.readouterr().out == ""
    assert axfr.read_bytes() == b"wire"


def test_migrate_keeps_matching_shard_and_leaves_a_conflict(tmp_path, capsys):
    set_log_level("info")
    zones = tmp_path / "zones"
    dest = zones / "2f" / "92"
    dest.mkdir(parents=True)
    (dest / "james.isthisyou.me.axfr").write_bytes(b"wire")
    (zones / "james.isthisyou.me.axfr").write_bytes(b"wire")
    assert migrate_flat_zone_files(zones) == 1
    assert not (zones / "james.isthisyou.me.axfr").exists()
    assert "removed flat zone file already in shard" in capsys.readouterr().out

    (zones / "james.isthisyou.me.json").write_bytes(b"new")
    (dest / "james.isthisyou.me.json").write_bytes(b"old")
    assert migrate_flat_zone_files(zones) == 0
    assert (zones / "james.isthisyou.me.json").read_bytes() == b"new"
    assert (dest / "james.isthisyou.me.json").read_bytes() == b"old"
    assert "differs from shard copy" in capsys.readouterr().out


def test_nsd_bare_zone_file_is_moved_to_axfr_name(tmp_path):
    zones = tmp_path / "nsd" / "zones"
    zones.mkdir(parents=True)
    (zones / "james.isthisyou.me").write_bytes(b"zone")
    (zones / "other.example.zone").write_bytes(b"zone2")
    assert migrate_flat_zone_files(zones, bare_as_axfr=True) == 2
    assert (zones / "2f" / "92" /
            "james.isthisyou.me.axfr").read_bytes() == b"zone"
    other = zone_path(zones, "other.example", "other.example.axfr")
    assert other.read_bytes() == b"zone2"
    assert not (zones / "james.isthisyou.me").exists()


def test_migrate_data_dirs_covers_zones_and_nsd(tmp_path):
    (tmp_path / "zones").mkdir()
    (tmp_path / "zones" / "user.example.axfr").write_bytes(b"a")
    nsd_zones = tmp_path / "nsd" / "zones"
    nsd_zones.mkdir(parents=True)
    (nsd_zones / "user.example").write_bytes(b"b")
    xfr = tmp_path / "nsd" / "xfr"
    xfr.mkdir(parents=True)
    (xfr / "user.example.axfr").write_bytes(b"c")
    (xfr / "nsd-xfr-1").mkdir()
    assert migrate_data_dirs(tmp_path) == 3
    assert (tmp_path / "zones" / "c6" / "3c" /
            "user.example.axfr").read_bytes() == b"a"
    assert (nsd_zones / "c6" / "3c" / "user.example.axfr").read_bytes() == b"b"
    assert (xfr / "c6" / "3c" / "user.example.axfr").read_bytes() == b"c"
    assert migrate_data_dirs(tmp_path) == 0


def test_controller_install_and_delete_use_the_shard(tmp_path, monkeypatch):
    from dns_host.controller import Controller, zone_wire_path
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
    path = zone_wire_path(settings, "James.IsThisYou.Me.")
    assert path == tmp_path / "zones" / "2f" / "92" / "james.isthisyou.me.axfr"
    assert path.is_file()
    assert not (tmp_path / "zones" / "james.isthisyou.me.axfr").exists()
    document = tmp_path / "zones" / "2f" / "92" / "james.isthisyou.me.json"
    assert document.is_file()
    conf = (tmp_path / "nsd" / "nsd.conf").read_text(encoding="utf-8")
    assert 'zonefile: "2f/92/james.isthisyou.me.axfr"' in conf
    assert "zonefiles-write: 60" in conf
    assert (tmp_path / "nsd" / "zones" / "2f" / "92").is_dir()
    assert "%1" not in conf

    flat = tmp_path / "zones" / "james.isthisyou.me.axfr"
    flat.write_bytes(b"stale")
    controller.remove("james.isthisyou.me.", settings.now())
    assert not path.exists()
    assert not flat.exists()
    assert not document.exists()


def test_readme_and_cron_document_the_layout():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "0x9d00b292" in readme
    assert "0x2f92" in readme
    assert "2f/92/" in readme
    assert "FNV-1a" in readme
    assert "zonefiles-write: 60" in readme
    assert "127.0.0.1:5353" in readme
    assert "(hash >> 16) ^ (hash & 0xFFFF)" in readme
    assert "every 15 minutes" in readme.lower() or "Every 15 minutes" in readme
    cron = (root / "deploy" / "crontabs" / "root").read_text(encoding="utf-8")
    assert cron.count("*/15 * * * *") == 2
    assert "-mmin +5" in cron
    assert "-maxdepth 1" in cron
    assert "* * * * *" not in cron
