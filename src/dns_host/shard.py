"""Two-level shard paths for per-zone files.

The canonical zone name is the apex with surrounding whitespace removed,
lowercased with ``str.lower()``, and with every trailing dot removed.
``james.isthisyou.me.`` and ``James.IsThisYou.Me`` are both
``james.isthisyou.me``. Apexes are already ASCII (IDNA) before they are
stored; this function does not punycode them again.

The hash input is the UTF-8 bytes of that canonical name. The digest is
32-bit FNV-1a:

* offset basis ``2166136261`` (``0x811c9dc5``)
* prime ``16777619`` (``0x01000193``)
* for each byte: ``hash = (hash XOR byte) * prime``, modulo ``2**32``

That 32-bit value is xor-folded to 16 bits: the high 16 bits XOR the low
16 bits (``(hash >> 16) ^ (hash & 0xFFFF)``). ``hh`` is the high byte of
the 16-bit value and ``ll`` is the low byte, each as two lowercase hex
digits. The path is ``<dir>/<hh>/<ll>/<file>``. Two levels is the layout;
it is not extended when the zone count grows.

``james.isthisyou.me`` hashes to FNV-1a ``0x9d00b292``, folds to
``0x2f92``, and lives under ``2f/92/``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from dns_host.logutil import log

FNV_32_OFFSET = 2166136261
FNV_32_PRIME = 16777619

_HEX2 = re.compile(r"[0-9a-f]{2}")
_KEEP = {"catalogue.json", "catalog.json"}
_SUFFIXES = (".json", ".zone", ".ixfr")


def canonical_zone(name: str) -> str:
    """Lowercase apex with surrounding space and trailing dots removed."""

    text = str(name).strip().lower()
    while text.endswith("."):
        text = text[:-1]
    return text


def fnv1a_32(data: bytes) -> int:
    """32-bit FNV-1a of ``data``."""

    digest = FNV_32_OFFSET
    for byte in data:
        digest ^= byte
        digest = (digest * FNV_32_PRIME) & 0xFFFFFFFF
    return digest


def fnv_16(name: str) -> int:
    """16-bit xor-fold of the FNV-1a digest of the canonical zone name."""

    digest = fnv1a_32(canonical_zone(name).encode("utf-8"))
    return ((digest >> 16) ^ (digest & 0xFFFF)) & 0xFFFF


def shard_parts(name: str) -> tuple[str, str]:
    """``(hh, ll)`` lowercase hex bytes of :func:`fnv_16`."""

    folded = fnv_16(name)
    return f"{folded >> 8:02x}", f"{folded & 0xFF:02x}"


def zone_file_name(apex: str, suffix: str) -> str:
    """Basename of a per-zone file. ``suffix`` includes the leading dot."""

    if (not suffix.startswith(".") or suffix in {".", ".."} or "/" in suffix
            or "\\" in suffix):
        raise ValueError(f"unsafe suffix {suffix}")
    name = canonical_zone(apex)
    if (not name or name in {".", ".."} or "/" in name or "\\" in name
            or '"' in name or "\n" in name or "\r" in name):
        raise ValueError(f"unsafe apex {apex}")
    return name + suffix


def zone_path(directory: Path, apex: str, filename: str) -> Path:
    """``directory/hh/ll/filename`` for the canonical form of ``apex``.

    This is the helper every per-zone path goes through.
    """

    if (not filename or filename in {".", ".."} or "/" in filename
            or "\\" in filename or filename.startswith(".")):
        raise ValueError(f"unsafe zone filename {filename}")
    high, low = shard_parts(apex)
    return Path(directory) / high / low / filename


def locate_zone_file(directory: Path, apex: str, filename: str) -> Path | None:
    """Sharded path when that file exists, otherwise a legacy flat file."""

    sharded = zone_path(directory, apex, filename)
    if sharded.is_file():
        return sharded
    flat = Path(directory) / filename
    if flat.is_file():
        return flat
    return None


def remove_zone_file(directory: Path, apex: str, filename: str) -> None:
    """Delete the sharded file and a legacy flat file of the same name."""

    zone_path(directory, apex, filename).unlink(missing_ok=True)
    flat = Path(directory) / filename
    if flat.is_file():
        flat.unlink()


def iter_zone_files(directory: Path, suffix: str | None = None):
    """Flat files and files already stored at ``hh/ll``."""

    directory = Path(directory)
    if not directory.is_dir():
        return
    for entry in _top_entries(directory):
        if entry.is_file() and _wanted(entry.name, suffix):
            yield entry
            continue
        if not entry.is_dir() or not _HEX2.fullmatch(entry.name):
            continue
        for mid in _top_entries(entry):
            if not mid.is_dir() or not _HEX2.fullmatch(mid.name):
                continue
            for child in _top_entries(mid):
                if child.is_file() and _wanted(child.name, suffix):
                    yield child


def migrate_flat_zone_files(directory: Path) -> int:
    """Move flat per-zone files into ``hh/ll/``. Repeat runs move nothing.

    Each move is logged at info. A shard copy that already matches is kept
    and the flat file is removed. A shard copy that differs is left untouched.
    """

    directory = Path(directory)
    if not directory.is_dir():
        return 0
    moved = 0
    for entry in list(_top_entries(directory)):
        if not entry.is_file():
            continue
        planned = _migration_target(entry.name)
        if planned is None:
            continue
        zone, filename = planned
        destination = zone_path(directory, zone, filename)
        if destination == entry:
            continue
        if _relocate(entry, destination, zone):
            moved += 1
    return moved


def discard_nsd_fnv_zonefiles(directory: Path) -> int:
    """Delete hash-layout NSD copies so NSD transfers them once more.

    The old files are ``<hh>/<ll>/<name>.axfr`` with two hex digits in each
    directory. NSD now writes ``%1/%2/%s.zone``, whose directories are one
    character. Removing the ``.axfr`` files is enough: the next start loads
    nothing for that zone and AXFRs it, then writes the new path. A second
    run finds nothing to delete.
    """

    directory = Path(directory)
    if not directory.is_dir():
        return 0
    removed = 0
    for high in list(_top_entries(directory)):
        if not high.is_dir() or not _HEX2.fullmatch(high.name):
            continue
        for low in list(_top_entries(high)):
            if not low.is_dir() or not _HEX2.fullmatch(low.name):
                continue
            for child in list(_top_entries(low)):
                if not child.is_file() or not child.name.endswith(".axfr"):
                    continue
                if child.name.startswith("."):
                    continue
                try:
                    child.unlink()
                except OSError as exc:
                    log("warning",
                        "NSD hash-layout zone file left in place",
                        path=str(child),
                        error=str(exc))
                    continue
                log("info",
                    "deleted NSD zone file from the hash layout",
                    path=str(child))
                removed += 1
            _rmdir_if_empty(low)
        _rmdir_if_empty(high)
    return removed


def migrate_data_dirs(root: Path | None = None) -> int:
    """Shard ``zones/`` and drop old NSD hash-layout copies. Idempotent."""

    from dns_host.config import data_dir

    base = Path(root) if root is not None else data_dir()
    moved = migrate_flat_zone_files(base / "zones")
    moved += discard_nsd_fnv_zonefiles(base / "nsd" / "zones")
    return moved


def main() -> None:
    migrate_data_dirs()


def _wanted(filename: str, suffix: str | None) -> bool:
    if filename.startswith("."):
        return False
    if suffix is None:
        return True
    return filename.endswith(suffix)


def _top_entries(directory: Path):
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    return [entry for entry in entries if not entry.is_symlink()]


def _suffix_of(filename: str) -> str:
    lower = filename.lower()
    for suffix in _SUFFIXES:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            return suffix
    return ""


def _rmdir_if_empty(directory: Path) -> None:
    try:
        directory.rmdir()
    except OSError:
        return


def _migration_target(filename: str) -> tuple[str, str] | None:
    if (not filename or filename.startswith(".") or filename in _KEEP
            or filename.startswith("xfr.") or filename.startswith("nsd-xfr")):
        return None
    suffix = _suffix_of(filename)
    if not suffix:
        return None
    base = filename[:-len(suffix)]
    try:
        zone = canonical_zone(base)
        zone_file_name(zone, ".axfr")
    except ValueError:
        return None
    return zone, zone + suffix.lower()


def _relocate(src: Path, dest: Path, zone: str) -> bool:
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            same = dest.read_bytes() == src.read_bytes()
            if same:
                src.unlink()
                log("info",
                    "removed flat zone file already in shard",
                    zone=zone,
                    src=str(src),
                    dest=str(dest))
                return True
            log("warning",
                "flat zone file differs from shard copy",
                zone=zone,
                src=str(src),
                dest=str(dest))
            return False
        os.replace(src, dest)
    except FileNotFoundError:
        return False
    except OSError as exc:
        log("warning",
            "flat zone file left in place",
            zone=zone,
            src=str(src),
            error=str(exc))
        return False
    log("info",
        "moved flat zone file",
        zone=zone,
        src=str(src),
        dest=str(dest))
    return True


if __name__ == "__main__":
    main()
