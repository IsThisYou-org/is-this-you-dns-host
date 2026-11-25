"""Operator configuration from ``/opt/data/etc/config.yaml``.

A missing file is empty configuration and the defaults below apply. Unknown
keys are rejected. Every problem is collected and reported together, one
line per problem, and the process exits without a traceback. The process
refuses to start when ``service_ns`` is unset. ``log_level`` defaults to
``info`` and must be a syslog severity name. ``axfr_allow`` defaults to
empty; each entry is an IPv4 or IPv6 CIDR (a bare address is a /32 or /128)
and a bad entry stops the process at startup. Tests construct ``Settings``
directly. TSIG secrets may be inline or read from a file; they are never
taken from a zone upload.
"""

from __future__ import annotations

import difflib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dns_host.errors import ApiError
from dns_host.names import normalise_name
from dns_host.rrtypes import DEFAULT_TYPES, STANDARD_ZONE_TYPES, ensure_wallet_type

CONFIG_PATH = Path("/opt/data/etc/config.yaml")

# The internal DNS listener is not operator configuration. UDP (SOA and
# NOTIFY) and TCP (AXFR) always bind here, and localhost AXFR is always
# accepted.
DNS_BIND = "127.0.0.1"
DNS_PORT = 5353

# nginx's localhost listener and gunicorn stay inside the container. They
# are not operator configuration.
INTERNAL_HTTP_PORT = 8081
GUNICORN_BIND = "127.0.0.1:8000"

# Public HTTP, NSD, the data directory, and the ICANN trust-anchor file
# are fixed by the image.
HTTP_PORT = 80
NSD_BIND = "0.0.0.0"
NSD_PORT = 53
# NSD statistics. Not on the public HTTP port.
METRICS_PORT = 9100
NSD_CONTROL_HOST = "127.0.0.1"
NSD_CONTROL_PORT = 8952
DATA_DIR = Path("/opt/data")
TRUST_ANCHOR_FILE = Path("/app/deploy/root-anchors.ds")

# Signed 32-bit ceiling used for TTLs and durations (RFC 2181).
_TIME_MAX = 2**31 - 1
_COUNT_MAX = 1000000

# 0 disables rate_limit_requests, parent_query_budget, and
# apexes_per_parent_per_day. Other counters and durations stay positive.
_INT_FIELDS: dict[str, tuple[int, int, int]] = {
    "gunicorn_workers": (3, 1, 1024),
    "axfr_children": (5, 1, 1024),
    "dnskey_cache_seconds": (3600, 0, _TIME_MAX),
    "max_body_bytes": (1048576, 1, 1024 * 1024 * 1024),
    "max_rrsets": (2000, 1, _COUNT_MAX),
    "max_names": (1000, 1, _COUNT_MAX),
    "max_rdata_bytes": (4096, 1, 65535),
    "rate_limit_requests": (30, 0, _COUNT_MAX),
    "rate_limit_window_seconds": (60, 1, _TIME_MAX),
    "parent_query_budget": (15, 0, _COUNT_MAX),
    "parent_query_window_seconds": (60, 1, _TIME_MAX),
    "max_doh_queries_per_walk": (32, 1, 10000),
    "serial_future_seconds": (300, 0, _TIME_MAX),
    "serial_past_seconds": (3600, 0, _TIME_MAX),
    "rrsig_max_lifetime_seconds": (30 * 86400, 1, _TIME_MAX),
    "rrsig_inception_future_seconds": (300, 0, _TIME_MAX),
    "rrsig_min_remaining_seconds": (0, 0, _TIME_MAX),
    "grace_days": (90, 0, 36500),
    "negative_cache_ttl_seconds": (60, 0, _TIME_MAX),
    "min_ttl": (30, 0, _TIME_MAX),
    "max_ttl": (86400, 0, _TIME_MAX),
    "apexes_per_parent_per_day": (0, 0, _COUNT_MAX),
    "doh_cd": (1, 0, 1),
    "maintenance_interval_seconds": (300, 1, _TIME_MAX),
    "soa_refresh": (60, 1, _TIME_MAX),
    "soa_retry": (60, 1, _TIME_MAX),
    "soa_expire": (864000, 1, _TIME_MAX),
    "soa_minimum": (300, 0, _TIME_MAX),
    "catalog_ttl": (300, 0, _TIME_MAX),
}

_KNOWN_KEYS = frozenset(_INT_FIELDS) | {
    "service_ns",
    "secondaries",
    "axfr_allow",
    "resolver_base_url",
    "catalog_zone",
    "catalog_rname",
    "doh_timeout_seconds",
    "handshake_root_servers",
    "handshake_trust_anchor_file",
    "type_allowlist",
    "trusted_proxies",
    "health_check_dns",
    "log_level",
}


def data_dir() -> Path:
    """Persistent state directory. Tests may monkeypatch ``DATA_DIR``."""

    return DATA_DIR


def _now() -> int:
    import time

    return int(time.time())


def parse_trusted_proxies(raw: str) -> list[str]:
    """Return nginx-ready CIDRs. A bare address becomes a /32 or /128."""

    out: list[str] = []
    problems: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            problems.append(
                f"invalid trusted_proxies {part!r}: expected an IPv4 or IPv6 "
                "CIDR (a bare address is a /32 or /128)")
    if problems:
        raise SystemExit("\n".join(problems))
    return out


def parse_axfr_allow(value) -> list[str]:
    """Return canonical CIDRs. A bare address is a /32 or /128.

    A missing value is an empty list. Host bits in a prefix are masked.
    Anything that is not an IPv4 or IPv6 network raises ``SystemExit``.
    """

    if value is None or value == "" or value == []:
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise SystemExit(
            f"invalid axfr_allow: expected a list of CIDRs, got {value!r}")
    out: list[str] = []
    seen: set[str] = set()
    problems: list[str] = []
    for item in items:
        if not isinstance(item, str):
            problems.append(
                f"invalid axfr_allow {item!r}: expected an IPv4 or IPv6 CIDR "
                "(a bare address is a /32 or /128)")
            continue
        text = item.strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            problems.append(
                f"invalid axfr_allow {text!r}: expected an IPv4 or IPv6 CIDR "
                "(a bare address is a /32 or /128)")
            continue
        canonical = str(network)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    if problems:
        raise SystemExit("\n".join(problems))
    return out


class AxfrAllow:
    """Secondary hosts and ``axfr_allow`` networks that may AXFR.

    Membership is subnet-aware. An address matches when it is a secondary
    host or it falls inside an ``axfr_allow`` network. Iteration yields
    canonical CIDR strings, secondaries first.
    """

    def __init__(self, networks: list) -> None:
        self._networks = list(networks)

    def __contains__(self, item: object) -> bool:
        try:
            address = ipaddress.ip_address(str(item).strip())
        except (TypeError, ValueError):
            return False
        return any(address in network for network in self._networks)

    def __iter__(self):
        return (str(network) for network in self._networks)

    def __len__(self) -> int:
        return len(self._networks)


@dataclass
class Secondary:
    """One configured secondary. Iterates as ``(host, port)`` for existing callers."""

    host: str
    port: int = 53
    tsig_key_name: str = ""
    tsig_secret: str = ""
    tsig_algo: str = "hmac-sha256"

    def __iter__(self):
        yield self.host
        yield self.port

    def __getitem__(self, index: int):
        return (self.host, self.port)[index]


def parse_secondaries(raw: str) -> list[tuple[str, int]]:
    """Parse ``ip``, ``ip:port``, or ``[ipv6]:port`` entries.

    IPv6 addresses must be in brackets. The port is the NOTIFY destination.
    AXFR authorisation uses the address only.
    """

    out: list[tuple[str, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("["):
            host, _, rest = part[1:].partition("]")
            if rest.startswith(":"):
                port = _port_text(rest[1:], part)
            elif rest == "":
                port = 53
            else:
                raise ValueError(f"bad secondary address {part}")
        elif part.count(":") == 1:
            host, port_s = part.split(":")
            port = _port_text(port_s, part)
        elif ":" in part:
            raise ValueError(f"bracket IPv6 secondaries, got {part}")
        else:
            host, port = part, 53
        ipaddress.ip_address(host)
        out.append((host, port))
    return out


def _port_text(text: str, part: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise ValueError(f"bad secondary port in {part}") from None


def parse_csv_names(raw: str) -> list:
    names = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            names.append(normalise_name(part, what="configured name"))
    return names


def load_ds_anchors(path: Path) -> list:
    """Load DS (or DNSKEY, ignored) presentation lines from a file."""

    if not path.is_file():
        return []
    anchors = []
    for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.split(";", 1)[0].strip()
        if not stripped or stripped.startswith("#"):
            continue
        upper = stripped.upper()
        if " DS " not in f" {upper} ":
            # Allow a bare rdata line: "20326 8 2 HEX"
            if stripped.split()[0].isdigit():
                rdata_text = stripped
            else:
                continue
        else:
            marker = upper.index(" DS ")
            rdata_text = stripped[marker + 4:].strip()
        try:
            anchors.append(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                    rdata_text))
        except Exception as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return anchors


@dataclass
class Settings:
    service_ns: list = field(default_factory=list)
    secondaries: list = field(default_factory=list)
    axfr_allow: list = field(default_factory=list)
    resolver_base_url: str = "https://api.isthisyou.org/"
    catalog_zone: object = None
    catalog_rname: object = None
    gunicorn_workers: int = 3
    axfr_children: int = 5
    dnskey_cache_seconds: int = 3600
    max_body_bytes: int = 1048576
    max_rrsets: int = 2000
    max_names: int = 1000
    max_rdata_bytes: int = 4096
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    parent_query_budget: int = 15
    parent_query_window_seconds: int = 60
    max_doh_queries_per_walk: int = 32
    serial_future_seconds: int = 300
    serial_past_seconds: int = 3600
    rrsig_max_lifetime_seconds: int = 30 * 86400
    rrsig_inception_future_seconds: int = 300
    rrsig_min_remaining_seconds: int = 0
    grace_days: int = 90
    negative_cache_ttl_seconds: int = 60
    min_ttl: int = 30
    max_ttl: int = 86400
    apexes_per_parent_per_day: int = 0
    doh_timeout_seconds: float = 5.0
    doh_cd: int = 1
    trust_anchors: list = field(default_factory=list)
    handshake_root_servers: list = field(default_factory=list)
    handshake_trust_anchors: list = field(default_factory=list)
    maintenance_interval_seconds: int = 300
    soa_refresh: int = 60
    soa_retry: int = 60
    soa_expire: int = 864000
    soa_minimum: int = 300
    catalog_ttl: int = 300
    type_allowlist: frozenset = field(default_factory=frozenset)
    trusted_proxies: list = field(default_factory=list)
    health_check_dns: bool = True
    log_level: str = "info"
    now_fn: Callable[[], int] = _now

    def __post_init__(self) -> None:
        from dns_host.logutil import parse_log_level, set_log_level

        try:
            canonical = parse_log_level(self.log_level)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        self.log_level = canonical
        set_log_level(canonical)
        self.axfr_allow = parse_axfr_allow(self.axfr_allow)

    def now(self) -> int:
        return int(self.now_fn())

    def require_service_ns(self) -> None:
        """Refuse to start when the public nameserver list was not configured."""

        if self.service_ns:
            return
        from dns_host.logutil import log

        log("error", "refusing to start", error="service_ns is unset")
        raise SystemExit("service_ns is required in /opt/data/etc/config.yaml")

    @property
    def grace_seconds(self) -> int:
        return self.grace_days * 86400

    @property
    def db_path(self) -> Path:
        return data_dir() / "host.db"

    @property
    def allowed_axfr_ips(self) -> AxfrAllow:
        """Secondary hosts plus ``axfr_allow`` networks. Membership tests subnets."""

        networks = []
        seen = set()
        for host, _port in self.secondaries:
            network = ipaddress.ip_network(str(host), strict=False)
            if network in seen:
                continue
            seen.add(network)
            networks.append(network)
        for item in self.axfr_allow:
            network = ipaddress.ip_network(str(item), strict=False)
            if network in seen:
                continue
            seen.add(network)
            networks.append(network)
        return AxfrAllow(networks)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        """Load ``/opt/data/etc/config.yaml``. A missing file is empty configuration."""

        config_path = Path(path) if path is not None else CONFIG_PATH
        raw: dict = {}
        if config_path.is_file():
            import yaml

            try:
                loaded = yaml.safe_load(
                    config_path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                _fail([f"{config_path} is not valid YAML: {exc}"], config_path)
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                _fail([f"{config_path} must be a mapping"], config_path)
            raw = loaded
        return cls.from_mapping(raw, config_path)

    @classmethod
    def from_mapping(cls, raw: dict, path: Path | None = None) -> "Settings":
        if not isinstance(raw, dict):
            _fail(["configuration must be a mapping"], path)
        errors: list[str] = []
        _unknown_keys(raw, errors)
        log_level = _guard(errors, "log_level", lambda: _map_log_level(raw),
                           "info")
        service_ns = _guard(
            errors, "service_ns",
            lambda: _names_value(raw.get("service_ns", []), "service_ns"), [])
        catalog = _mapping_name(raw, "catalog_zone", "catalog.example.net.",
                                errors)
        rname = _catalog_rname(raw, catalog, errors)
        types = _type_allowlist(raw, errors)
        secondaries = _guard(
            errors, "secondaries",
            lambda: _secondaries_value(raw.get("secondaries", [])), [])
        axfr_allow = _guard(
            errors, "axfr_allow",
            lambda: parse_axfr_allow(raw.get("axfr_allow", [])), [])
        resolver = _resolver_base_url(raw, errors)
        failed: set[str] = set()
        ints: dict[str, int] = {}
        for key, (default, low, high) in _INT_FIELDS.items():
            ints[key] = _map_int(raw, key, default, low, high, errors, failed)
        timeout = _map_timeout(raw, errors)
        anchors = _handshake_anchors(raw, errors)
        roots = _guard(
            errors, "handshake_root_servers",
            lambda: _names_value(raw.get("handshake_root_servers", []),
                                 "handshake_root_servers"), [])
        proxies = _trusted_proxies(raw, errors)
        health = _map_bool(raw, "health_check_dns", True, errors)
        _cross_checks(ints, failed, errors)
        if errors or catalog is None or rname is None:
            _fail(errors or ["invalid configuration"], path)
        return cls(
            service_ns=service_ns,
            secondaries=secondaries,
            axfr_allow=axfr_allow,
            resolver_base_url=resolver,
            catalog_zone=catalog,
            catalog_rname=rname,
            gunicorn_workers=ints["gunicorn_workers"],
            axfr_children=ints["axfr_children"],
            dnskey_cache_seconds=ints["dnskey_cache_seconds"],
            max_body_bytes=ints["max_body_bytes"],
            max_rrsets=ints["max_rrsets"],
            max_names=ints["max_names"],
            max_rdata_bytes=ints["max_rdata_bytes"],
            rate_limit_requests=ints["rate_limit_requests"],
            rate_limit_window_seconds=ints["rate_limit_window_seconds"],
            parent_query_budget=ints["parent_query_budget"],
            parent_query_window_seconds=ints["parent_query_window_seconds"],
            max_doh_queries_per_walk=ints["max_doh_queries_per_walk"],
            serial_future_seconds=ints["serial_future_seconds"],
            serial_past_seconds=ints["serial_past_seconds"],
            rrsig_max_lifetime_seconds=ints["rrsig_max_lifetime_seconds"],
            rrsig_inception_future_seconds=ints[
                "rrsig_inception_future_seconds"],
            rrsig_min_remaining_seconds=ints["rrsig_min_remaining_seconds"],
            grace_days=ints["grace_days"],
            negative_cache_ttl_seconds=ints["negative_cache_ttl_seconds"],
            min_ttl=ints["min_ttl"],
            max_ttl=ints["max_ttl"],
            apexes_per_parent_per_day=ints["apexes_per_parent_per_day"],
            doh_timeout_seconds=timeout,
            doh_cd=ints["doh_cd"],
            trust_anchors=load_ds_anchors(TRUST_ANCHOR_FILE),
            handshake_root_servers=roots,
            handshake_trust_anchors=anchors,
            maintenance_interval_seconds=ints["maintenance_interval_seconds"],
            soa_refresh=ints["soa_refresh"],
            soa_retry=ints["soa_retry"],
            soa_expire=ints["soa_expire"],
            soa_minimum=ints["soa_minimum"],
            catalog_ttl=ints["catalog_ttl"],
            type_allowlist=types,
            trusted_proxies=proxies,
            health_check_dns=health,
            log_level=log_level,
        )


def _fail(problems: list[str], path: Path | None = None) -> None:
    """Log every collected problem once, then exit without a traceback.

    The logged ``error`` and the ``SystemExit`` text both name the file
    that was loaded, then list one problem per line.
    """

    source = CONFIG_PATH if path is None else Path(path)
    body = "\n".join(line for line in problems if line.strip())
    if not body:
        body = "invalid configuration"
    message = f"{source} is invalid:\n{body}"
    from dns_host.logutil import log

    log("error", "invalid configuration", error=message)
    raise SystemExit(message) from None


def _add_error(errors: list[str], key: str, text: object) -> None:
    raw_text = text if isinstance(text, str) else str(text)
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if key not in line:
            line = f"invalid {key}: {line}"
        errors.append(line)


def _guard(errors: list[str], key: str, func: Callable, default):
    try:
        return func()
    except SystemExit as exc:
        detail = exc.code if isinstance(exc.code, str) else exc
        _add_error(errors, key, detail)
    except (ApiError, ValueError, TypeError) as exc:
        _add_error(errors, key, str(exc))
    return default


def _unknown_keys(raw: dict, errors: list[str]) -> None:
    known = sorted(_KNOWN_KEYS)
    for key in sorted(raw, key=str):
        if key in _KNOWN_KEYS:
            continue
        label = key if isinstance(key, str) else str(key)
        matches: list[str] = []
        if isinstance(key, str):
            matches = difflib.get_close_matches(key, known, n=1, cutoff=0.6)
            if not matches:
                matches = difflib.get_close_matches(key.lower(),
                                                    known,
                                                    n=1,
                                                    cutoff=0.6)
        if matches and matches[0] != key:
            errors.append(
                f"unknown key {label!r}: did you mean {matches[0]!r}?")
        else:
            errors.append(f"unknown key {label!r}")


def _map_log_level(raw: dict) -> str:
    if "log_level" not in raw:
        return "info"
    value = raw.get("log_level")
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return "info"
    from dns_host.logutil import parse_log_level

    try:
        return parse_log_level(value)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _map_int(raw: dict, key: str, default: int, low: int, high: int,
             errors: list[str], failed: set[str]) -> int:
    if key not in raw:
        return default
    value = raw.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        failed.add(key)
        if isinstance(value, bool):
            errors.append(
                f"invalid {key} {value!r}: expected an integer from {low} to "
                f"{high}, not a boolean")
        else:
            errors.append(
                f"invalid {key} {value!r}: expected an integer from {low} to "
                f"{high}")
        return default
    if value < low or value > high:
        failed.add(key)
        errors.append(
            f"invalid {key} {value}: expected an integer from {low} to {high}")
        return default
    return value


def _map_bool(raw: dict, key: str, default: bool, errors: list[str]) -> bool:
    """Accept a YAML boolean. Missing and null keep the default."""

    if key not in raw:
        return default
    value = raw.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    errors.append(f"invalid {key} {value!r}: expected a boolean")
    return default


def _map_timeout(raw: dict, errors: list[str]) -> float:
    key = "doh_timeout_seconds"
    if key not in raw or raw.get(key) in (None, ""):
        return 5.0
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"invalid {key} {value!r}: expected a positive number")
        return 5.0
    number = float(value)
    if (number <= 0 or number != number or number == float("inf")
            or number > 300):
        errors.append(
            f"invalid {key} {value!r}: expected a positive number up to 300")
        return 5.0
    return number


def _default_types() -> frozenset:
    return frozenset(item.strip().upper() for item in DEFAULT_TYPES.split(",")
                     if item.strip())


def _known_rr_type(token: str) -> bool:
    ensure_wallet_type()
    try:
        dns.rdatatype.from_text(token)
    except (dns.exception.DNSException, ValueError):
        # This image's dnspython does not know every name the default
        # allow-list already ships (NXNAME, DSYNC, RESINFO).
        return token.strip().upper() in STANDARD_ZONE_TYPES
    return True


def _type_allowlist(raw: dict, errors: list[str]) -> frozenset:
    key = "type_allowlist"
    if not raw.get(key):
        return _default_types()
    value = raw.get(key)
    items: list[str] = []
    bad = False
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple)):
        for item in value:
            if not isinstance(item, str):
                errors.append(
                    f"invalid {key} {item!r}: expected an RR type name")
                bad = True
                continue
            if item.strip():
                items.append(item.strip())
    else:
        errors.append(
            f"invalid {key} {value!r}: expected a list of RR type names")
        return _default_types()
    names: list[str] = []
    for token in items:
        if _known_rr_type(token):
            names.append(token.upper())
            continue
        errors.append(f"invalid {key} {token!r}: unknown RR type")
        bad = True
    if bad or not names:
        return _default_types()
    return frozenset(names)


def _mapping_name(raw: dict, key: str, default: str, errors: list[str]):
    if key not in raw or raw.get(key) in (None, ""):
        text = default
    else:
        value = raw.get(key)
        if not isinstance(value, str):
            errors.append(f"invalid {key} {value!r}: expected a DNS name")
            return None
        text = value
    try:
        return normalise_name(text, what=key)
    except ApiError as exc:
        errors.append(f"invalid {key}: {exc}")
        return None


def _catalog_rname(raw: dict, catalog, errors: list[str]):
    key = "catalog_rname"
    if key not in raw or raw.get(key) in (None, ""):
        if catalog is None:
            return None
        try:
            return normalise_name("hostmaster." + catalog.to_text(), what=key)
        except ApiError as exc:
            errors.append(f"invalid {key}: {exc}")
            return None
    value = raw.get(key)
    if not isinstance(value, str):
        errors.append(f"invalid {key} {value!r}: expected a DNS name")
        return None
    try:
        return normalise_name(value, what=key)
    except ApiError as exc:
        errors.append(f"invalid {key}: {exc}")
        return None


def _resolver_base_url(raw: dict, errors: list[str]) -> str:
    key = "resolver_base_url"
    default = "https://api.isthisyou.org/"
    if key not in raw or raw.get(key) in (None, ""):
        return default
    value = raw.get(key)
    if not isinstance(value, str):
        errors.append(f"invalid {key} {value!r}: expected a string")
        return default
    return value


def _handshake_anchors(raw: dict, errors: list[str]) -> list:
    key = "handshake_trust_anchor_file"
    if key not in raw or raw.get(key) in (None, ""):
        return []
    value = raw.get(key)
    if not isinstance(value, str):
        errors.append(f"invalid {key} {value!r}: expected a path")
        return []
    path = Path(value)
    if not path.is_file():
        errors.append(f"invalid {key}: {path} is not a file")
        return []
    try:
        return load_ds_anchors(path)
    except (OSError, ValueError) as exc:
        errors.append(f"invalid {key}: {exc}")
        return []


def _trusted_proxies(raw: dict, errors: list[str]) -> list:
    key = "trusted_proxies"
    if key not in raw or raw.get(key) in (None, "", []):
        return []
    value = raw.get(key)
    if isinstance(value, str):
        text = value
    elif isinstance(value, (list, tuple)):
        parts: list[str] = []
        for item in value:
            if not isinstance(item, str):
                errors.append(
                    f"invalid {key} {item!r}: expected an IPv4 or IPv6 CIDR "
                    "(a bare address is a /32 or /128)")
                continue
            if item.strip():
                parts.append(item.strip())
        text = ",".join(parts)
    else:
        errors.append(f"invalid {key} {value!r}: expected a list of CIDRs")
        return []
    if not text:
        return []
    return _guard(errors, key, lambda: parse_trusted_proxies(text), [])


def _cross_checks(values: dict[str, int], failed: set[str],
                  errors: list[str]) -> None:

    def ready(*keys: str) -> bool:
        return all(key not in failed for key in keys)

    if ready("min_ttl", "max_ttl") and values["min_ttl"] > values["max_ttl"]:
        errors.append(
            f"invalid min_ttl {values['min_ttl']}: must be less than or equal "
            f"to max_ttl {values['max_ttl']}")
    if (ready("soa_retry", "soa_refresh")
            and values["soa_retry"] > values["soa_refresh"]):
        errors.append(
            f"invalid soa_retry {values['soa_retry']}: must be less than "
            f"or equal to soa_refresh {values['soa_refresh']}")
    if (ready("soa_expire", "soa_refresh")
            and values["soa_expire"] <= values["soa_refresh"]):
        errors.append(
            f"invalid soa_expire {values['soa_expire']}: must be greater than "
            f"soa_refresh {values['soa_refresh']}")
    if (ready("soa_retry", "soa_expire")
            and values["soa_retry"] >= values["soa_expire"]):
        errors.append(
            f"invalid soa_retry {values['soa_retry']}: must be less than "
            f"soa_expire {values['soa_expire']}")
    if (ready("rrsig_min_remaining_seconds", "rrsig_max_lifetime_seconds")
            and values["rrsig_min_remaining_seconds"]
            >= values["rrsig_max_lifetime_seconds"]):
        errors.append(
            "invalid rrsig_min_remaining_seconds "
            f"{values['rrsig_min_remaining_seconds']}: must be less than "
            "rrsig_max_lifetime_seconds "
            f"{values['rrsig_max_lifetime_seconds']}")


def _names_value(value, key: str) -> list:
    if value is None or value == "" or value == []:
        return []
    problems: list[str] = []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple)):
        items = []
        for item in value:
            if isinstance(item, str):
                if item.strip():
                    items.append(item.strip())
                continue
            problems.append(f"invalid {key} {item!r}: expected a DNS name")
    else:
        raise SystemExit(
            f"invalid {key} {value!r}: expected a list of DNS names")
    names = []
    for item in items:
        try:
            names.append(normalise_name(item, what=key))
        except ApiError as exc:
            problems.append(f"invalid {key}: {exc}")
    if problems:
        raise SystemExit("\n".join(problems))
    return names


def _read_secret(item: dict) -> str:
    path = item.get("tsig_secret_file") or ""
    if path:
        if not isinstance(path, str):
            raise SystemExit(
                f"invalid secondaries tsig_secret_file {path!r}: expected a path"
            )
        secret_path = Path(path)
        if not secret_path.is_file():
            raise SystemExit(
                f"invalid secondaries: TSIG secret file {secret_path} is missing"
            )
        return secret_path.read_text(encoding="utf-8").strip()
    secret = item.get("tsig_secret")
    if secret is None or secret == "":
        return ""
    if not isinstance(secret, str):
        raise SystemExit(
            f"invalid secondaries tsig_secret {secret!r}: expected a string")
    return secret


def _take_port(port: object, problems: list[str]) -> int | None:
    if isinstance(
            port,
            bool) or not isinstance(port, int) or port < 1 or port > 65535:
        problems.append(
            f"invalid secondaries port {port!r}: expected an integer from 1 to 65535"
        )
        return None
    return int(port)


def _append_secondary_strings(value: str, out: list,
                              problems: list[str]) -> None:
    try:
        parsed = parse_secondaries(value)
    except (ValueError, TypeError) as exc:
        problems.append(f"invalid secondaries: {exc}")
        return
    for host, port in parsed:
        checked = _take_port(port, problems)
        if checked is None:
            continue
        out.append(Secondary(host, checked))


def _append_secondary_mapping(item: dict, out: list,
                              problems: list[str]) -> None:
    host = str(
        item.get("ip") or item.get("address") or item.get("host")
        or "").strip()
    if not host:
        problems.append("invalid secondaries: a secondary is missing ip")
        return
    try:
        ipaddress.ip_address(host)
    except ValueError:
        problems.append(
            f"invalid secondaries {host!r}: expected an IPv4 or IPv6 address")
        return
    if "port" not in item or item.get("port") in (None, ""):
        port: int | None = 53
    else:
        port = _take_port(item.get("port"), problems)
        if port is None:
            return
    try:
        secret = _read_secret(item)
    except SystemExit as exc:
        text = exc.code if isinstance(exc.code, str) else str(exc)
        problems.append(text if "secondaries" in
                        str(text) else f"invalid secondaries: {text}")
        return
    key_name = item.get("tsig_key_name") or item.get("key_name") or ""
    algo = item.get("tsig_algo") or item.get("algorithm") or "hmac-sha256"
    if not isinstance(key_name, str) or not isinstance(algo, str):
        problems.append(
            "invalid secondaries: TSIG key name and algorithm must be strings")
        return
    out.append(
        Secondary(
            host=host,
            port=port,
            tsig_key_name=key_name,
            tsig_secret=secret,
            tsig_algo=algo,
        ))


def _secondaries_value(value) -> list:
    if value is None or value == "" or value == []:
        return []
    problems: list[str] = []
    out: list = []
    if isinstance(value, str):
        _append_secondary_strings(value, out, problems)
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str):
                _append_secondary_strings(item, out, problems)
                continue
            if isinstance(item, dict):
                _append_secondary_mapping(item, out, problems)
                continue
            problems.append(
                "invalid secondaries: each secondary must be a mapping or an address"
            )
    else:
        problems.append(
            f"invalid secondaries {value!r}: expected a list of addresses")
    if problems:
        raise SystemExit("\n".join(problems))
    return out


def log_effective(settings: Settings) -> None:
    """Log the configuration actually in use. TSIG secrets are not included."""

    from dns_host.logutil import log

    secondaries = []
    for item in settings.secondaries:
        host, port = item[0], item[1]
        secondaries.append({
            "ip":
            host,
            "port":
            port,
            "tsig":
            bool(
                getattr(item, "tsig_key_name", "")
                and getattr(item, "tsig_secret", "")),
        })
    log(
        "info",
        "configuration",
        log_level=settings.log_level,
        service_ns=[name.to_text() for name in settings.service_ns],
        resolver_base_url=settings.resolver_base_url,
        catalog_zone=settings.catalog_zone.to_text()
        if settings.catalog_zone is not None else "",
        secondaries=secondaries,
        axfr_allow=list(settings.axfr_allow),
        grace_days=settings.grace_days,
        dns_bind=DNS_BIND,
        dns_port=DNS_PORT,
        nsd_bind=NSD_BIND,
        nsd_port=NSD_PORT,
        http_port=HTTP_PORT,
        internal_http_port=INTERNAL_HTTP_PORT,
        gunicorn_bind=GUNICORN_BIND,
        data_dir=str(data_dir()),
        trust_anchor_file=str(TRUST_ANCHOR_FILE),
    )
