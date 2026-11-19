#!/usr/bin/env python3
"""Push an already-signed zone to the hosting service.

This is a maintainer tool. It does not run inside the container and it does
not change admission. It turns a master file, or an AXFR, into the
``dnsauth#signedZone`` JSON document and POSTs that document.

The service accepts a full zone only: ``POST /api/v1/zones/{apex}``.

Run it from a checkout with dnspython installed (``pip install -r
requirements.txt`` is enough). MIT licensed, same as the rest of this
repository.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.zone

WALLET_TYPE = 262

_TSIG_ALGORITHMS = {
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


def ensure_wallet_type() -> None:
    """Let presentation text say WALLET when this dnspython build lacks it."""

    try:
        if int(dns.rdatatype.from_text("WALLET")) == WALLET_TYPE:
            return
    except Exception:
        pass
    dns.rdatatype.register_type(WALLET_TYPE, "WALLET")


class ZonePushError(Exception):
    """The tool could not build or check a zone. The service was not changed."""


def _origin_from_text(text: str) -> dns.name.Name | None:
    for line in text.splitlines():
        stripped = line.split(";", 1)[0].strip()
        if not stripped.upper().startswith("$ORIGIN"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            return dns.name.from_text(parts[1])
    return None


def load_zone_file(path: str | Path, apex: str | None = None) -> dns.zone.Zone:
    """Read a master-format zone file. ``apex`` overrides ``$ORIGIN``."""

    raw = Path(path).read_text(encoding="utf-8")
    if apex:
        origin = dns.name.from_text(apex if apex.endswith(".") else apex + ".")
    else:
        origin = _origin_from_text(raw)
        if origin is None:
            raise ZonePushError("zone file has no $ORIGIN; pass --apex")
    try:
        return dns.zone.from_text(raw, origin=origin, relativize=False, check_origin=False)
    except dns.exception.DNSException as exc:
        raise ZonePushError(f"could not read the zone file: {exc}") from exc


def build_tsig(key_name: str, secret: str, algorithm: str):
    """Return ``(keyring, keyname, algorithm)`` for dnspython AXFR."""

    algo = _TSIG_ALGORITHMS.get(algorithm.strip().lower())
    if algo is None:
        known = ", ".join(sorted(_TSIG_ALGORITHMS))
        raise ZonePushError(f"TSIG algorithm {algorithm!r} is not one of {known}")
    owner = dns.name.from_text(key_name if key_name.endswith(".") else key_name + ".")
    try:
        ring = dns.tsigkeyring.from_text({owner.to_text(): secret})
    except Exception as exc:
        raise ZonePushError(f"TSIG secret is not valid base64: {exc}") from exc
    for name, key in list(ring.items()):
        raw = key.secret if hasattr(key, "secret") else key
        ring[name] = dns.tsig.Key(name, raw, algo)
    return ring, owner, algo


def load_axfr(
    zone_name: str,
    server: str,
    port: int,
    *,
    timeout: float = 10,
    tsig_key_name: str = "",
    tsig_secret: str = "",
    tsig_algo: str = "hmac-sha256",
) -> dns.zone.Zone:
    """AXFR ``zone_name`` from ``server`` and return it as a zone object."""

    apex = zone_name if zone_name.endswith(".") else zone_name + "."
    kwargs = {"port": int(port), "timeout": timeout, "relativize": False}
    if tsig_key_name or tsig_secret:
        if not tsig_key_name or not tsig_secret:
            raise ZonePushError("TSIG needs both --tsig-key-name and --tsig-secret")
        keyring, keyname, algorithm = build_tsig(tsig_key_name, tsig_secret, tsig_algo)
        kwargs["keyring"] = keyring
        kwargs["keyname"] = keyname
        kwargs["keyalgorithm"] = algorithm
    try:
        messages = dns.query.xfr(server, apex, **kwargs)
        return dns.zone.from_xfr(messages, zone_factory=dns.zone.Zone, relativize=False)
    except Exception as exc:
        raise ZonePushError(f"AXFR of {apex} from {server}:{port} failed: {exc}") from exc


def zone_to_upload(zone: dns.zone.Zone) -> dict:
    """Convert a signed zone into the service's upload document.

    Every RRset is kept, including DNSSEC records. Presentation text uses
    absolute names so the service does not treat them as relative to the apex.
    """

    ensure_wallet_type()
    if zone.origin is None:
        raise ZonePushError("zone has no origin")
    origin = zone.origin
    # dnspython keeps one RRSIG rdataset per covered type. The upload API
    # wants a single RRSIG RRset per owner, which is how a master file is
    # written and how the service parses it.
    grouped: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for name in sorted(zone.nodes, key=lambda item: tuple(reversed(item.canonicalize().labels))):
        node = zone.nodes[name]
        absolute = name if name.is_absolute() else name.derelativize(origin)
        for rdataset in node.rdatasets:
            if int(rdataset.rdclass) != int(dns.rdataclass.IN):
                continue
            texts = [rdata.to_text(origin=origin, relativize=False) for rdata in rdataset]
            if not texts:
                continue
            type_name = dns.rdatatype.to_text(rdataset.rdtype)
            if int(rdataset.rdtype) == WALLET_TYPE:
                type_name = "WALLET"
            key = (absolute.to_text(), type_name)
            bucket = grouped.get(key)
            if bucket is None:
                grouped[key] = {
                    "kind": "dns#resourceRecordSet",
                    "name": key[0],
                    "type": type_name,
                    "ttl": int(rdataset.ttl),
                    "rrdatas": texts,
                }
                order.append(key)
                continue
            if int(bucket["ttl"]) != int(rdataset.ttl):
                raise ZonePushError(f"{key[0]} {type_name} has more than one TTL")
            bucket["rrdatas"].extend(texts)
    if not grouped:
        raise ZonePushError("zone has no IN records")
    return {
        "kind": "dnsauth#signedZone",
        "apex": origin.to_text(),
        "rrsets": [grouped[key] for key in order],
    }


def soa_serial(document: dict) -> int:
    apex = document["apex"].lower()
    for item in document["rrsets"]:
        if item["name"].lower() == apex and item["type"].upper() == "SOA":
            if len(item["rrdatas"]) != 1:
                raise ZonePushError("apex SOA must contain exactly one record")
            parts = item["rrdatas"][0].split()
            if len(parts) < 3 or not parts[2].isdigit():
                raise ZonePushError("apex SOA serial is missing")
            return int(parts[2])
    raise ZonePushError("zone has no SOA at the apex")


def post_zone(base_url: str, document: dict, *, timeout: float = 60) -> tuple[int, str]:
    """POST the document. Returns ``(status, body)`` even when the status is an error."""

    apex = document["apex"].rstrip(".")
    quoted = urllib.parse.quote(apex, safe=".-")
    url = base_url.rstrip("/") + "/api/v1/zones/" + quoted
    payload = json.dumps(document).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def format_body(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    try:
        return json.dumps(json.loads(stripped), indent=2, sort_keys=True)
    except json.JSONDecodeError:
        return stripped


def query_soa_serial(server: str, port: int, apex: str, *, timeout: float = 2) -> int | None:
    query = dns.message.make_query(apex, dns.rdatatype.SOA)
    try:
        response = dns.query.udp(query, server, port=int(port), timeout=timeout)
    except Exception:
        return None
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.SOA and len(rrset) == 1:
            return int(list(rrset)[0].serial)
    return None


def wait_for_serial(
    server: str,
    port: int,
    apex: str,
    expected: int,
    *,
    timeout: float,
) -> int | None:
    deadline = time.monotonic() + timeout
    seen: int | None = None
    while True:
        seen = query_soa_serial(server, port, apex)
        if seen == expected:
            return seen
        if time.monotonic() >= deadline:
            return seen
        time.sleep(0.4)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Convert a signed zone to the hosting service's upload JSON and POST it. "
            "The service replaces the whole zone; this tool does not edit records itself."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--zone-file", help="Master-format zone file, already signed")
    source.add_argument("--axfr-zone", help="Zone name to AXFR from --axfr-server")
    parser.add_argument("--apex", help="Zone apex if the file has no $ORIGIN")
    parser.add_argument("--axfr-server", default="127.0.0.1", help="AXFR server address (default 127.0.0.1)")
    parser.add_argument("--axfr-port", type=int, default=53, help="AXFR server port (default 53)")
    parser.add_argument("--tsig-key-name", default="", help="Optional TSIG key name for the AXFR")
    parser.add_argument("--tsig-secret", default="", help="Optional TSIG secret, standard base64")
    parser.add_argument("--tsig-algo", default="hmac-sha256", help="TSIG algorithm (default hmac-sha256)")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:80",
        help="Service base URL (default http://127.0.0.1:80). The POST path is /api/v1/zones/{apex}.",
    )
    parser.add_argument("--timeout", type=float, default=60, help="HTTP and AXFR timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print the upload JSON and do not POST")
    parser.add_argument("--verify", action="store_true", help="After a successful POST, query NSD for the SOA serial")
    parser.add_argument("--dns-server", default="127.0.0.1", help="NSD address for --verify (default 127.0.0.1)")
    parser.add_argument("--dns-port", type=int, default=53, help="NSD port for --verify (default 53)")
    parser.add_argument("--verify-timeout", type=float, default=20, help="Seconds to wait for the SOA serial")
    parser.add_argument(
        "--request-id",
        default="",
        help="Identifier printed with the result, so a failed run is easy to refer to",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    request_id = args.request_id.strip() or uuid.uuid4().hex
    try:
        if args.zone_file:
            loaded = load_zone_file(args.zone_file, args.apex)
        else:
            loaded = load_axfr(
                args.axfr_zone,
                args.axfr_server,
                args.axfr_port,
                timeout=args.timeout,
                tsig_key_name=args.tsig_key_name,
                tsig_secret=args.tsig_secret,
                tsig_algo=args.tsig_algo,
            )
        document = zone_to_upload(loaded)
        serial = soa_serial(document)
    except (ZonePushError, OSError) as exc:
        print(f"request_id: {request_id}", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"request_id: {request_id}", file=sys.stderr)
        json.dump(document, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    try:
        status, body = post_zone(args.base_url, document, timeout=args.timeout)
    except urllib.error.URLError as exc:
        print(f"request_id: {request_id}")
        print(f"HTTP request failed: {exc.reason}")
        return 1

    print(f"request_id: {request_id}")
    print(f"apex: {document['apex']}")
    print(f"soa_serial: {serial}")
    print(f"HTTP {status}")
    formatted = format_body(body)
    if formatted:
        print(formatted)
    if status not in (200, 201):
        return 1
    if not args.verify:
        return 0
    seen = wait_for_serial(
        args.dns_server,
        args.dns_port,
        document["apex"],
        serial,
        timeout=args.verify_timeout,
    )
    if seen == serial:
        print(f"SOA serial {serial} matches {args.dns_server}:{args.dns_port}")
        return 0
    if seen is None:
        print(f"NSD at {args.dns_server}:{args.dns_port} did not answer SOA for {document['apex']}")
    else:
        print(f"SOA serial mismatch: uploaded {serial}, NSD answered {seen}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
