"""Maintainer zone-push tool: zone file to upload JSON, and the HTTP POST."""

from __future__ import annotations

import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from dns_host.dns_server import DnsServer
from dns_host.names import normalise_apex
from dns_host.zone import parse_upload
from tests.conftest import post

_TOOL = Path(__file__).resolve().parents[1] / "tools" / "zone_push.py"
_spec = importlib.util.spec_from_file_location("zone_push", _TOOL)
zone_push = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zone_push)


def _wires(parsed) -> set[tuple]:
    found = set()
    for (name, rdtype), rrset in parsed.rrsets.items():
        found.add((name.to_text(), int(rdtype), tuple(item.to_wire() for item in rrset)))
    for (name, covered), rrset in parsed.sigs.items():
        found.add((name.to_text(), f"RRSIG {int(covered)}", tuple(item.to_wire() for item in rrset)))
    return found


def _master(document: dict) -> str:
    lines = [f"$ORIGIN {document['apex']}", "$TTL 300"]
    for item in document["rrsets"]:
        for rdata in item["rrdatas"]:
            lines.append(f"{item['name']} {item['ttl']} IN {item['type']} {rdata}")
    return "\n".join(lines) + "\n"


def _write(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "zone.txt"
    path.write_text(_master(document), encoding="utf-8")
    return path


def test_zone_file_round_trips_through_the_upload_parser(tmp_path, lab):
    apex_name = lab.apex.to_text()
    document = lab.zone(
        extras=[
            (f"_auth.7e9a2f4c8b1d.{apex_name}", "TXT", ['"v=dnsauth1 alg=ES256 k=example"']),
            (apex_name, "URI", ['10 1 "https://example.org/j"']),
            (apex_name, "WALLET", ['"btc" "bc1qexampleaddress"']),
        ]
    )
    loaded = zone_push.load_zone_file(_write(tmp_path, document))
    uploaded = zone_push.zone_to_upload(loaded)
    apex = normalise_apex(uploaded["apex"])
    assert zone_push.soa_serial(uploaded) == lab.now
    assert _wires(parse_upload(document, apex)) == _wires(parse_upload(uploaded, apex))

    updated = lab.zone(serial=lab.now + 10, extras=[(apex_name, "TXT", ['"second"'])])
    second = zone_push.zone_to_upload(zone_push.load_zone_file(_write(tmp_path, updated), apex_name))
    assert zone_push.soa_serial(second) == lab.now + 10
    assert _wires(parse_upload(updated, apex)) == _wires(parse_upload(second, apex))


def test_dry_run_prints_json_and_does_not_connect(tmp_path, lab, capsys):
    path = _write(tmp_path, lab.zone())
    code = zone_push.main(
        ["--zone-file", str(path), "--dry-run", "--base-url", "http://127.0.0.1:1", "--request-id", "dry-1"]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "request_id: dry-1" in captured.err
    body = json.loads(captured.out)
    assert body["kind"] == "dnsauth#signedZone"
    assert body["apex"] == lab.apex.to_text()
    assert "HTTP" not in captured.out


def test_post_prints_the_service_error_body(tmp_path, lab, capsys):
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            seen["path"] = self.path
            seen["body"] = json.loads(self.rfile.read(length).decode())
            payload = json.dumps(
                {"error": "apex_ns_incomplete", "message": "apex NS is missing a service nameserver"}
            ).encode()
            self.send_response(422)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path = _write(tmp_path, lab.zone())
        code = zone_push.main(
            [
                "--zone-file",
                str(path),
                "--base-url",
                f"http://127.0.0.1:{port}",
                "--request-id",
                "post-422",
            ]
        )
    finally:
        server.shutdown()
    captured = capsys.readouterr()
    assert code == 1
    assert seen["path"] == "/api/v1/zones/user.example"
    assert seen["body"]["kind"] == "dnsauth#signedZone"
    assert "request_id: post-422" in captured.out
    assert "HTTP 422" in captured.out
    assert "apex_ns_incomplete" in captured.out
    assert "missing a service nameserver" in captured.out


def test_axfr_input_and_soa_check(env, tmp_path, capsys):
    document = env.lab.zone()
    assert post(env, document).status_code == 201
    server = DnsServer(env.settings, env.store)
    server.start()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload_in = json.loads(self.rfile.read(length).decode())
            self.server.serial = zone_push.soa_serial(payload_in)
            body = json.dumps(
                {"apex": payload_in["apex"], "serial": self.server.serial, "catalogUpdated": False}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    import threading

    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        code = zone_push.main(
            [
                "--axfr-zone",
                "user.example.",
                "--axfr-server",
                "127.0.0.1",
                "--axfr-port",
                str(server.port),
                "--base-url",
                f"http://127.0.0.1:{http.server_address[1]}",
                "--verify",
                "--dns-server",
                "127.0.0.1",
                "--dns-port",
                str(server.port),
                "--verify-timeout",
                "5",
                "--request-id",
                "axfr-1",
            ]
        )
    finally:
        http.shutdown()
        server.stop()
    captured = capsys.readouterr()
    assert code == 0, captured.out
    assert "HTTP 200" in captured.out
    assert f"SOA serial {env.lab.now} matches 127.0.0.1:{server.port}" in captured.out


def test_tsig_keyring_uses_the_named_algorithm():
    import dns.name
    import dns.tsig

    ring, owner, algorithm = zone_push.build_tsig(
        "transfer.example.",
        "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2U=",
        "hmac-sha256",
    )
    assert owner == dns.name.from_text("transfer.example.")
    assert algorithm == dns.tsig.HMAC_SHA256
    assert ring


def test_missing_soa_is_reported(tmp_path):
    path = tmp_path / "empty.zone"
    path.write_text("$ORIGIN example.\nwww 300 IN A 192.0.2.1\n", encoding="utf-8")
    with pytest.raises(zone_push.ZonePushError, match="no SOA"):
        zone_push.soa_serial(zone_push.zone_to_upload(zone_push.load_zone_file(path)))
