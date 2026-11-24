"""Parent DS/NS results and the hosting-side negative cache."""

import json

import dns.name
import pytest

from dns_host.chain import _query_type, _walk_from_root
from dns_host.dnskey_cache import get_process_cache
from dns_host.doh import LookupError, LookupResponse
from dns_host.errors import ApiError
from dns_host.logutil import set_log_level
from tests.conftest import post


def test_parent_ds_missing_is_cached(env):
    env.lab.publish(ds="missing")
    first = post(env, env.lab.zone())
    assert first.status_code == 403, first.get_json()
    assert first.get_json()["error"] == "parent_ds_missing"
    calls = len(env.lab.calls)
    assert calls > 0
    second = post(env, env.lab.zone(serial=env.clock.t + 1))
    assert second.status_code == 403
    assert second.get_json()["error"] == "parent_ds_missing"
    assert len(env.lab.calls) == calls


def test_parent_ds_mismatch(env):
    env.lab.publish(ds="mismatch")
    response = post(env, env.lab.zone())
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ds_mismatch"
    assert env.lab.calls


def test_parent_ns_incomplete(env):
    env.lab.publish(ns="incomplete")
    response = post(env, env.lab.zone())
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ns_incomplete"


def test_ns_set_mismatch(env):
    env.lab.publish(ns="extra")
    response = post(env, env.lab.zone())
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "ns_set_mismatch"


def test_bad_signature_runs_after_parent_and_ds(env):
    response = post(
        env,
        env.lab.zone(tamper=f"_auth.7e9a2f4c8b1d.{env.lab.apex.to_text()}"))
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "zone_validation_failed"
    assert any(call["type"] == "DS" and call["server"]
               for call in env.lab.calls)


class _RecordingLookup:

    def __init__(self, status=0):
        self.calls = []
        self.status = status

    def query(self, name, rdtype, *, server=None, rd=0, do=1, cd=None):
        self.calls.append({
            "name": name,
            "type": rdtype,
            "server": server,
            "rd": rd,
            "do": do,
            "cd": cd,
        })
        return LookupResponse(status=self.status)


@pytest.mark.parametrize(
    ("name", "rdtype", "servers", "rd", "server"),
    [
        (".", "DNSKEY", [None], 0, None),
        (".", "NS", [None], 0, None),
        ("example.", "DS", ["a.root-servers.net."], 0, "a.root-servers.net."),
        ("me.", "DS", ["a.root-servers.net.", "b.root-servers.net."
                       ], 0, "a.root-servers.net."),
        ("example.", "DNSKEY", ["ns1.example.", "ns2.example."], 1, None),
        ("example.", "NS", ["a.root-servers.net."], 1, None),
        ("me.", "DNSKEY", ["ns1.me."], 1, None),
        ("me.", "NS", ["a.root-servers.net."], 1, None),
        ("user.example.", "DS", ["ns1.example."], 1, None),
        ("user.example.", "NS", ["ns1.example."], 1, None),
        ("isthisyou.me.", "DS", ["ns1.me."], 1, None),
        ("james.isthisyou.me.", "DNSKEY", ["ns1.isthisyou.me."], 1, None),
    ],
)
def test_rd_is_zero_only_for_root_zone_data(env, name, rdtype, servers, rd,
                                            server):
    env.settings.doh_cd = 0
    lookup = _RecordingLookup()
    _query_type(lookup, env.settings, dns.name.from_text(name), rdtype,
                servers)
    assert len(lookup.calls) == 1
    call = lookup.calls[0]
    assert call["name"] == name
    assert call["type"] == rdtype
    assert call["rd"] == rd
    assert call["do"] == 1
    assert call["cd"] == 0
    assert call["server"] == server


def test_tld_dnskey_query_uses_rd1_without_server(env):
    get_process_cache().clear()
    response = post(env, env.lab.zone())
    assert response.status_code == 201, response.get_json()
    dnskeys = [
        call for call in env.lab.calls
        if call["type"] == "DNSKEY" and call["name"] == "example."
    ]
    assert dnskeys, "the walk must fetch the TLD DNSKEY"
    assert all(call["rd"] == 1 and call["do"] == 1 and call["server"] is None
               for call in dnskeys)
    root = [call for call in env.lab.calls if call["name"] == "."]
    assert root
    assert all(call["rd"] == 0 and call["server"] is None
               and call["type"] in {"DNSKEY", "NS"} for call in root)
    tld_ds = [
        call for call in env.lab.calls
        if call["type"] == "DS" and call["name"] == "example."
    ]
    assert tld_ds
    assert all(call["rd"] == 0 and call["server"] == "a.root-servers.net."
               for call in tld_ds)
    below = [
        call for call in env.lab.calls
        if call["name"] not in {".", "example."} or (
            call["name"] == "example." and call["type"] != "DS")
    ]
    assert below
    assert all(call["rd"] == 1 and call["do"] == 1 and call["server"] is None
               for call in below)
    assert all(call["cd"] == env.settings.doh_cd for call in env.lab.calls)


def test_handshake_root_data_uses_rd0_at_the_handshake_server(env):
    server = "hs-root.example."
    for rdtype in ("DNSKEY", "NS"):
        env.lab.responses[(".", rdtype,
                           server)] = env.lab.responses[(".", rdtype, "")]
    env.lab.responses[("example.", "DS",
                       server)] = env.lab.responses[("example.", "DS",
                                                     "a.root-servers.net.")]
    env.lab.calls.clear()
    delegation = _walk_from_root(
        env.lab,
        env.settings,
        env.lab.apex,
        env.settings.now(),
        anchors=[env.lab.root_ds],
        root_server=server,
        cache=None,
        root_id="handshake",
    )
    assert delegation.parent_zone == env.lab.parent
    root_zone = [
        call for call in env.lab.calls if call["name"] == "." or (
            call["name"] == "example." and call["type"] == "DS")
    ]
    assert root_zone
    assert all(call["rd"] == 0 and call["do"] == 1 and call["server"] == server
               for call in root_zone)
    other = [call for call in env.lab.calls if call not in root_zone]
    assert any(call["type"] == "DNSKEY" and call["name"] == "example."
               for call in other)
    assert all(call["rd"] == 1 and call["do"] == 1 and call["server"] is None
               for call in other)


def test_lookup_error_text_is_logged_and_returned(env, capsys):
    set_log_level("info")

    class Boom:

        def __init__(self):
            self.n = 0

        def query(self, name, rdtype, *, server=None, rd=0, do=1, cd=None):
            self.n += 1
            raise LookupError(f"resolver request failed: attempt {self.n}")

    with pytest.raises(ApiError) as raised:
        _query_type(
            Boom(),
            env.settings,
            dns.name.root,
            "DNSKEY",
            ["a.root-servers.net.", "b.root-servers.net."],
        )
    err = raised.value
    assert err.status == 503
    assert err.error == "parent_lookup_unavailable"
    assert err.message == "DNSKEY lookup for . failed: resolver request failed: attempt 2"
    logged = []
    for line in capsys.readouterr().out.splitlines():
        if line.startswith("{"):
            logged.append(json.loads(line))
    warnings = [
        item for item in logged if item.get("msg") == "parent lookup failed"
    ]
    assert [item["error"] for item in warnings] == [
        "resolver request failed: attempt 1",
        "resolver request failed: attempt 2",
    ]
    assert all(item["level"] == "warning" for item in warnings)
