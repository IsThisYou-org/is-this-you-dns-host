"""A one-label apex is accepted. In-bailiwick NS names are not resolved here."""

import json

import dns.dnssec
import dns.name
import dns.rrset

from dns_host.chain import _walk_from_root
from dns_host.doh import LookupRR, LookupResponse
from dns_host.dnskey_cache import get_process_cache
from dns_host.logutil import set_log_level
from dns_host.names import normalise_apex
from dns_host.pipeline import check_glue, ds_matches, offline_checks
from dns_host.zone import parse_upload
from dns_host.zonesign import generate_key, sign_rrset, signed_zone_document


def _items(rrset):
    rdtype = dns.rdatatype.to_text(rrset.rdtype)
    return [
        LookupRR(name=rrset.name.to_text(),
                 rdtype=rdtype,
                 ttl=int(rrset.ttl),
                 data=rdata.to_text(),
                 wire=rdata.to_wire()) for rdata in rrset
    ]


def _signed(rrset, private, dnskey, signer, inception, expiration):
    sig = sign_rrset(rrset, private, dnskey, signer, inception, expiration)
    sigset = dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)
    return _items(rrset) + _items(sigset)


class Api:
    """Resolver stand-in. No answer_delegation hook, so servers= is used."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def query(self,
              name,
              rdtype,
              *,
              server=None,
              servers=None,
              rd=0,
              do=1,
              cd=None):
        self.calls.append({
            "name": name,
            "type": rdtype,
            "server": server,
            "servers": servers,
            "rd": rd,
            "do": do,
        })
        key = (name, rdtype, server, tuple(servers or ()))
        if key not in self.table:
            return LookupResponse(status=2)
        got = self.table[key]
        if isinstance(got, list):
            return got.pop(0)
        return got


def test_tld_apex_with_in_bailiwick_ns_uses_servers_and_skips_glue(
        env, syslog_lines):
    """example. with NS ns1.example. and no address records in the zone.

    The parent is the root. Root-zone DS and the delegation NS both use
    ``servers=`` set to the walk's root server, including the DS re-check.
    No address query is made for the in-bailiwick nameserver.
    """

    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    apex = normalise_apex("example")
    assert apex.to_text() == "example."
    ns = dns.name.from_text("ns1.example.")
    root = dns.name.root
    root_server = "hs-root.example."

    root_ksk_priv, root_ksk = generate_key(257)
    root_zsk_priv, root_zsk = generate_key(256)
    ksk_priv, ksk = generate_key(257)
    zsk_priv, zsk = generate_key(256)
    _other_priv, other = generate_key(257)

    root_dnskey = dns.rrset.from_rdata(root, 300, root_ksk, root_zsk)
    root_ns = dns.rrset.from_text(root, 300, "IN", "NS", ns.to_text())
    stale = dns.rrset.from_rdata(apex, 300,
                                 dns.dnssec.make_ds(apex, other, "SHA256"))
    fresh = dns.rrset.from_rdata(apex, 300,
                                 dns.dnssec.make_ds(apex, ksk, "SHA256"))
    child_ns = dns.rrset.from_text(apex, 300, "IN", "NS", ns.to_text())

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    table = {
        (".", "DNSKEY", None, (root_server, )):
        LookupResponse(status=0,
                       answer=signed(root_dnskey, root_ksk_priv, root_ksk,
                                     root)),
        (".", "NS", None, (root_server, )):
        LookupResponse(status=0,
                       answer=signed(root_ns, root_zsk_priv, root_zsk, root)),
        ("example.", "NS", None, (root_server, )):
        LookupResponse(status=0, authority=_items(child_ns)),
        ("example.", "DS", None, (root_server, )): [
            LookupResponse(status=0,
                           answer=signed(stale, root_zsk_priv, root_zsk,
                                         root)),
            LookupResponse(status=0,
                           answer=signed(fresh, root_zsk_priv, root_zsk, root),
                           responder="192.0.2.8"),
        ],
    }
    api = Api(table)
    env.settings.service_ns = [ns]
    body = signed_zone_document(
        apex="example.",
        serial=now,
        ns_names=[ns.to_text()],
        ksk_private=ksk_priv,
        ksk=ksk,
        zsk_private=zsk_priv,
        zsk=zsk,
        inception=inception,
        expiration=expiration,
        extras=[],
    )
    zone = parse_upload(body, apex)
    assert "A" not in {item["type"] for item in body["rrsets"]}
    offline_checks(zone, env.settings, None)
    check_glue(zone)

    delegation = _walk_from_root(
        api,
        env.settings,
        apex,
        now,
        anchors=[dns.dnssec.make_ds(root, root_ksk, "SHA256")],
        root_servers=[root_server],
        cache=None,
        root_id="handshake",
    )
    assert delegation.parent_zone == root
    assert [name.to_text() for name in delegation.ns_names] == [ns.to_text()]
    matched = ds_matches(zone, delegation, env.settings, api)
    assert ksk in matched

    address_lookups = [
        call for call in api.calls if call["type"] in {"A", "AAAA"}
    ]
    assert address_lookups == []
    ds_calls = [
        call for call in api.calls
        if call["name"] == "example." and call["type"] == "DS"
    ]
    assert [call["servers"] for call in ds_calls] == [[root_server],
                                                      [root_server]]
    assert all(
        call.get("server") is None and call["rd"] == 0 and call["do"] == 1
        for call in ds_calls)
    logged = [
        json.loads(line) for line in syslog_lines if "parent DS taken" in line
    ]
    assert logged
    assert logged[-1]["responder"] == "192.0.2.8"
