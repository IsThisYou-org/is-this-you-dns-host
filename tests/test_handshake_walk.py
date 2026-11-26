"""Handshake fallback when the ICANN root proves a TLD does not exist.

The DS and the delegation NS at the root are read with ``servers=`` from the
same set. A proved NXDOMAIN on the NS answer is enough to start the
Handshake walk, even if a ``server=`` query would have returned a DS.
"""

import dns.dnssec
import dns.name
import dns.rrset

from dns_host.chain import authenticate_parent
from dns_host.doh import LookupRR, LookupResponse
from dns_host.dnskey_cache import get_process_cache
from dns_host.logutil import set_log_level
from dns_host.zonesign import generate_key, sign_rrset


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

    def __init__(self, decide):
        self.decide = decide
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
        call = {
            "name": name,
            "type": rdtype,
            "server": server,
            "servers": list(servers) if servers else None,
            "rd": rd,
            "do": do,
        }
        self.calls.append(call)
        return self.decide(call)


def _nx(owner_items):
    return LookupResponse(status=3, authority=owner_items)


def test_icann_nxdomain_starts_the_handshake_walk_for_an_sld(
        env, syslog_lines):
    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    root = dns.name.root
    tld = dns.name.from_text("hnstld.")
    apex = dns.name.from_text("example.hnstld.")
    hs = "hs-root.example."
    icann = ["a.root-servers.net.", "b.root-servers.net."]
    synthetic = "synthetic-root.example."

    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)
    hs_ksk_priv, hs_ksk = generate_key(257)
    hs_zsk_priv, hs_zsk = generate_key(256)
    tld_ksk_priv, tld_ksk = generate_key(257)
    tld_zsk_priv, tld_zsk = generate_key(256)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
    hs_dnskey = dns.rrset.from_rdata(root, 300, hs_ksk, hs_zsk)
    hs_ns = dns.rrset.from_text(root, 300, "IN", "NS", synthetic)
    tld_ds = dns.rrset.from_rdata(tld, 300,
                                  dns.dnssec.make_ds(tld, tld_ksk, "SHA256"))
    tld_ns = dns.rrset.from_text(tld, 300, "IN", "NS", "ns1.outside.example.",
                                 "ns2.outside.example.")
    tld_dnskey = dns.rrset.from_rdata(tld, 300, tld_ksk, tld_zsk)
    child_ds = dns.rrset.from_rdata(
        apex, 300, dns.dnssec.make_ds(apex, tld_ksk, "SHA256"))

    icann_denial = _nx(signed(nsec, icann_zsk_priv, icann_zsk, root))

    def decide(call):
        name, rdtype = call["name"], call["type"]
        servers = call["servers"]
        if call["server"]:
            # The merged local root. The walk must not use this for the TLD.
            return LookupResponse(status=0, answer=_items(tld_ds))
        if servers == icann:
            if name == "." and rdtype == "DNSKEY":
                return LookupResponse(status=0,
                                      answer=signed(icann_dnskey,
                                                    icann_ksk_priv, icann_ksk,
                                                    root))
            if name == "." and rdtype == "NS":
                return LookupResponse(status=0,
                                      answer=signed(icann_ns, icann_zsk_priv,
                                                    icann_zsk, root))
            if name == "hnstld.":
                return icann_denial
        if servers == [hs]:
            if name == "." and rdtype == "DNSKEY":
                return LookupResponse(status=0,
                                      answer=signed(hs_dnskey, hs_ksk_priv,
                                                    hs_ksk, root))
            if name == "." and rdtype == "NS":
                return LookupResponse(status=0,
                                      answer=signed(hs_ns, hs_zsk_priv, hs_zsk,
                                                    root))
            if name == "hnstld." and rdtype == "DS":
                return LookupResponse(status=0,
                                      answer=signed(tld_ds, hs_zsk_priv,
                                                    hs_zsk, root))
            if name == "hnstld." and rdtype == "NS":
                return LookupResponse(status=0, authority=_items(tld_ns))
        if name == "hnstld." and rdtype == "DNSKEY" and call["rd"] == 1:
            return LookupResponse(status=0,
                                  answer=signed(tld_dnskey, tld_ksk_priv,
                                                tld_ksk, tld))
        if name == "hnstld." and rdtype == "NS" and call["rd"] == 1:
            return LookupResponse(status=0,
                                  answer=signed(tld_ns, tld_zsk_priv, tld_zsk,
                                                tld))
        if name == "example.hnstld." and rdtype == "DS" and call["rd"] == 1:
            return LookupResponse(status=0,
                                  answer=signed(child_ds, tld_zsk_priv,
                                                tld_zsk, tld))
        if (name == "example.hnstld." and rdtype == "NS" and servers
                == ["ns1.outside.example.", "ns2.outside.example."]):
            return LookupResponse(status=0,
                                  authority=_items(
                                      dns.rrset.from_text(
                                          apex, 300, "IN", "NS",
                                          "ns1.outside.example.",
                                          "ns2.outside.example.")))
        if servers is None and name == "." and rdtype == "NS":
            return LookupResponse(status=0, answer=_items(icann_ns))
        return LookupResponse(status=2)

    api = Api(decide)
    env.settings.trust_anchors = [
        dns.dnssec.make_ds(root, icann_ksk, "SHA256")
    ]
    env.settings.handshake_root_servers = [dns.name.from_text(hs)]
    env.settings.handshake_trust_anchors = [
        dns.dnssec.make_ds(root, hs_ksk, "SHA256")
    ]
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == tld
    assert [name.to_text() for name in delegation.ns_names] == [
        "ns1.outside.example.",
        "ns2.outside.example.",
    ]
    tld_ns_calls = [
        call for call in api.calls if call["name"] == "hnstld."
        and call["type"] == "NS" and call["rd"] == 0
    ]
    assert [call["servers"] for call in tld_ns_calls] == [icann, [hs]]
    assert all(call["server"] is None for call in api.calls)
    logged = [
        line for line in syslog_lines
        if "retrying parent walk from handshake root" in line
    ]
    assert logged
    assert "does not exist" in logged[0]
    assert synthetic not in "".join(str(call["servers"]) for call in api.calls)


def test_handshake_tld_apex_asks_the_root_server_for_delegation(
        env, syslog_lines):
    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    root = dns.name.root
    apex = dns.name.from_text("hnstld.")
    hs = "hs-root.example."
    icann = ["a.root-servers.net.", "b.root-servers.net."]
    synthetic = "synthetic-root.example."

    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)
    hs_ksk_priv, hs_ksk = generate_key(257)
    hs_zsk_priv, hs_zsk = generate_key(256)
    _ksk_priv, ksk = generate_key(257)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
    hs_dnskey = dns.rrset.from_rdata(root, 300, hs_ksk, hs_zsk)
    hs_ns = dns.rrset.from_text(root, 300, "IN", "NS", synthetic)
    fresh = dns.rrset.from_rdata(apex, 300,
                                 dns.dnssec.make_ds(apex, ksk, "SHA256"))
    child_ns = dns.rrset.from_text(apex, 300, "IN", "NS", "ns1.hnstld.")
    denial = _nx(signed(nsec, icann_zsk_priv, icann_zsk, root))

    def decide(call):
        name, rdtype = call["name"], call["type"]
        servers = call["servers"]
        if servers == icann and name == "hnstld.":
            return denial
        if servers == icann and name == "." and rdtype == "DNSKEY":
            return LookupResponse(status=0,
                                  answer=signed(icann_dnskey, icann_ksk_priv,
                                                icann_ksk, root))
        if servers == icann and name == "." and rdtype == "NS":
            return LookupResponse(status=0,
                                  answer=signed(icann_ns, icann_zsk_priv,
                                                icann_zsk, root))
        if servers == [hs] and name == "." and rdtype == "DNSKEY":
            return LookupResponse(status=0,
                                  answer=signed(hs_dnskey, hs_ksk_priv, hs_ksk,
                                                root))
        if servers == [hs] and name == "." and rdtype == "NS":
            return LookupResponse(status=0,
                                  answer=signed(hs_ns, hs_zsk_priv, hs_zsk,
                                                root))
        if servers == [hs] and name == "hnstld." and rdtype == "DS":
            return LookupResponse(status=0,
                                  answer=signed(fresh, hs_zsk_priv, hs_zsk,
                                                root))
        if servers == [hs] and name == "hnstld." and rdtype == "NS":
            return LookupResponse(status=0, authority=_items(child_ns))
        if servers is None and name == "." and rdtype == "NS":
            return LookupResponse(status=0, answer=_items(icann_ns))
        return LookupResponse(status=2)

    api = Api(decide)
    env.settings.trust_anchors = [
        dns.dnssec.make_ds(root, icann_ksk, "SHA256")
    ]
    env.settings.handshake_root_servers = [dns.name.from_text(hs)]
    env.settings.handshake_trust_anchors = [
        dns.dnssec.make_ds(root, hs_ksk, "SHA256")
    ]
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == root
    assert [name.to_text() for name in delegation.ns_names] == ["ns1.hnstld."]
    assert delegation.parent_servers == [hs]
    ns_calls = [
        call for call in api.calls
        if call["name"] == "hnstld." and call["type"] == "NS"
    ]
    assert [call["servers"] for call in ns_calls] == [icann, [hs]]
    assert synthetic not in "".join(str(call["servers"]) for call in api.calls)
    assert any("retrying parent walk from handshake root" in line
               for line in syslog_lines)
