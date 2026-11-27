"""Handshake fallback when the ICANN root returns NXDOMAIN for a TLD.

The TLD DS and NS are then read with ``rd=0`` and no server. Those RRsets
are trusted without a root signature. A further NXDOMAIN keeps the ICANN
``parent_ds_missing`` error.
"""

import pytest

import dns.dnssec
import dns.name
import dns.rrset

from dns_host.chain import TldMissingAtRoot, _tld_missing, authenticate_parent
from dns_host.doh import LookupRR, LookupResponse
from dns_host.dnskey_cache import get_process_cache
from dns_host.errors import ApiError
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
    icann = ["a.root-servers.net.", "b.root-servers.net."]

    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)
    tld_ksk_priv, tld_ksk = generate_key(257)
    tld_zsk_priv, tld_zsk = generate_key(256)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
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
            return LookupResponse(status=2)
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
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "DS"):
            # Unsigned. The Handshake anchor does not need a root signature.
            return LookupResponse(status=0,
                                  answer=_items(tld_ds),
                                  responder="192.0.2.8")
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "NS"):
            return LookupResponse(status=0, answer=_items(tld_ns))
        if name == "hnstld." and rdtype == "DNSKEY" and call["rd"] == 0:
            return LookupResponse(status=0,
                                  answer=signed(tld_dnskey, tld_ksk_priv,
                                                tld_ksk, tld))
        if name == "hnstld." and rdtype == "NS" and call["rd"] == 0:
            return LookupResponse(status=0,
                                  answer=signed(tld_ns, tld_zsk_priv, tld_zsk,
                                                tld))
        if name == "example.hnstld." and rdtype == "DS" and call["rd"] == 0:
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
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == tld
    assert [name.to_text() for name in delegation.ns_names] == [
        "ns1.outside.example.",
        "ns2.outside.example.",
    ]
    plain = [
        call for call in api.calls if call["name"] == "hnstld."
        and call["rd"] == 0 and not call["servers"] and call["server"] is None
    ]
    assert [call["type"] for call in plain] == ["DS", "NS"]
    assert all(call["do"] == 1 for call in plain)
    assert all(call["server"] is None for call in api.calls)
    logged = [line for line in syslog_lines if "handshake fallback" in line]
    assert logged
    assert "does not exist" in logged[0]
    assert "192.0.2.8" in logged[0]


def test_handshake_tld_apex_trusts_ds_and_ns_without_a_root_key(
        env, syslog_lines):
    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    root = dns.name.root
    apex = dns.name.from_text("hnstld.")
    icann = ["a.root-servers.net.", "b.root-servers.net."]

    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)
    other_priv, other_key = generate_key(256)
    _ksk_priv, ksk = generate_key(257)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
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
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "DS"):
            # Signed by a key that is not the ICANN root. It must still be trusted.
            return LookupResponse(status=0,
                                  answer=signed(fresh, other_priv, other_key,
                                                root),
                                  responder="192.0.2.9")
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "NS"):
            return LookupResponse(status=0, authority=_items(child_ns))
        if servers is None and name == "." and rdtype == "NS":
            return LookupResponse(status=0, answer=_items(icann_ns))
        return LookupResponse(status=2)

    api = Api(decide)
    env.settings.trust_anchors = [
        dns.dnssec.make_ds(root, icann_ksk, "SHA256")
    ]
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == root
    assert [name.to_text() for name in delegation.ns_names] == ["ns1.hnstld."]
    assert delegation.parent_servers is None
    plain = [
        call for call in api.calls if call["name"] == "hnstld."
        and call["rd"] == 0 and not call["servers"]
    ]
    assert [call["type"] for call in plain] == ["DS", "NS"]
    assert all(call["do"] == 1 and call["server"] is None for call in plain)
    assert not any(call["type"] == "DNSKEY" and not call["servers"]
                   for call in api.calls)
    logged = [line for line in syslog_lines if "handshake fallback" in line]
    assert logged
    assert "192.0.2.9" in logged[0]


def test_tld_missing_is_the_exception_type_not_the_message():
    same_words = ApiError(403, "parent_ds_missing",
                          "webmail. does not exist under .")
    other_words = TldMissingAtRoot(403, "parent_chain_invalid",
                                   "parent served no delegation for webmail.",
                                   dns.name.from_text("webmail."))
    assert _tld_missing(same_words) is False
    assert _tld_missing(other_words) is True


def test_icann_ds_nxdomain_starts_the_handshake_walk(env, syslog_lines):
    """DS NXDOMAIN at the ICANN root starts the Handshake walk.

    The NS answer is NOERROR with no delegation, so the ICANN error is
    ``parent served no delegation`` and does not say the name does not
    exist. The DS status alone selects the no-server Handshake read.
    """

    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    root = dns.name.root
    tld = dns.name.from_text("hnstld.")
    apex = dns.name.from_text("example.hnstld.")
    icann = ["a.root-servers.net.", "b.root-servers.net."]

    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)
    tld_ksk_priv, tld_ksk = generate_key(257)
    tld_zsk_priv, tld_zsk = generate_key(256)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    tld_ds = dns.rrset.from_rdata(tld, 300,
                                  dns.dnssec.make_ds(tld, tld_ksk, "SHA256"))
    tld_ns = dns.rrset.from_text(tld, 300, "IN", "NS", "ns1.outside.example.",
                                 "ns2.outside.example.")
    child_ns = dns.rrset.from_text(apex, 300, "IN", "NS",
                                   "ns1.outside.example.",
                                   "ns2.outside.example.")
    tld_dnskey = dns.rrset.from_rdata(tld, 300, tld_ksk, tld_zsk)
    child_ds = dns.rrset.from_rdata(
        apex, 300, dns.dnssec.make_ds(apex, tld_ksk, "SHA256"))

    def decide(call):
        name, rdtype = call["name"], call["type"]
        servers = call["servers"]
        if servers == icann and name == "." and rdtype == "DNSKEY":
            return LookupResponse(status=0,
                                  answer=signed(icann_dnskey, icann_ksk_priv,
                                                icann_ksk, root))
        if servers == icann and name == "." and rdtype == "NS":
            return LookupResponse(status=0,
                                  answer=signed(icann_ns, icann_zsk_priv,
                                                icann_zsk, root))
        if servers == icann and name == "hnstld." and rdtype == "DS":
            return LookupResponse(status=3)
        if servers == icann and name == "hnstld." and rdtype == "NS":
            return LookupResponse(status=0)
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "DS"):
            return LookupResponse(status=0, answer=_items(tld_ds))
        if (servers is None and call["rd"] == 0 and name == "hnstld."
                and rdtype == "NS"):
            return LookupResponse(status=0, authority=_items(tld_ns))
        if name == "hnstld." and rdtype == "DNSKEY" and call["rd"] == 0:
            return LookupResponse(status=0,
                                  answer=signed(tld_dnskey, tld_ksk_priv,
                                                tld_ksk, tld))
        if name == "hnstld." and rdtype == "NS" and call["rd"] == 0:
            return LookupResponse(status=0,
                                  answer=signed(tld_ns, tld_zsk_priv, tld_zsk,
                                                tld))
        if name == "example.hnstld." and rdtype == "DS" and call["rd"] == 0:
            return LookupResponse(status=0,
                                  answer=signed(child_ds, tld_zsk_priv,
                                                tld_zsk, tld))
        if (name == "example.hnstld." and rdtype == "NS" and servers
                == ["ns1.outside.example.", "ns2.outside.example."]):
            return LookupResponse(status=0, authority=_items(child_ns))
        if servers is None and name == "." and rdtype == "NS":
            return LookupResponse(status=0, answer=_items(icann_ns))
        return LookupResponse(status=2)

    api = Api(decide)
    env.settings.trust_anchors = [
        dns.dnssec.make_ds(root, icann_ksk, "SHA256")
    ]
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == tld
    plain = [
        call for call in api.calls if call["name"] == "hnstld."
        and call["rd"] == 0 and not call["servers"] and call["server"] is None
    ]
    assert [call["type"] for call in plain] == ["DS", "NS"]
    logged = [line for line in syslog_lines if "handshake fallback" in line]
    assert logged
    assert "parent served no delegation" in logged[0]
    assert "does not exist" not in logged[0]


def test_handshake_nxdomain_keeps_the_icann_error(env, syslog_lines):
    set_log_level("info")
    get_process_cache().clear()
    now = env.settings.now()
    inception, expiration = now - 120, now + 10 * 86400
    root = dns.name.root
    apex = dns.name.from_text("example.hnstld.")
    icann = ["a.root-servers.net.", "b.root-servers.net."]
    icann_ksk_priv, icann_ksk = generate_key(257)
    icann_zsk_priv, icann_zsk = generate_key(256)

    def signed(rrset, private, dnskey, signer):
        return _signed(rrset, private, dnskey, signer, inception, expiration)

    icann_dnskey = dns.rrset.from_rdata(root, 300, icann_ksk, icann_zsk)
    icann_ns = dns.rrset.from_text(root, 300, "IN", "NS", *icann)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
    denial = _nx(signed(nsec, icann_zsk_priv, icann_zsk, root))

    def decide(call):
        name, rdtype = call["name"], call["type"]
        servers = call["servers"]
        if servers == icann and name == "." and rdtype == "DNSKEY":
            return LookupResponse(status=0,
                                  answer=signed(icann_dnskey, icann_ksk_priv,
                                                icann_ksk, root))
        if servers == icann and name == "." and rdtype == "NS":
            return LookupResponse(status=0,
                                  answer=signed(icann_ns, icann_zsk_priv,
                                                icann_zsk, root))
        if servers == icann and name == "hnstld.":
            return denial
        if (servers is None and call["rd"] == 0 and name == "hnstld."):
            return LookupResponse(status=3, responder="192.0.2.10")
        if servers is None and name == "." and rdtype == "NS":
            return LookupResponse(status=0, answer=_items(icann_ns))
        return LookupResponse(status=2)

    api = Api(decide)
    env.settings.trust_anchors = [
        dns.dnssec.make_ds(root, icann_ksk, "SHA256")
    ]
    with pytest.raises(TldMissingAtRoot) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_ds_missing"
    assert raised.value.message == "hnstld. does not exist under ."
    logged = [line for line in syslog_lines if "handshake fallback" in line]
    assert logged
    assert "192.0.2.10" in logged[0]
    assert "does not exist" in logged[0]
