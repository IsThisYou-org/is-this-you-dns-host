"""One validation algorithm, two trust inputs.

The signed material is generated here. Nothing is copied from a live zone.
"""

import pytest

import dns.dnssec
import dns.name
import dns.rrset

from dns_host.chain import (
    BadSignature,
    DsMismatch,
    DsNotAuthenticated,
    ExpiredSignature,
    TldMissingAtRoot,
    authenticate_parent,
)
from dns_host.dnskey_cache import get_process_cache
from dns_host.doh import LookupRR, LookupResponse
from dns_host.zonesign import generate_key, sign_rrset

ROOT_SERVER = "a.root-servers.net."
TLD_NS = "ns1.hnstld."


def _items(rrset, sigset=None):
    rows = []
    for item in (rrset, sigset):
        if item is None:
            continue
        rdtype = dns.rdatatype.to_text(item.rdtype)
        rows.extend(
            LookupRR(name=item.name.to_text(),
                     rdtype=rdtype,
                     ttl=int(item.ttl),
                     data=rdata.to_text(),
                     wire=rdata.to_wire()) for rdata in item)
    return rows


def _signed(rrset, private, dnskey, signer, inception, expiration):
    sig = sign_rrset(rrset, private, dnskey, signer, inception, expiration)
    return rrset, dns.rrset.from_rdata(rrset.name, rrset.ttl, sig)


class Api:

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
              cd=None,
              tcp=False):
        self.calls.append({
            "name": name,
            "type": rdtype,
            "server": server,
            "servers": list(servers) if servers else None,
            "rd": rd,
            "do": do,
            "tcp": tcp,
        })
        key = (name, rdtype, tuple(servers) if servers else None)
        return self.table.get(key, LookupResponse(status=2))


def _chain(now, *, mode, fault):
    """Return ``(api, anchors, apex)`` for ``mode`` and ``fault``."""

    root = dns.name.root
    tld = dns.name.from_text("hnstld.")
    apex = dns.name.from_text("example.hnstld.")
    inception, expiration = now - 120, now + 10 * 86400
    root_ksk_priv, root_ksk = generate_key(257)
    root_zsk_priv, root_zsk = generate_key(256)
    tld_ksk_priv, tld_ksk = generate_key(257)
    tld_zsk_priv, tld_zsk = generate_key(256)
    child_ksk_priv, child_ksk = generate_key(257)

    def signed(rrset, private, dnskey, signer, window=None):
        start, end = window or (inception, expiration)
        return _signed(rrset, private, dnskey, signer, start, end)

    def answer(rrset, sigset):
        return LookupResponse(status=0, answer=_items(rrset, sigset))

    root_dnskey = dns.rrset.from_rdata(root, 300, root_ksk, root_zsk)
    root_ns = dns.rrset.from_text(root, 300, "IN", "NS", ROOT_SERVER)
    tld_dnskey = dns.rrset.from_rdata(tld, 300, tld_ksk, tld_zsk)
    tld_ns = dns.rrset.from_text(tld, 300, "IN", "NS", TLD_NS)
    tld_ds = dns.rrset.from_rdata(tld, 300,
                                  dns.dnssec.make_ds(tld, tld_ksk, "SHA256"))
    child_ds = dns.rrset.from_rdata(
        apex, 300, dns.dnssec.make_ds(apex, child_ksk, "SHA256"))
    child_ns = dns.rrset.from_text(apex, 300, "IN", "NS",
                                   "ns1.outside.example.")

    if fault == "mismatch":
        _priv, other = generate_key(257)
        tld_dnskey = dns.rrset.from_rdata(tld, 300, other, tld_zsk)
        tld_ksk_priv, tld_ksk = generate_key(257)
    if fault == "bad-signature":
        _priv, other = generate_key(256)
        child_signed = signed(child_ds, _priv, other, tld)
    elif fault == "expired":
        child_signed = signed(child_ds, tld_zsk_priv, tld_zsk, tld,
                              (now - 86400, now - 60))
    else:
        child_signed = signed(child_ds, tld_zsk_priv, tld_zsk, tld)

    root_key_rr, root_key_sig = signed(root_dnskey, root_ksk_priv, root_ksk,
                                       root)
    root_ns_rr, root_ns_sig = signed(root_ns, root_zsk_priv, root_zsk, root)
    tld_ds_rr, tld_ds_sig = signed(tld_ds, root_zsk_priv, root_zsk, root)
    tld_key_rr, tld_key_sig = signed(tld_dnskey, tld_ksk_priv, tld_ksk, tld)
    tld_ns_rr, tld_ns_sig = signed(tld_ns, tld_zsk_priv, tld_zsk, tld)
    nsec = dns.rrset.from_text("h.", 300, "IN", "NSEC",
                               "i. NS SOA RRSIG NSEC DNSKEY")
    nsec_rr, nsec_sig = signed(nsec, root_zsk_priv, root_zsk, root)
    denial = LookupResponse(status=3, authority=_items(nsec_rr, nsec_sig))

    root_pair = (ROOT_SERVER, )
    tld_pair = (TLD_NS, )
    table = {
        (".", "NS", None):
        LookupResponse(status=0, answer=_items(root_ns)),
        (".", "DNSKEY", root_pair):
        answer(root_key_rr, root_key_sig),
        (".", "NS", root_pair):
        answer(root_ns_rr, root_ns_sig),
        ("hnstld.", "DNSKEY", tld_pair):
        answer(tld_key_rr, tld_key_sig),
        ("hnstld.", "NS", tld_pair):
        answer(tld_ns_rr, tld_ns_sig),
        ("example.hnstld.", "NS", tld_pair):
        LookupResponse(status=0, authority=_items(child_ns)),
    }
    if fault == "nxdomain" or mode == "handshake":
        table[("hnstld.", "DS", root_pair)] = denial
        table[("hnstld.", "NS", root_pair)] = denial
    else:
        table[("hnstld.", "DS", root_pair)] = answer(tld_ds_rr, tld_ds_sig)
        table[("hnstld.", "NS",
               root_pair)] = LookupResponse(status=0, authority=_items(tld_ns))
    if fault == "nxdomain":
        table[("hnstld.", "DS", None)] = LookupResponse(status=3)
        table[("hnstld.", "NS", None)] = LookupResponse(status=3)
    elif mode == "handshake":
        table[("hnstld.", "DS", None)] = LookupResponse(status=0,
                                                        answer=_items(tld_ds),
                                                        responder="192.0.2.8")
        table[("hnstld.", "NS", None)] = LookupResponse(status=0,
                                                        answer=_items(tld_ns))
    if fault == "no-ds":
        table[("example.hnstld.", "DS", tld_pair)] = LookupResponse(status=0)
    else:
        table[("example.hnstld.", "DS", tld_pair)] = answer(*child_signed)
    del child_ksk_priv
    return Api(table), [dns.dnssec.make_ds(root, root_ksk, "SHA256")], apex


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_valid_chain(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(), mode=mode, fault=None)
    env.settings.trust_anchors = anchors
    delegation = authenticate_parent(api, env.settings, apex)
    assert delegation.parent_zone == dns.name.from_text("hnstld.")
    assert [name.to_text()
            for name in delegation.ns_names] == ["ns1.outside.example."]
    assert all(call["rd"] == 0 and call["do"] == 1 for call in api.calls)


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_no_ds_at_the_parent(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(), mode=mode, fault="no-ds")
    env.settings.trust_anchors = anchors
    with pytest.raises(DsNotAuthenticated) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_chain_invalid"
    assert "not authenticated" in raised.value.message


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_bad_signature(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(),
                                mode=mode,
                                fault="bad-signature")
    env.settings.trust_anchors = anchors
    with pytest.raises(BadSignature) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_chain_invalid"
    assert "signature did not validate" in raised.value.message


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_expired_signature(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(), mode=mode, fault="expired")
    env.settings.trust_anchors = anchors
    with pytest.raises(ExpiredSignature) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_chain_invalid"


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_nxdomain_at_the_root(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(),
                                mode=mode,
                                fault="nxdomain")
    env.settings.trust_anchors = anchors
    with pytest.raises(TldMissingAtRoot) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_ds_missing"
    assert raised.value.message == "hnstld. does not exist under ."


@pytest.mark.parametrize("mode", ["icann", "handshake"])
def test_ds_dnskey_mismatch(env, mode):
    get_process_cache().clear()
    api, anchors, apex = _chain(env.settings.now(),
                                mode=mode,
                                fault="mismatch")
    env.settings.trust_anchors = anchors
    with pytest.raises(DsMismatch) as raised:
        authenticate_parent(api, env.settings, apex)
    assert raised.value.error == "parent_chain_invalid"
    assert "does not match" in raised.value.message
