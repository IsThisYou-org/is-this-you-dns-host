"""Parent DS against the uploaded KSKs during a KSK rollover.

All keys here are synthetic. A parent DS set passes when, for each DS
algorithm, at least one DS matches a KSK of that algorithm which signs the
DNSKEY RRset. SHA-256 is tried first. SHA-384 is hashed only when no SHA-256
DS matched for that algorithm. SHA-1 is ignored. A DS for a key already
removed from the zone is allowed.
"""

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset

from dns_host.chain import _keys_matching_ds, match_ds_by_algorithm
from dns_host.zonesign import generate_key
from tests.conftest import post
from tests.test_ksk_double_rrset import _double_ksk


def _publish_ds(lab, *ds_rdatas):
    ds = dns.rrset.from_rdata(lab.apex, 300, *ds_rdatas)
    sig = lab._sig(ds, lab.parent_zsk_priv, lab.parent_zsk, lab.parent)
    lab._put(lab.apex, "DS", None, ds, sig)
    for server in lab.parent_ns:
        lab._put(lab.apex, "DS", server, ds, sig)


def _ds(lab, key, digest="SHA256"):
    return dns.dnssec.make_ds(lab.apex, key, digest)


def _tag(key) -> int:
    return int(dns.dnssec.key_id(key))


def test_two_ds_one_ksk_passes_either_order(env):
    lab = env.lab
    _priv, removed = generate_key(257)
    for order in ((removed, lab.child_ksk), (lab.child_ksk, removed)):
        _publish_ds(lab, *[_ds(lab, key) for key in order])
        env.clock.t += 5
        response = post(env, lab.zone(serial=env.clock.t))
        assert response.status_code in (200, 201), response.get_json()


def test_one_ds_two_ksks_passes(env):
    lab = env.lab
    _publish_ds(lab, _ds(lab, lab.child_ksk))
    response = post(env, _double_ksk(lab, lab.zone(serial=lab.now)))
    assert response.status_code == 201, response.get_json()


def _watch_digests(monkeypatch):
    seen = []
    real = dns.dnssec.make_ds

    def spy(name, key, algorithm, *args, **kwargs):
        seen.append(str(algorithm).upper())
        return real(name, key, algorithm, *args, **kwargs)

    monkeypatch.setattr(dns.dnssec, "make_ds", spy)
    return seen


def _sha1_ds(key):
    # dnspython refuses to build a SHA-1 DS. The digest bytes are irrelevant:
    # digest type 1 is ignored before it is hashed.
    return dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DS,
        f"{int(dns.dnssec.key_id(key))} {int(key.algorithm)} 1 {'ab' * 20}")


def test_sha256_match_does_not_hash_sha384(env, monkeypatch):
    lab = env.lab
    sha256 = _ds(lab, lab.child_ksk, "SHA256")
    sha384 = _ds(lab, lab.child_ksk, "SHA384")
    # SHA-384 is first in the RRset so preference, not wire order, decides.
    _publish_ds(lab, sha384, sha256)
    body = lab.zone(serial=lab.now)
    seen = _watch_digests(monkeypatch)
    response = post(env, body)
    assert response.status_code == 201, response.get_json()
    assert "SHA384" not in seen
    assert "SHA256" in seen


def test_sha384_only_ds_is_accepted(env, monkeypatch):
    lab = env.lab
    _publish_ds(lab, _ds(lab, lab.child_ksk, "SHA384"))
    body = lab.zone(serial=lab.now)
    seen = _watch_digests(monkeypatch)
    response = post(env, body)
    assert response.status_code == 201, response.get_json()
    assert "SHA384" in seen


def test_sha384_is_accepted_when_sha256_does_not_match(env, monkeypatch):
    lab = env.lab
    sha256 = _ds(lab, lab.child_ksk, "SHA256")
    flipped = bytearray(sha256.digest)
    flipped[0] ^= 0xff
    bad = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DS,
        f"{int(sha256.key_tag)} {int(sha256.algorithm)} 2 {flipped.hex()}")
    _publish_ds(lab, bad, _ds(lab, lab.child_ksk, "SHA384"))
    body = lab.zone(serial=lab.now)
    seen = _watch_digests(monkeypatch)
    response = post(env, body)
    assert response.status_code == 201, response.get_json()
    assert "SHA256" in seen
    assert "SHA384" in seen


def test_sha1_ds_is_rejected(env):
    lab = env.lab
    _publish_ds(lab, _sha1_ds(lab.child_ksk))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ds_mismatch"


def test_keys_matching_ds_skips_sha384_when_sha256_matches(monkeypatch):
    _priv, key = generate_key(257)
    name = dns.name.from_text("user.example.")
    sha256 = dns.dnssec.make_ds(name, key, "SHA256")
    sha384 = dns.dnssec.make_ds(name, key, "SHA384")
    keys = dns.rrset.from_rdata(name, 300, key)
    seen = _watch_digests(monkeypatch)
    matched, unmatched = match_ds_by_algorithm(name, keys, [sha384, sha256])
    assert matched == [key]
    assert unmatched == []
    assert _keys_matching_ds(name, keys, [sha384, sha256]) == [key]
    assert seen == ["SHA256", "SHA256"]


def test_sha256_on_one_algorithm_does_not_skip_sha384_on_another(monkeypatch):
    _p13, k13 = generate_key(257, 13)
    _p15, k15 = generate_key(257, 15)
    name = dns.name.from_text("user.example.")
    ds13_sha256 = dns.dnssec.make_ds(name, k13, "SHA256")
    ds13_sha384 = dns.dnssec.make_ds(name, k13, "SHA384")
    ds15_sha384 = dns.dnssec.make_ds(name, k15, "SHA384")
    keys = dns.rrset.from_rdata(name, 300, k13, k15)
    seen = _watch_digests(monkeypatch)
    matched, unmatched = match_ds_by_algorithm(
        name, keys, [ds13_sha384, ds13_sha256, ds15_sha384])
    assert unmatched == []
    assert matched == [k13, k15]
    assert seen.count("SHA256") == 1
    assert seen.count("SHA384") == 1
    assert _keys_matching_ds(
        name, keys, [ds13_sha384, ds13_sha256, ds15_sha384]) == [k13, k15]


def test_no_match_is_rejected_with_key_tags(env):
    lab = env.lab
    _p1, gone1 = generate_key(257)
    _p2, gone2 = generate_key(257)
    _publish_ds(lab, _ds(lab, gone1), _ds(lab, gone2))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 403, response.get_json()
    body = response.get_json()
    assert body["error"] == "parent_ds_mismatch"
    message = body["message"]
    assert message.startswith(
        "parent DS does not match a KSK in the uploaded zone")
    assert f"{_tag(gone1)} (alg 13, digest 2)" in message
    assert f"{_tag(gone2)} (alg 13, digest 2)" in message
    assert f"zone KSK: {_tag(lab.child_ksk)} (alg 13)" in message


def test_two_algorithms_with_one_unmatched_is_rejected(env):
    lab = env.lab
    _priv, ed_key = generate_key(257, 15)
    _publish_ds(lab, _ds(lab, lab.child_ksk), _ds(lab, ed_key))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 403, response.get_json()
    body = response.get_json()
    assert body["error"] == "parent_ds_mismatch"
    assert "for algorithm 15" in body["message"]
    assert f"{_tag(ed_key)} (alg 15, digest 2)" in body["message"]


def test_corrected_upload_is_not_answered_from_negative_cache(env):
    lab = env.lab
    good = (lab.child_ksk_priv, lab.child_ksk)
    _priv, removed = generate_key(257)
    _publish_ds(lab, _ds(lab, removed), _ds(lab, lab.child_ksk))
    lab.child_ksk_priv, lab.child_ksk = generate_key(257)
    first = post(env, lab.zone(serial=env.clock.t))
    assert first.get_json()["error"] == "parent_ds_mismatch"
    lab.child_ksk_priv, lab.child_ksk = good
    env.clock.t += 5
    second = post(env, lab.zone(serial=env.clock.t))
    assert second.status_code == 201, second.get_json()


def test_match_uses_canonical_owner_name():
    _priv, key = generate_key(257)
    lower = dns.name.from_text("user.example.")
    upper = dns.name.from_text("USER.Example.")
    ds = dns.dnssec.make_ds(lower, key, "SHA256")
    keys = dns.rrset.from_rdata(upper, 300, key)
    matched, unmatched = match_ds_by_algorithm(upper, keys, [ds])
    assert matched == [key]
    assert unmatched == []


def _direct_ds(lab, *ds_rdatas, signer=None):
    from tests.support import _pack
    from dns_host.doh import LookupResponse

    ds = dns.rrset.from_rdata(lab.apex, 300, *ds_rdatas)
    priv, key = signer or (lab.parent_zsk_priv, lab.parent_zsk)
    sig = lab._sig(ds, priv, key, lab.parent)
    lab.direct[(lab.apex.to_text(),
                "DS")] = LookupResponse(status=0,
                                        answer=_pack(ds, sig),
                                        aa=True)


def test_stale_resolver_ds_is_rechecked_at_the_parent(env):
    """The resolver still has the DS set from before the new DS was added."""

    lab = env.lab
    _priv, removed = generate_key(257)
    _publish_ds(lab, _ds(lab, removed))
    _direct_ds(lab, _ds(lab, removed), _ds(lab, lab.child_ksk))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 201, response.get_json()
    direct_ds = [
        call for call in lab.calls
        if call.get("direct") and call["type"] == "DS"
    ]
    assert {call["server"]
            for call in direct_ds
            } == {name.to_text()
                  for name in lab.parent_ns}


def test_direct_ds_with_a_bad_signature_is_ignored(env):
    lab = env.lab
    _priv, removed = generate_key(257)
    _publish_ds(lab, _ds(lab, removed))
    _direct_ds(lab,
               _ds(lab, removed),
               _ds(lab, lab.child_ksk),
               signer=generate_key(256))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 403, response.get_json()
    body = response.get_json()
    assert body["error"] == "parent_ds_mismatch"
    assert f"{_tag(removed)} (alg 13, digest 2)" in body["message"]


def test_matching_resolver_ds_does_not_ask_the_parent(env):
    lab = env.lab
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 201, response.get_json()
    assert not [
        call
        for call in lab.calls if call.get("direct") and call["type"] == "DS"
    ]


def test_dnskey_signed_only_by_removed_ksk_is_a_signature_error(env):
    """Not parent_ds_mismatch: the offline RRSIG check rejects it first."""

    from dns_host.zonesign import sign_rrset

    lab = env.lab
    old_priv, old = generate_key(257)
    _publish_ds(lab, _ds(lab, old), _ds(lab, lab.child_ksk))
    body = lab.zone(serial=lab.now)
    dnskey = dns.rrset.from_rdata(lab.apex, 300, lab.child_ksk, lab.child_zsk)
    sig = sign_rrset(dnskey, old_priv, old, lab.apex, lab.inception,
                     lab.expiration)
    for item in body["rrsets"]:
        if item["type"] == "RRSIG" and item["rrdatas"][0].startswith(
                "DNSKEY "):
            item["rrdatas"] = [sig.to_text()]
    response = post(env, body)
    assert response.status_code == 422, response.get_json()
    assert response.get_json()["error"] == "rrsig_key_mismatch"
    assert str(_tag(old)) in response.get_json()["message"]
