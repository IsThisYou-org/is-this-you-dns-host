"""Parent DS against the uploaded KSKs during a KSK rollover.

All keys here are synthetic. A parent DS set passes when, for each DS
algorithm, at least one DS (of a supported digest type) matches a KSK of
that algorithm which signs the DNSKEY RRset. A DS for a key already removed
from the zone is allowed.
"""

import dns.dnssec
import dns.name
import dns.rrset

from dns_host.chain import match_ds_by_algorithm
from dns_host.zonesign import generate_key
from tests.conftest import post
from tests.test_ksk_double_rrset import _double_ksk


def _publish_ds(lab, *ds_rdatas):
    ds = dns.rrset.from_rdata(lab.apex, 300, *ds_rdatas)
    sig = lab._sig(ds, lab.parent_zsk_priv, lab.parent_zsk, lab.parent)
    lab._put(lab.apex, "DS", None, ds, sig)


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


def test_two_ds_of_different_digest_types(env):
    lab = env.lab
    env.settings.ds_digest_types = (2, 4)
    _priv, removed = generate_key(257)
    _publish_ds(lab, _ds(lab, removed, "SHA256"),
                _ds(lab, lab.child_ksk, "SHA384"))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 201, response.get_json()


def test_unsupported_digest_type_is_ignored(env):
    lab = env.lab
    assert tuple(env.settings.ds_digest_types) == (2, )
    # SHA-384 is not in the allow-list: that DS is skipped, not fatal.
    _publish_ds(lab, _ds(lab, lab.child_ksk, "SHA384"),
                _ds(lab, lab.child_ksk, "SHA256"))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 201, response.get_json()


def test_only_unsupported_digest_type_is_rejected(env):
    lab = env.lab
    _publish_ds(lab, _ds(lab, lab.child_ksk, "SHA384"))
    response = post(env, lab.zone(serial=lab.now))
    assert response.status_code == 403, response.get_json()
    assert response.get_json()["error"] == "parent_ds_mismatch"


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
    matched, unmatched = match_ds_by_algorithm(upper, keys, [ds], (2, ))
    assert matched == [key]
    assert unmatched == []
