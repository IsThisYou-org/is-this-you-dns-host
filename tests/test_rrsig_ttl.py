"""RRSIG TTL follows the covered RRset, including a second signature."""

import base64

import dns.rdataclass
import dns.rdata
import dns.rdatatype

from dns_host.dns_server import DnsServer
from dns_host.errors import ApiError
from dns_host.zone import parse_upload
from dns_host.zonesign import sign_rrset
from tests.conftest import post
from tests.test_axfr_grace import _xfr
from tests.test_zone_push import _write, zone_push


def _rrsig_items(document, covered: str):
    return [
        item for item in document["rrsets"] if item["type"] == "RRSIG"
        and item["rrdatas"] and item["rrdatas"][0].startswith(covered + " ")
    ]


def _second_soa_signature(lab, body):
    parsed = parse_upload(body, lab.apex)
    soa = parsed.get(dns.rdatatype.SOA)
    extra = sign_rrset(
        soa,
        lab.child_ksk_priv,
        lab.child_ksk,
        lab.apex,
        lab.inception,
        lab.expiration,
    )
    text = extra.to_text(origin=lab.apex, relativize=False)
    first = list(parsed.sigs[(lab.apex, int(dns.rdatatype.SOA))])[0]
    assert int(extra.key_tag) != int(first.key_tag)
    return text


def _replace_soa_sigs(body, groups):
    """``groups`` is a list of (ttl, rrdatas) replacing the SOA RRSIG item."""

    kept = [
        item for item in body["rrsets"] if not (
            item["type"] == "RRSIG" and item["rrdatas"][0].startswith("SOA "))
    ]
    name = body["apex"]
    for ttl, datas in groups:
        kept.append({
            "kind": "dns#resourceRecordSet",
            "name": name,
            "type": "RRSIG",
            "ttl": ttl,
            "rrdatas": datas,
        })
    body["rrsets"] = kept
    return body


def test_two_signatures_over_one_rrset_as_one_item_and_as_two(env):
    lab = env.lab
    one = lab.zone(serial=lab.now)
    original = _rrsig_items(one, "SOA")[0]["rrdatas"]
    second = _second_soa_signature(lab, one)
    _replace_soa_sigs(one, [(300, original + [second])])
    parsed = parse_upload(one, lab.apex)
    sigs = list(parsed.sigs[(lab.apex, int(dns.rdatatype.SOA))])
    assert len(sigs) == 2
    assert len({int(sig.key_tag) for sig in sigs}) == 2
    assert post(env, one).status_code == 201

    two = lab.zone(serial=lab.now + 1)
    original = _rrsig_items(two, "SOA")[0]["rrdatas"]
    second = _second_soa_signature(lab, two)
    _replace_soa_sigs(two, [(300, original), (300, [second])])
    parsed = parse_upload(two, lab.apex)
    assert len(list(parsed.sigs[(lab.apex, int(dns.rdatatype.SOA))])) == 2
    assert post(env, two).status_code == 200

    clash = lab.zone(serial=lab.now + 2)
    original = _rrsig_items(clash, "SOA")[0]["rrdatas"]
    second = _second_soa_signature(lab, clash)
    _replace_soa_sigs(clash, [(300, original), (3600, [second])])
    try:
        parse_upload(clash, lab.apex)
    except ApiError as exc:
        assert exc.status == 422
        assert exc.error == "duplicate_rrset"
        assert "more than one TTL" in exc.message
    else:
        raise AssertionError("mixed RRSIG TTLs were accepted")


def test_uri_ttl_survives_zone_push_upload_and_axfr(env, tmp_path):
    apex = env.lab.apex.to_text()
    document = env.lab.zone(extras=[
        (f"_auth.7e9a2f4c8b1d.{apex}", "TXT",
         ['"v=dnsauth1 alg=ES256 k=example"']),
        (apex, "URI", ['10 1 "https://example.org/j"'], 3600),
    ])
    uploaded = zone_push.zone_to_upload(
        zone_push.load_zone_file(_write(tmp_path, document)))
    assert [item["ttl"] for item in _rrsig_items(uploaded, "SOA")] == [300]
    assert [item["ttl"] for item in _rrsig_items(uploaded, "URI")] == [3600]
    assert [
        item["ttl"] for item in uploaded["rrsets"] if item["type"] == "SOA"
    ] == [300]
    assert [
        item["ttl"] for item in uploaded["rrsets"] if item["type"] == "URI"
    ] == [3600]

    response = post(env, uploaded)
    assert response.status_code == 201, response.get_json()
    stored = env.store.get_zone("user.example.").document
    assert _stored_ttl(stored, "SOA") == 300
    assert _stored_ttl(stored, "URI") == 3600
    assert _stored_ttl(stored, "RRSIG", dns.rdatatype.SOA) == 300
    assert _stored_ttl(stored, "RRSIG", dns.rdatatype.URI) == 3600

    server = DnsServer(env.settings, env.store)
    port = server.start()
    try:
        seen = _axfr_ttls(_xfr(port, "user.example."))
    finally:
        server.stop()
    assert seen["SOA"] == {300}
    assert seen["NS"] == {300}
    assert seen["DNSKEY"] == {300}
    assert seen["URI"] == {3600}
    assert seen[("RRSIG", "SOA")] == {300}
    assert seen[("RRSIG", "URI")] == {3600}


def _stored_ttl(document, rdtype, covered=None):
    found = []
    for item in document["rrsets"]:
        if item["type"] != rdtype:
            continue
        if covered is None:
            found.append(int(item["ttl"]))
            continue
        raw = base64.b64decode(item["wire"][0])
        rdata = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                    raw, 0, len(raw))
        if int(rdata.type_covered) == int(covered):
            found.append(int(item["ttl"]))
    assert found == [found[0]]
    return found[0]


def _axfr_ttls(messages):
    found = {}
    for message in messages:
        for rrset in message.answer:
            if int(rrset.rdtype) == int(dns.rdatatype.RRSIG):
                key = ("RRSIG", dns.rdatatype.to_text(rrset[0].type_covered))
            else:
                key = dns.rdatatype.to_text(rrset.rdtype)
            found.setdefault(key, set()).add(int(rrset.ttl))
    return found
