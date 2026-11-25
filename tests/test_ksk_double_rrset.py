"""KSK Double-RRset (RFC 7583): two KSKs in DNSKEY, one DS at the parent."""

import dns.name
import dns.rdatatype
import dns.rrset

from dns_host.axfr_service import CatalogView
from dns_host.catalogfile import Catalog, Member
from dns_host.dns_server import DnsServer
from dns_host.zonesign import generate_key, sign_rrset
from tests.conftest import post
from tests.test_axfr_grace import _records, _xfr


def _double_ksk(lab, body):
    """Add a second KSK to DNSKEY and sign DNSKEY with both KSKs."""

    _priv2, ksk2 = generate_key(257)
    apex = lab.apex
    dnskey = dns.rrset.from_rdata(apex, 300, lab.child_ksk, ksk2,
                                  lab.child_zsk)
    sigs = [
        sign_rrset(dnskey, priv, key, apex, lab.inception, lab.expiration)
        for priv, key in ((lab.child_ksk_priv, lab.child_ksk), (_priv2, ksk2))
    ]
    kept = [
        item for item in body["rrsets"] if item["type"] != "DNSKEY"
        and not (item["type"] == "RRSIG"
                 and item["rrdatas"][0].startswith("DNSKEY "))
    ]
    text = [rdata.to_text(origin=apex, relativize=False) for rdata in dnskey]
    kept.append({
        "kind": "dns#resourceRecordSet",
        "name": apex.to_text(),
        "type": "DNSKEY",
        "ttl": 300,
        "rrdatas": text,
    })
    kept.append({
        "kind":
        "dns#resourceRecordSet",
        "name":
        apex.to_text(),
        "type":
        "RRSIG",
        "ttl":
        300,
        "rrdatas":
        [sig.to_text(origin=apex, relativize=False) for sig in sigs],
    })
    body["rrsets"] = kept
    return body


def test_two_ksks_one_ds_is_served(env):
    lab = env.lab
    response = post(env, _double_ksk(lab, lab.zone(serial=lab.now)))
    assert response.status_code == 201, response.get_json()
    catalog = Catalog(env.settings)
    catalog.load()
    assert lab.apex.to_text() in catalog.zones
    view = CatalogView(env.settings)
    assert view.wire_for(lab.apex.to_text())
    server = DnsServer(env.settings, env.store)
    port = server.start()
    try:
        member = _records(_xfr(port, lab.apex.to_text()))
        keys = [r for r in member if r[1] == "DNSKEY"]
        assert len(keys) == 3
    finally:
        server.stop()


def test_update_to_two_ksks_keeps_zone_served(env):
    import dns.message
    import dns.query

    lab = env.lab
    assert post(env, lab.zone(serial=lab.now)).status_code == 201
    env.clock.t += 5
    body = _double_ksk(lab, lab.zone(serial=lab.now + 5))
    response = post(env, body)
    assert response.status_code == 200, response.get_json()
    again = post(env, body)
    assert again.status_code == 409
    server = DnsServer(env.settings, env.store)
    port = server.start()
    try:
        query = dns.message.make_query(lab.apex, "SOA")
        answer = dns.query.udp(query, "127.0.0.1", port=port, timeout=2)
        assert answer.rcode() == 0
        assert answer.answer[0][0].serial == lab.now + 5
        member = _records(_xfr(port, lab.apex.to_text()))
        assert len([r for r in member if r[1] == "DNSKEY"]) == 3
        catalog = _records(_xfr(port, "catalog.svc.test."))
        assert any(r[1] == "PTR" and r[2] == lab.apex.to_text()
                   for r in catalog)
    finally:
        server.stop()


def test_stored_two_ksk_document_is_served(settings):
    """A synthetic stored zone: 1 ZSK, 2 KSKs and 2 DNSKEY RRSIGs."""

    import json
    from pathlib import Path

    import dns.message
    import dns.query

    from dns_host.catalogfile import Member
    from dns_host.zone import document_to_zone
    from dns_host.zonesync import write_member

    from dns_host.config import data_dir

    document = json.loads(
        (Path(__file__).parent / "data" / "two_ksk_zone.json").read_text())
    apex = document["apex"]
    write_member(data_dir() / "zones", apex, document)
    soa = document_to_zone(dns.name.from_text(apex), document).soa_rdata()
    catalog = Catalog(settings)
    catalog.zones[apex] = Member(apex=apex,
                                 serial=int(soa.serial),
                                 soa=soa.to_text(),
                                 ttl=3600,
                                 expires_at=0)
    catalog.save(settings.now())
    server = DnsServer(settings)
    port = server.start()
    try:
        query = dns.message.make_query(apex, "SOA")
        answer = dns.query.udp(query, "127.0.0.1", port=port, timeout=2)
        assert answer.rcode() == 0
        member = _records(_xfr(port, apex))
        assert len([r for r in member if r[1] == "DNSKEY"]) == 3
        dnskey_sigs = [
            r for r in member if r[1] == "RRSIG" and r[2].startswith("DNSKEY ")
        ]
        assert len(dnskey_sigs) == 2
        catalog_rrs = _records(_xfr(port, "catalog.svc.test."))
        assert any(r[1] == "PTR" and r[2] == apex for r in catalog_rrs)
    finally:
        server.stop()


def test_catalog_load_pairs_content_with_its_own_mtime(settings):
    catalog = Catalog(settings)
    catalog.zones["a.example."] = Member(apex="a.example.",
                                         serial=1,
                                         soa="",
                                         ttl=300,
                                         expires_at=0)
    serial = catalog.save(settings.now())
    reader = Catalog(settings)
    reader.load()
    assert reader.serial == serial
    assert reader.mtime_ns == catalog.mtime_ns
    assert "a.example." in reader.zones
