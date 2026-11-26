"""Parent NS lookups go through the resolver API, two names at a time."""

import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from dns_host.chain import _Budget, _BudgetLookup
from dns_host.doh import LookupError, LookupRR, LookupResponse
from dns_host.errors import ApiError
from dns_host.parent_ns import fetch_delegation_ns, query_parent_servers

CHILD = dns.name.from_text("james.isthisyou.me.")
PARENT_NS = "ns1.isthisyou.org."
SECOND_NS = "ns2.isthisyou.org."
THIRD_NS = "ns3.isthisyou.org."
SETTINGS = object()


class Scripted:

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def query(self, name, rdtype, **kwargs):
        self.calls.append({"name": name, "type": str(rdtype), **kwargs})
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ns(qname, names, *, aa=False, status=0, responder=None):
    items = []
    for name in names:
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, name)
        items.append(
            LookupRR(name=qname.to_text(),
                     rdtype="NS",
                     ttl=300,
                     data=name,
                     wire=rdata.to_wire()))
    response = LookupResponse(status=status, aa=aa, responder=responder)
    if aa:
        response.answer = items
    else:
        response.authority = items
    return response


def _targets(rrset):
    return [rdata.target.to_text() for rdata in rrset]


def test_referral_ns_is_asked_with_servers_and_rd0():
    book = Scripted([
        _ns(CHILD, ["ns1.isthisyou.me.", "ns2.isthisyou.me."]),
    ])
    budget = _Budget(8)
    rrset, response = fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS],
                                          budget)
    assert _targets(rrset) == ["ns1.isthisyou.me.", "ns2.isthisyou.me."]
    assert response.status == 0
    assert response.aa is False
    assert book.calls == [{
        "name": "james.isthisyou.me.",
        "type": "NS",
        "servers": [PARENT_NS],
        "rd": 0,
        "do": 0,
    }]
    assert budget.used == 1


def test_authoritative_parent_ns_is_read_from_the_answer_section():
    book = Scripted([
        _ns(CHILD, ["ns1.isthisyou.me.", "ns2.isthisyou.me."], aa=True),
    ])
    rrset, response = fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS],
                                          _Budget(4))
    assert response.aa is True
    assert response.authority == []
    assert _targets(rrset) == ["ns1.isthisyou.me.", "ns2.isthisyou.me."]


def test_nameservers_are_sent_as_pairs_and_a_failed_pair_is_retried():
    book = Scripted([
        LookupError("pair down"),
        _ns(CHILD, ["ns1.isthisyou.me."]),
    ])
    rrset, _response = fetch_delegation_ns(book, SETTINGS, CHILD,
                                           [PARENT_NS, SECOND_NS, THIRD_NS],
                                           _Budget(8))
    assert _targets(rrset) == ["ns1.isthisyou.me."]
    assert [call["servers"] for call in book.calls] == [
        [PARENT_NS, SECOND_NS],
        [THIRD_NS],
    ]
    assert all(call["rd"] == 0 and call["do"] == 0 for call in book.calls)


def test_unreachable_pairs_name_the_servers():
    book = Scripted([
        LookupError("timed out"),
        LookupError("timed out"),
    ])
    with pytest.raises(ApiError) as caught:
        fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS, SECOND_NS],
                            _Budget(8))
    err = caught.value
    assert err.status == 503
    assert err.error == "parent_lookup_unavailable"
    assert "parent nameservers unreachable for james.isthisyou.me." in err.message
    assert PARENT_NS in err.message
    assert SECOND_NS in err.message
    assert "timed out" in err.message
    assert "served no delegation" not in err.message


def test_servfail_is_not_a_missing_delegation():
    book = Scripted([LookupResponse(status=dns.rcode.SERVFAIL)])
    with pytest.raises(ApiError) as caught:
        fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS], _Budget(4))
    err = caught.value
    assert err.status == 503
    assert "did not answer the delegation query" in err.message
    assert "SERVFAIL" in err.message
    assert "served no delegation" not in err.message
    assert "unreachable" not in err.message


def test_nodata_from_the_parent_has_no_delegation_ns():
    soa = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns1.isthisyou.org. hostmaster.isthisyou.me. 1 3600 600 864000 300")
    response = LookupResponse(
        status=0,
        authority=[
            LookupRR(name="isthisyou.me.",
                     rdtype="SOA",
                     ttl=300,
                     data=soa.to_text(),
                     wire=soa.to_wire())
        ],
    )
    book = Scripted([response])
    rrset, got = fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS],
                                     _Budget(4))
    assert rrset is None
    assert got.status == 0
    assert any(item.rdtype == "SOA" for item in got.authority)


def test_a_second_pair_is_refused_once_the_budget_is_spent():
    book = Scripted([LookupError("down"), _ns(CHILD, ["ns1.isthisyou.me."])])
    budget = _Budget(1)
    with pytest.raises(LookupError, match="fan-out"):
        fetch_delegation_ns(_BudgetLookup(book, budget), SETTINGS, CHILD,
                            [PARENT_NS, SECOND_NS, THIRD_NS], budget)
    assert budget.used == 2
    assert len(book.calls) == 1


def test_ds_recheck_pairs_keep_the_responder():
    ds = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                             "12345 13 2 " + "ab" * 32)
    answer = LookupResponse(
        status=0,
        answer=[
            LookupRR(name="james.isthisyou.me.",
                     rdtype="DS",
                     ttl=300,
                     data=ds.to_text(),
                     wire=ds.to_wire())
        ],
        responder="203.0.113.10",
    )
    book = Scripted([LookupError("down"), answer])
    found = query_parent_servers(book, SETTINGS, CHILD, "DS",
                                 [PARENT_NS, SECOND_NS, THIRD_NS], _Budget(8))
    assert len(found) == 1
    label, response = found[0]
    assert label == THIRD_NS
    assert response.responder == "203.0.113.10"
    assert [call["servers"] for call in book.calls] == [
        [PARENT_NS, SECOND_NS],
        [THIRD_NS],
    ]
    assert all(call["rd"] == 0 and call["do"] == 1 for call in book.calls)
    assert all(call["type"] == "DS" for call in book.calls)
