"""Direct parent NS lookups: referral, truncation, and unreachable servers."""

from types import SimpleNamespace

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from dns_host.chain import _Budget, _BudgetLookup
from dns_host.doh import LookupError, LookupRR, LookupResponse
from dns_host.errors import ApiError
from dns_host.parent_ns import fetch_delegation_ns

CHILD = dns.name.from_text("james.isthisyou.me.")
PARENT_NS = "ns1.isthisyou.org."
PARENT_IP = "192.0.2.53"
SETTINGS = SimpleNamespace(doh_timeout_seconds=2)


class AddressBook:

    def __init__(self, addresses, status=0):
        self.addresses = {
            key.lower(): list(values)
            for key, values in addresses.items()
        }
        self.status = status
        self.calls = []

    def query(self, name, rdtype, **kwargs):
        self.calls.append({"name": name, "type": str(rdtype), **kwargs})
        if self.status != 0:
            return LookupResponse(status=self.status)
        want = str(rdtype).upper()
        answer = []
        for ip in self.addresses.get(name.lower(), []):
            kind = "AAAA" if ":" in ip else "A"
            if kind != want:
                continue
            rdtype_code = dns.rdatatype.A if kind == "A" else dns.rdatatype.AAAA
            rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype_code, ip)
            answer.append(
                LookupRR(
                    name=name,
                    rdtype=kind,
                    ttl=300,
                    data=ip,
                    wire=rdata.to_wire(),
                ))
        return LookupResponse(status=0, answer=answer)


def _response(qname,
              ns_names,
              *,
              section="authority",
              tc=False,
              rcode=0,
              glue=None):
    query = dns.message.make_query(qname, dns.rdatatype.NS, flags=0)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    if tc:
        response.flags |= dns.flags.TC
    if ns_names:
        rrset = dns.rrset.from_text(qname, 300, "IN", "NS", *ns_names)
        if section == "answer":
            response.flags |= dns.flags.AA
            response.answer.append(rrset)
        else:
            response.authority.append(rrset)
    if glue:
        for owner, ip in glue:
            kind = "AAAA" if ":" in ip else "A"
            response.additional.append(
                dns.rrset.from_text(owner, 300, "IN", kind, ip))
    return response


def _patch(monkeypatch, udp, tcp=None):
    monkeypatch.setattr(dns.query, "udp", udp)
    if tcp is None:

        def fail_tcp(*_args, **_kwargs):
            raise AssertionError("TCP fallback was not expected")

        tcp = fail_tcp
    monkeypatch.setattr(dns.query, "tcp", tcp)


def _targets(rrset):
    return [rdata.target.to_text() for rdata in rrset]


def test_referral_ns_is_read_from_the_parent_authority_section(monkeypatch):
    seen = []

    def udp(query, where, timeout=None, port=53, **_kwargs):
        seen.append((query, where, timeout, port))
        assert int(query.flags) & int(dns.flags.RD) == 0
        assert query.edns < 0
        assert query.question[0].name == CHILD
        return _response(CHILD, ["ns1.isthisyou.me.", "ns2.isthisyou.me."])

    _patch(monkeypatch, udp)
    book = AddressBook({PARENT_NS: [PARENT_IP, "2001:db8::53"]})
    budget = _Budget(8)
    glue = {}
    rrset, response = fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS],
                                          glue, budget)
    assert _targets(rrset) == ["ns1.isthisyou.me.", "ns2.isthisyou.me."]
    assert response.status == 0
    assert response.aa is False
    assert any(item.rdtype == "NS" for item in response.authority)
    assert seen[0][1] == PARENT_IP
    assert seen[0][2] == 2
    assert seen[0][3] == 53
    assert [call["type"] for call in book.calls] == ["A", "AAAA"]
    assert all(
        call["rd"] == 1 and call["do"] == 0 and call.get("server") is None
        for call in book.calls)
    assert all(call["type"] != "NS" for call in book.calls)
    # A and AAAA are charged when the lookup is the walk's budget wrapper.
    # The direct query counted here is the one UDP packet to the A address.
    assert budget.used == 1


def test_authoritative_parent_ns_is_read_from_the_answer_section(monkeypatch):

    def udp(_query, where, timeout=None, port=53, **_kwargs):
        assert where == PARENT_IP
        return _response(
            CHILD,
            ["ns1.isthisyou.me.", "ns2.isthisyou.me."],
            section="answer",
        )

    _patch(monkeypatch, udp)
    rrset, response = fetch_delegation_ns(
        AddressBook({PARENT_NS: [PARENT_IP]}),
        SETTINGS,
        CHILD,
        [PARENT_NS],
        {},
        _Budget(8),
    )
    assert response.aa is True
    assert _targets(rrset) == ["ns1.isthisyou.me.", "ns2.isthisyou.me."]
    assert response.authority == []


def test_truncated_udp_falls_back_to_tcp(monkeypatch):
    udp_calls = []
    tcp_calls = []

    def udp(query, where, timeout=None, port=53, **_kwargs):
        udp_calls.append((query, where, timeout, port))
        return _response(CHILD, ["truncated.isthisyou.me."], tc=True)

    def tcp(query, where, timeout=None, port=53, **_kwargs):
        tcp_calls.append((query, where, timeout, port))
        assert int(query.flags) & int(dns.flags.RD) == 0
        return _response(CHILD, ["ns1.isthisyou.me.", "ns2.isthisyou.me."])

    _patch(monkeypatch, udp, tcp)
    budget = _Budget(8)
    rrset, _response_out = fetch_delegation_ns(
        AddressBook({PARENT_NS: [PARENT_IP]}),
        SETTINGS,
        CHILD,
        [PARENT_NS],
        {},
        budget,
    )
    assert len(udp_calls) == 1
    assert len(tcp_calls) == 1
    assert tcp_calls[0][1] == PARENT_IP
    assert tcp_calls[0][3] == 53
    assert _targets(rrset) == ["ns1.isthisyou.me.", "ns2.isthisyou.me."]
    # UDP plus the TCP retry. Address lookups are charged on the lookup wrapper.
    assert budget.used == 2


def test_tcp_fallback_counts_against_the_walk_budget(monkeypatch):

    def udp(_query, _where, timeout=None, port=53, **_kwargs):
        return _response(CHILD, ["truncated.isthisyou.me."], tc=True)

    def tcp(*_args, **_kwargs):
        raise AssertionError("TCP is not sent once the budget is spent")

    _patch(monkeypatch, udp, tcp)
    glue = {dns.name.from_text(PARENT_NS).canonicalize(): [PARENT_IP]}
    budget = _Budget(1)
    with pytest.raises(LookupError, match="fan-out"):
        fetch_delegation_ns(AddressBook({}), SETTINGS, CHILD, [PARENT_NS],
                            glue, budget)
    assert budget.used == 2


def test_unreachable_parent_nameservers(monkeypatch):

    def udp(_query, _where, timeout=None, port=53, **_kwargs):
        raise dns.exception.Timeout

    _patch(monkeypatch, udp)
    book = AddressBook({
        PARENT_NS: [PARENT_IP],
        "ns2.isthisyou.org.": ["192.0.2.54"]
    })
    with pytest.raises(ApiError) as caught:
        fetch_delegation_ns(
            book,
            SETTINGS,
            CHILD,
            [PARENT_NS, "ns2.isthisyou.org."],
            {},
            _Budget(8),
        )
    err = caught.value
    assert err.status == 503
    assert err.error == "parent_lookup_unavailable"
    assert "parent nameservers unreachable for james.isthisyou.me." in err.message
    assert PARENT_IP in err.message
    assert "192.0.2.54" in err.message
    assert "Timeout" in err.message
    assert "served no delegation" not in err.message
    assert "parent returned no delegation" not in err.message
    assert all(call["type"] != "NS" for call in book.calls)


def test_the_next_parent_nameserver_is_tried_after_a_timeout(monkeypatch):
    asked = []

    def udp(_query, where, timeout=None, port=53, **_kwargs):
        asked.append(where)
        if where == PARENT_IP:
            raise OSError("network unreachable")
        return _response(CHILD, ["ns1.isthisyou.me."])

    _patch(monkeypatch, udp)
    rrset, _response_out = fetch_delegation_ns(
        AddressBook({
            PARENT_NS: [PARENT_IP],
            "ns2.isthisyou.org.": ["192.0.2.54"],
        }),
        SETTINGS,
        CHILD,
        [PARENT_NS, "ns2.isthisyou.org."],
        {},
        _Budget(8),
    )
    assert asked == [PARENT_IP, "192.0.2.54"]
    assert _targets(rrset) == ["ns1.isthisyou.me."]


def test_parent_servfail_is_not_reported_as_a_missing_delegation(monkeypatch):

    def udp(_query, _where, timeout=None, port=53, **_kwargs):
        return _response(CHILD, [], rcode=dns.rcode.SERVFAIL)

    _patch(monkeypatch, udp)
    glue = {dns.name.from_text(PARENT_NS).canonicalize(): [PARENT_IP]}
    with pytest.raises(ApiError) as caught:
        fetch_delegation_ns(AddressBook({}), SETTINGS, CHILD, [PARENT_NS],
                            glue, _Budget(4))
    err = caught.value
    assert err.status == 503
    assert err.error == "parent_lookup_unavailable"
    assert "did not answer the delegation query" in err.message
    assert "SERVFAIL" in err.message
    assert "served no delegation" not in err.message
    assert "parent returned no delegation" not in err.message
    assert "unreachable" not in err.message


def test_nodata_from_the_parent_has_no_delegation_ns(monkeypatch):

    def udp(_query, _where, timeout=None, port=53, **_kwargs):
        response = _response(CHILD, [])
        response.authority.append(
            dns.rrset.from_text(
                "isthisyou.me.",
                300,
                "IN",
                "SOA",
                "ns1.isthisyou.org. hostmaster.isthisyou.me. 1 3600 600 864000 300",
            ))
        return response

    _patch(monkeypatch, udp)
    glue = {dns.name.from_text(PARENT_NS).canonicalize(): [PARENT_IP]}
    rrset, response = fetch_delegation_ns(AddressBook({}), SETTINGS, CHILD,
                                          [PARENT_NS], glue, _Budget(4))
    assert rrset is None
    assert response.status == 0
    assert any(item.rdtype == "SOA" for item in response.authority)


def test_glue_is_used_and_a_resolver_servfail_is_not_a_parent_answer(
        monkeypatch):

    def udp(_query, where, timeout=None, port=53, **_kwargs):
        assert where == "192.0.2.8"
        return _response(
            CHILD,
            ["ns1.isthisyou.me."],
            glue=[("ns1.isthisyou.me.", "192.0.2.9")],
        )

    _patch(monkeypatch, udp)

    class Exploding:

        def query(self, *_args, **_kwargs):
            raise AssertionError(
                "resolver was asked even though glue was present")

    glue = {dns.name.from_text(PARENT_NS).canonicalize(): ["192.0.2.8"]}
    rrset, _response_out = fetch_delegation_ns(Exploding(), SETTINGS, CHILD,
                                               [PARENT_NS], glue, _Budget(4))
    assert _targets(rrset) == ["ns1.isthisyou.me."]
    assert glue[dns.name.from_text("ns1.isthisyou.me.").canonicalize()] == [
        "192.0.2.9"
    ]


def test_resolver_address_servfail_is_unreachable_not_a_parent_answer(
        monkeypatch):

    def udp(*_args, **_kwargs):
        raise AssertionError("no address means the parent was not queried")

    _patch(monkeypatch, udp)
    book = AddressBook({PARENT_NS: [PARENT_IP]}, status=2)
    with pytest.raises(ApiError) as caught:
        fetch_delegation_ns(book, SETTINGS, CHILD, [PARENT_NS], {}, _Budget(4))
    err = caught.value
    assert err.status == 503
    assert "parent nameservers unreachable for james.isthisyou.me." in err.message
    assert "no address" in err.message
    assert "served no delegation" not in err.message
    assert all(call["type"] in {"A", "AAAA"} for call in book.calls)


def test_aaaa_is_used_when_the_name_has_no_address_record(monkeypatch):

    def udp(_query, where, timeout=None, port=53, **_kwargs):
        assert where == "2001:db8::53"
        return _response(CHILD, ["ns1.isthisyou.me."])

    _patch(monkeypatch, udp)
    rrset, _response_out = fetch_delegation_ns(
        AddressBook({PARENT_NS: ["2001:db8::53"]}),
        SETTINGS,
        CHILD,
        [PARENT_NS],
        {},
        _Budget(4),
    )
    assert _targets(rrset) == ["ns1.isthisyou.me."]


def test_direct_and_resolver_queries_share_one_budget(monkeypatch):

    def udp(*_args, **_kwargs):
        raise AssertionError("the budget is spent on address lookups first")

    _patch(monkeypatch, udp)
    budget = _Budget(2)
    book = AddressBook({PARENT_NS: [PARENT_IP]})
    with pytest.raises(LookupError, match="fan-out"):
        fetch_delegation_ns(_BudgetLookup(book, budget), SETTINGS, CHILD,
                            [PARENT_NS], {}, budget)
    assert budget.used == 3
    assert [call["type"] for call in book.calls] == ["A", "AAAA"]
