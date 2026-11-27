"""Read a delegation NS set from the parent zone's authoritative servers.

A recursive lookup for the child NS follows the referral into the child.
That zone is not served until admission, so the resolver returns SERVFAIL.
The SERVFAIL is not a parent answer. Ask the resolver API instead, with
``rd=0`` and ``servers=`` set to a pair of parent names or addresses. The
API asks that pair and returns the fastest answer. A failed pair is
followed by the next pair.

The validation walk asks for NS itself, with ``do=1``, through the same
query it uses for every other hop. This helper remains for a caller that
wants the NS RRset alone. Delegation NS records are unsigned. The DS,
checked against the parent DNSKEY, is what proves the chain.
"""

from __future__ import annotations

import ipaddress

import dns.name
import dns.rcode
import dns.rrset

from dns_host.doh import LookupError, LookupResponse
from dns_host.errors import ApiError
from dns_host.names import normalise_name

_DEFINITIVE = {0, 3}


def fetch_delegation_ns(lookup, settings, child, parent_servers, budget):
    """Return ``(ns_rrset_or_none, response)`` for ``child``.

    Raises ``ApiError`` 503 when no parent pair gives a NOERROR or
    NXDOMAIN answer. A response with no NS RRset is returned so the walk
    can still authenticate a denial. An NXDOMAIN is that response, not an
    error raised here: the walk marks a root-cut NXDOMAIN, from this NS
    answer or from the DS answer, as ``TldMissingAtRoot``. ``LookupError``
    from ``budget`` is left to the caller.

    An in-memory lookup may implement ``answer_delegation(child,
    parent_servers)`` and skip the API. The production client does not.
    """

    del settings
    hook = _answer_delegation(lookup)
    if hook is not None:
        return hook(child, parent_servers)
    child_name = _as_name(child)
    names = _server_names(parent_servers)
    transport_errors = []
    rcode_errors = []
    definitive = None
    if not names:
        transport_errors.append("no parent nameservers")
    for pair in _pairs(names):
        label = ",".join(pair)
        budget.charge()
        try:
            response = _ask(lookup, budget, child_name, "NS", pair, do=0)
        except LookupError as exc:
            transport_errors.append(f"{label}: {exc}")
            continue
        rcode = int(response.status)
        if rcode not in _DEFINITIVE:
            rcode_errors.append(f"{label}: rcode {dns.rcode.to_text(rcode)}")
            continue
        ns_rrset = _ns_rrset(response, child_name)
        if ns_rrset is not None:
            return ns_rrset, response
        if definitive is None:
            definitive = (None, response)
    if definitive is not None:
        return definitive
    reached = bool(rcode_errors)
    errors = rcode_errors + transport_errors
    if not errors:
        errors = ["no parent nameservers"]
    raise delegation_lookup_error(child_name, reached, errors)


def query_parent_servers(lookup, settings, qname, rdtype: str, servers,
                         budget) -> list:
    """Ask the resolver API for ``qname``/``rdtype`` at the parent servers.

    Nameservers are sent two at a time in ``servers=``. Each NOERROR answer
    is returned as ``(label, LookupResponse)``. A pair that does not answer
    is skipped. ``do=1`` so the DS RRSIG is present. An in-memory lookup
    may implement ``answer_direct(qname, rdtype, server)``.
    """

    del settings
    hook = _find_hook(lookup, "answer_direct")
    name = _as_name(qname)
    if hook is not None:
        answers = []
        for server in servers or []:
            try:
                label = _as_name(server).to_text()
            except Exception:
                continue
            budget.charge()
            response = hook(name, rdtype, label)
            if response is not None and int(response.status) == 0:
                answers.append((label, response))
        return answers
    answers = []
    for pair in _pairs(_server_names(servers)):
        label = ",".join(pair)
        budget.charge()
        try:
            response = _ask(lookup, budget, name, rdtype, pair, do=1)
        except LookupError:
            continue
        if int(response.status) != 0:
            continue
        answers.append((label, response))
    return answers


def delegation_lookup_error(child, reached: bool, errors: list) -> ApiError:
    """503 for a delegation query that produced no NOERROR or NXDOMAIN."""

    detail = "; ".join(str(item) for item in errors) or "no response"
    if len(detail) > 500:
        detail = detail[:500] + "..."
    child_text = child.to_text() if isinstance(
        child, dns.name.Name) else _name_text(child)
    if reached:
        message = (
            f"parent nameservers for {child_text} did not answer the delegation query: {detail}"
        )
    else:
        message = f"parent nameservers unreachable for {child_text}: {detail}"
    return ApiError(503, "parent_lookup_unavailable", message)


def _ask(lookup, budget, qname, rdtype: str, pair: list[str], *, do: int):
    """One API call. The caller charges ``budget`` before this returns."""

    client = _client(lookup, budget)
    text = qname.to_text() if isinstance(qname, dns.name.Name) else str(qname)
    return client.query(text, rdtype, servers=pair, rd=0, do=do)


def _client(lookup, budget):
    """Skip a budget wrapper that would charge this same budget again."""

    client = lookup
    while getattr(client, "budget", None) is budget and getattr(
            client, "inner", None) is not None:
        client = client.inner
    return client


def _pairs(names: list[str]):
    for start in range(0, len(names), 2):
        yield names[start:start + 2]


def _server_names(servers) -> list[str]:
    names = []
    for server in servers or []:
        if isinstance(server, dns.name.Name):
            text = server.to_text()
        else:
            text = str(server).strip()
            if not text:
                continue
            if not _is_ip(text) and not text.endswith("."):
                text += "."
        if text:
            names.append(text)
    return names


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _ns_rrset(response: LookupResponse, qname: dns.name.Name):
    owner = qname.canonicalize()
    for section in (response.answer, response.authority):
        rdatas = []
        ttl = 300
        for item in section or []:
            if str(getattr(item, "rdtype", "")).upper() != "NS":
                continue
            try:
                name = normalise_name(item.name, allow_root=True)
                rdata = item.to_rdata()
            except Exception:
                continue
            if name.canonicalize() != owner:
                continue
            ttl = int(item.ttl or ttl)
            rdatas.append(rdata)
        if rdatas:
            return dns.rrset.from_rdata(qname, ttl, *rdatas)
    return None


def _answer_delegation(lookup):
    return _find_hook(lookup, "answer_delegation")


def _find_hook(lookup, attribute: str):
    current = lookup
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        hook = getattr(current, attribute, None)
        if callable(hook):
            return hook
        current = getattr(current, "inner", None)
    return None


def _as_name(value) -> dns.name.Name:
    if isinstance(value, dns.name.Name):
        return value
    return dns.name.from_text(_name_text(value))


def _name_text(value) -> str:
    text = str(value).strip()
    if text and not text.endswith("."):
        text += "."
    return text
