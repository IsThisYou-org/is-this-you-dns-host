"""Read a delegation NS set from the parent zone's authoritative servers.

A recursive lookup for the child NS follows the referral into the child.
That zone is not served until admission, so the resolver returns SERVFAIL.
The SERVFAIL is not a parent answer. Ask the parent over DNS instead
(UDP port 53, TCP when the UDP answer is truncated) with the recursion
bit clear, and read the NS RRset from the referral AUTHORITY section, or
from ANSWER when the parent is also authoritative for the child.

Delegation NS records are unsigned. The DS, fetched through the resolver
and checked against the parent DNSKEY, is what proves the chain.
"""

from __future__ import annotations

import ipaddress

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from dns_host.doh import LookupRR, LookupResponse
from dns_host.errors import ApiError
from dns_host.names import normalise_name

_DEFINITIVE = {0, 3}


def fetch_delegation_ns(lookup, settings, child, parent_servers, glue, budget):
    """Return ``(ns_rrset_or_none, response)`` for ``child``.

    Raises ``ApiError`` 503 when no parent nameserver gives a NOERROR or
    NXDOMAIN answer. A response with no NS RRset is returned so the walk
    can still authenticate a denial. ``LookupError`` from ``budget`` is
    left to the caller.

    An in-memory lookup may implement ``answer_delegation(child,
    parent_servers)`` and skip the network. The production client does not.
    """

    hook = _answer_delegation(lookup)
    if hook is not None:
        return hook(child, parent_servers)
    if glue is None:
        glue = {}
    child_name = _as_name(child)
    timeout = _timeout(settings)
    transport_errors = []
    rcode_errors = []
    definitive = None
    for server in parent_servers or []:
        try:
            server_name = _as_name(server)
        except Exception:
            transport_errors.append(f"{server}: not a DNS name")
            continue
        label = server_name.to_text()
        addresses = _addresses(lookup, server_name, glue)
        if not addresses:
            transport_errors.append(f"{label}: no address")
            continue
        for address in addresses:
            try:
                message = _exchange(address, child_name, timeout, budget)
            except _Transport as exc:
                transport_errors.append(f"{label} {address}: {exc}")
                continue
            rcode = int(message.rcode())
            if rcode not in _DEFINITIVE:
                rcode_errors.append(
                    f"{label} {address}: rcode {dns.rcode.to_text(rcode)}")
                continue
            _harvest_message(message, glue)
            response = message_to_lookup(message)
            ns_rrset = _ns_rrset(message, child_name)
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


def message_to_lookup(message) -> LookupResponse:
    """Adapt a DNS message to the resolver response the denial checks read."""

    return LookupResponse(
        status=int(message.rcode()),
        answer=_section(message.answer),
        authority=_section(message.authority),
        additional=_section(message.additional),
        aa=bool(int(message.flags) & int(dns.flags.AA)),
    )


def harvest_lookup_glue(response, glue: dict) -> None:
    """Remember A and AAAA addresses carried on a resolver response."""

    if response is None or glue is None:
        return
    for item in list(response.additional or []) + list(response.answer or []):
        if str(getattr(item, "rdtype", "")).upper() not in {"A", "AAAA"}:
            continue
        try:
            rdata = item.to_rdata()
            owner = normalise_name(item.name, allow_root=True)
        except Exception:
            continue
        _remember(glue, owner, getattr(rdata, "address", None))


class _Transport(Exception):
    pass


def _answer_delegation(lookup):
    current = lookup
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        hook = getattr(current, "answer_delegation", None)
        if callable(hook):
            return hook
        current = getattr(current, "inner", None)
    return None


def _exchange(address: str, qname, timeout: float, budget):
    query = dns.message.make_query(qname, dns.rdatatype.NS, flags=0)
    budget.charge()
    try:
        response = dns.query.udp(query, address, timeout=timeout, port=53)
    except Exception as exc:
        raise _Transport(_failure_text(exc)) from exc
    if int(response.flags) & int(dns.flags.TC):
        budget.charge()
        try:
            response = dns.query.tcp(query, address, timeout=timeout, port=53)
        except Exception as exc:
            raise _Transport(_failure_text(exc)) from exc
    return response


def _addresses(lookup, server_name, glue) -> list:
    key = server_name.canonicalize()
    glued = []
    for item in glue.get(key, ()):
        ip = _ip_text(item)
        if ip and ip not in glued:
            glued.append(ip)
    if glued:
        return glued
    resolved = _resolve(lookup, server_name)
    if resolved:
        glue[key] = list(resolved)
    return resolved


def _resolve(lookup, server_name) -> list:
    found = []
    qname = server_name.to_text()
    for rdtype in ("A", "AAAA"):
        response = lookup.query(qname, rdtype, rd=1, do=0)
        if response is None or int(response.status) != 0:
            continue
        for item in response.answer or []:
            if str(item.rdtype).upper() != rdtype:
                continue
            try:
                rdata = item.to_rdata()
            except Exception:
                continue
            ip = _ip_text(getattr(rdata, "address", None))
            if ip and ip not in found:
                found.append(ip)
    return found


def _ns_rrset(message, qname):
    owner = qname.canonicalize()
    for section in (message.answer, message.authority):
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.NS:
                continue
            if rrset.name.canonicalize() != owner:
                continue
            if len(rrset) == 0:
                continue
            return rrset
    return None


def _section(rrsets) -> list:
    items = []
    for rrset in rrsets:
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            items.append(
                LookupRR(
                    name=rrset.name.to_text(),
                    rdtype=rdtype,
                    ttl=int(rrset.ttl),
                    data=rdata.to_text(),
                    wire=rdata.to_wire(),
                ))
    return items


def _harvest_message(message, glue: dict) -> None:
    for section in (message.additional, message.answer):
        for rrset in section:
            if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
                continue
            for rdata in rrset:
                _remember(glue, rrset.name, getattr(rdata, "address", None))


def _remember(glue: dict, owner, address) -> None:
    ip = _ip_text(address)
    if ip is None:
        return
    if not isinstance(owner, dns.name.Name):
        try:
            owner = _as_name(owner)
        except Exception:
            return
    bucket = glue.setdefault(owner.canonicalize(), [])
    if ip not in bucket:
        bucket.append(ip)


def _as_name(value) -> dns.name.Name:
    if isinstance(value, dns.name.Name):
        return value
    return dns.name.from_text(_name_text(value))


def _name_text(value) -> str:
    text = str(value).strip()
    if text and not text.endswith("."):
        text += "."
    return text


def _ip_text(value):
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _timeout(settings) -> float:
    raw = getattr(settings, "doh_timeout_seconds", 5.0)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 5.0
    if value <= 0:
        return 5.0
    return value


def _failure_text(exc: BaseException) -> str:
    text = str(exc).strip()
    if text:
        return f"{exc.__class__.__name__}: {text}"
    return exc.__class__.__name__
