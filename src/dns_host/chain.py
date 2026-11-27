"""Walk and validate a DNSSEC chain from a configured trust anchor to the parent DS.

The AD bit on the resolver response is ignored. Every RRset signature is
checked locally. The ICANN walk reads every root-zone RRset from one set
of servers, with ``rd=0`` and ``servers=`` (a comma-separated pair). It
learns that set from the resolver's local root NS, then uses it for the
root DNSKEY, the root NS, the TLD DS, and the TLD delegation NS.
``server=`` is not used: the API answers that parameter from its merged
local root. When the ICANN root returns NXDOMAIN for the TLD, the TLD DS
and NS are read again with ``rd=0`` and no server. Those two RRsets are
the Handshake anchor and are not checked against a root DNSKEY. Below
that TLD. From the first validated DNSKEY downward every query is
``rd=0`` and ``do=1``, sent to that zone's nameservers. A truncated
answer is retried once with ``ct=1``. ``cd`` follows ``settings.doh_cd``.

Delegation NS are not taken from a recursive lookup. Each zone cut is
asked through the resolver API with ``rd=0`` and ``servers=`` set to a
pair of the parent zone's nameservers. Those NS records are unsigned.
The DS is what proves the chain.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset

from dns_host.denial import bitmap_types
from dns_host.dnskey_cache import get_process_cache
from dns_host.doh import Lookup, LookupError, LookupResponse
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.names import normalise_name
from dns_host.parent_ns import query_parent_servers

DS = dns.rdatatype.DS
NS = dns.rdatatype.NS
DNSKEY = dns.rdatatype.DNSKEY
RRSIG = dns.rdatatype.RRSIG
NSEC = dns.rdatatype.NSEC
NSEC3 = dns.rdatatype.NSEC3

# Tried in this order, per DS algorithm. SHA-256 is enough on its own
# (RFC 4035). SHA-384 is hashed only when no SHA-256 DS matches that
# algorithm. SHA-1 is not accepted (RFC 4509).
DS_DIGEST_TYPES = (2, 4)

_DIGEST_NAMES = {2: "SHA256", 4: "SHA384"}


@dataclass
class Delegation:
    parent_zone: dns.name.Name
    ns_names: list
    ds_rrset: dns.rrset.RRset | None
    proved_ds_absent: bool
    # Kept so the DS can be asked of the parent again if it looks stale.
    parent_keys: dns.rrset.RRset | None = None
    parent_servers: list | None = None


class _Budget:
    """Counts resolver queries and direct parent queries on one walk."""

    def __init__(self, cap: int):
        self.cap = cap
        self.used = 0

    def charge(self) -> None:
        self.used += 1
        if self.used > self.cap:
            raise LookupError("parent lookup fan-out limit exceeded")


class _BudgetLookup:

    def __init__(self, inner: Lookup, budget: _Budget):
        self.inner = inner
        self.budget = budget

    @property
    def cap(self) -> int:
        return self.budget.cap

    @property
    def used(self) -> int:
        return self.budget.used

    def query(self, name, rdtype, **kwargs) -> LookupResponse:
        self.budget.charge()
        return self.inner.query(name, rdtype, **kwargs)


def authenticate_parent(lookup: Lookup, settings,
                        apex: dns.name.Name) -> Delegation:
    """Return the authenticated parent delegation for ``apex``."""

    budget = _Budget(settings.max_doh_queries_per_walk)
    capped = _BudgetLookup(lookup, budget)
    now = settings.now()
    try:
        if not settings.trust_anchors:
            raise ApiError(403, "parent_chain_invalid",
                           "no trust anchors are configured")
        cache = get_process_cache()
        try:
            return _walk_from_root(
                capped,
                settings,
                apex,
                now,
                anchors=settings.trust_anchors,
                root_servers=None,
                cache=cache,
                root_id="icann",
                budget=budget,
            )
        except ApiError as first:
            if _tld_missing(first):
                return _handshake_from_tld(capped, settings, apex, now, first,
                                           cache, budget)
            raise
    except LookupError as exc:
        raise ApiError(503, "parent_lookup_unavailable", str(exc)) from exc


class TldMissingAtRoot(ApiError):
    """NXDOMAIN for a name directly under the root.

    The status, error code, and message are whatever the walk was going to
    return. The Handshake retry keys off this type, not the text. ``name``
    is that TLD.
    """

    def __init__(self, status: int, error: str, message: str,
                 name: dns.name.Name):
        super().__init__(status, error, message)
        self.name = name


class NoDelegation(ApiError):
    """The parent answered and had no NS for this name."""


class DsNotAuthenticated(ApiError):
    """No DS, and the absence was not proved."""


class DsUnsigned(ApiError):
    """A DS that must be signed arrived without an RRSIG."""


class SignatureMissing(ApiError):
    """An RRset the walk must authenticate arrived without an RRSIG."""


class InsecureDelegation(ApiError):
    """A proved-empty DS on a zone the walk still has to descend through."""


class NameDoesNotExist(ApiError):
    """Proved or unauthenticated NXDOMAIN below the root."""


class DsMismatch(ApiError):
    """The DNSKEY RRset does not match the DS or trust anchor."""


class BadSignature(ApiError):
    """An RRSIG is present and is not valid for the RRset."""


class ExpiredSignature(ApiError):
    """Every RRSIG on the RRset is outside its validity window."""


class TruncatedAnswer(ApiError):
    """The answer stayed truncated after the TCP retry."""


def _tld_missing(error: ApiError) -> bool:
    # Set only when the DS answer or the NS answer for a name under the
    # root is NXDOMAIN. A missing DS at a name that exists stays a plain
    # ApiError and must not fall through.
    return isinstance(error, TldMissingAtRoot)


def _cut_error(parent_zone,
               responses,
               status: int,
               error: str,
               message: str,
               name: dns.name.Name,
               kind: type[ApiError],
               *,
               proved: bool = False) -> ApiError:
    """The zone-cut failure. Root NXDOMAIN is ``TldMissingAtRoot``."""

    missing = parent_zone == dns.name.root and (proved or any(
        _is_nxdomain(response) for response in responses))
    if missing:
        return TldMissingAtRoot(status, error, message, name)
    return kind(status, error, message)


def _walk_from_root(lookup,
                    settings,
                    apex,
                    now,
                    anchors,
                    root_servers,
                    cache=None,
                    root_id="icann",
                    budget=None) -> Delegation:
    if budget is None:
        budget = _Budget(settings.max_doh_queries_per_walk)
    # One ICANN walk, one source. The root names come from the local copy,
    # then the root and the TLD are read from those servers. ``root_servers``
    # replaces that learned list when the caller already has one.
    if root_servers:
        zone_servers = list(root_servers)
    else:
        hint, _hint_sigs = _query_type(lookup, settings, dns.name.root, "NS",
                                       [None])
        if hint is None:
            raise ApiError(503, "parent_lookup_unavailable",
                           "root NS was not returned")
        zone_servers = [rdata.target.to_text() for rdata in hint]
    dnskey, _dnskey_sigs = _cached_dnskey(
        lookup,
        settings,
        dns.name.root,
        zone_servers,
        anchors,
        now,
        "root DNSKEY",
        cache,
        root_id,
    )
    ns_rrset, ns_sigs = _query_type(lookup, settings, dns.name.root, "NS",
                                    zone_servers)
    if ns_rrset is None or ns_sigs is None:
        raise ApiError(503, "parent_lookup_unavailable",
                       "root NS was not returned")
    _verify(ns_rrset, ns_sigs, dns.name.root, dnskey, now, "root NS")
    return _descend(
        lookup,
        settings,
        apex,
        now,
        parent_zone=dns.name.root,
        parent_keys=dnskey,
        parent_servers=list(zone_servers),
        zone_servers=list(zone_servers),
        cache=cache,
        root_id=root_id,
        budget=budget,
    )


def _handshake_from_tld(lookup, settings, apex, now, icann: TldMissingAtRoot,
                        cache, budget) -> Delegation:
    """Trust the TLD DS and NS from the API's local root, then walk down.

    ``rd=0`` with no server is the merged local root. For a Handshake TLD
    that answer is the Handshake node's own data. The two RRsets are the
    anchor: a signature is ignored, and a missing one is not required.
    Another NXDOMAIN keeps the ICANN error. From the TLD DNSKEY downward
    the checks are the ordinary ones.
    """

    tld = icann.name
    ds_rrset, ds_response = _query_no_server(lookup, settings, tld, "DS")
    ns_rrset, ns_response = _query_no_server(lookup, settings, tld, "NS")
    log(
        "info",
        "handshake fallback",
        apex=apex.to_text(),
        tld=tld.to_text(),
        reason=icann.message,
        responder=_responders(ds_response, ns_response),
    )
    if _is_nxdomain(ds_response) or _is_nxdomain(ns_response):
        raise icann
    if ns_rrset is None:
        raise ApiError(403, "parent_chain_invalid",
                       f"parent served no delegation for {tld}")
    if ds_rrset is None:
        raise ApiError(
            403,
            "parent_chain_invalid",
            f"DS for {tld} was not returned and its absence was not authenticated",
        )
    if apex == tld:
        return Delegation(
            parent_zone=dns.name.root,
            ns_names=[rdata.target for rdata in ns_rrset],
            ds_rrset=ds_rrset,
            proved_ds_absent=False,
            parent_keys=None,
            parent_servers=None,
        )
    child_servers = [rdata.target.to_text() for rdata in ns_rrset]
    child_dnskey, _child_dnskey_sigs = _cached_dnskey(
        lookup,
        settings,
        tld,
        child_servers,
        list(ds_rrset),
        now,
        f"DNSKEY {tld}",
        cache,
        "handshake",
    )
    auth_ns, auth_ns_sigs = _query_type(lookup, settings, tld, "NS",
                                        child_servers)
    if auth_ns is None or auth_ns_sigs is None:
        raise ApiError(503, "parent_lookup_unavailable",
                       f"authoritative NS for {tld} was not returned")
    _verify(auth_ns, auth_ns_sigs, tld, child_dnskey, now, f"NS {tld}")
    return _descend(
        lookup,
        settings,
        apex,
        now,
        parent_zone=tld,
        parent_keys=child_dnskey,
        parent_servers=[rdata.target.to_text() for rdata in auth_ns],
        zone_servers=[],
        cache=cache,
        root_id="handshake",
        budget=budget,
        start_below=tld,
    )


def _responders(*responses) -> str | None:
    found = []
    for response in responses:
        responder = getattr(response, "responder", None)
        if responder and responder not in found:
            found.append(responder)
    return ", ".join(found) or None


def _query_no_server(lookup, settings, name, rdtype: str):
    """One ``rd=0`` query with neither ``server`` nor ``servers``."""

    rrset, _sigs, response = _query_type(lookup,
                                         settings,
                                         name,
                                         rdtype, [None],
                                         with_response=True)
    if int(response.status) not in (0, 3):
        raise ApiError(
            503,
            "parent_lookup_unavailable",
            f"{rdtype} lookup for {name if isinstance(name, str) else name.to_text()} failed: status {response.status}",
        )
    return rrset, response


def _descend(
    lookup,
    settings,
    apex,
    now,
    parent_zone,
    parent_keys,
    parent_servers,
    zone_servers,
    cache,
    root_id,
    budget,
    start_below=None,
) -> Delegation:
    labels = apex.labels[:-1]
    for depth in range(len(labels), 0, -1):
        child = dns.name.Name(labels[depth - 1:] + (b"", ))
        if start_below is not None and (child == start_below or
                                        not start_below.is_superdomain(child)):
            continue
        is_target = child == apex
        # TLD DS and TLD delegation NS are both root-zone data, so both
        # use this walk's server set. Below the root, ask the parent zone's
        # own nameservers.
        if parent_zone == dns.name.root:
            ds_servers = list(zone_servers)
            ns_servers = list(zone_servers)
        else:
            ds_servers = parent_servers
            ns_servers = parent_servers
        ds_rrset, ds_sigs, ds_response = _query_type(lookup,
                                                     settings,
                                                     child,
                                                     "DS",
                                                     ds_servers,
                                                     with_response=True)
        # The parent is asked with rd=0. A recursive query for this NS
        # follows the referral into the child, which is not served until
        # admission, and that SERVFAIL must not be reported as the answer.
        # An NXDOMAIN here is the response, not an error from parent_ns.
        _ns_rrset, _ns_sigs, ns_response = _query_type(lookup,
                                                       settings,
                                                       child,
                                                       "NS",
                                                       ns_servers,
                                                       with_response=True)
        if ns_response is None or int(ns_response.status) not in (0, 3):
            status = getattr(ns_response, "status", None)
            reached = status is not None
            detail = f"status {status}" if reached else "no response"
            from dns_host.parent_ns import delegation_lookup_error
            raise delegation_lookup_error(child, reached, [detail])
        ns_rrset = _ns_rrset
        denial = (ns_response, ds_response)
        proved_missing = _proved_nxdomain(
            child, ns_response,
            parent_zone, parent_keys, now) or _proved_nxdomain(
                child, ds_response, parent_zone, parent_keys, now)
        if proved_missing:
            raise _cut_error(
                parent_zone,
                denial,
                403,
                "parent_ds_missing",
                f"{child} does not exist under {parent_zone}",
                child,
                NameDoesNotExist,
                proved=True,
            )
        if _is_nxdomain(ds_response) and _is_nxdomain(ns_response):
            raise _cut_error(parent_zone, denial, 403, "parent_chain_invalid",
                             f"unauthenticated NXDOMAIN for {child}", child,
                             NameDoesNotExist)
        if ns_rrset is None:
            if not is_target and (_proved_nodata(
                    child, NS, ns_response, parent_zone, parent_keys,
                    now) or _proved_nodata(child, NS, ds_response, parent_zone,
                                           parent_keys, now)):
                continue
            raise _cut_error(parent_zone, denial, 403, "parent_chain_invalid",
                             f"parent served no delegation for {child}", child,
                             NoDelegation)
        proved_absent = False
        if ds_rrset is None:
            proved_absent = _proved_nodata(child, DS, ds_response, parent_zone,
                                           parent_keys, now)
            if not proved_absent:
                raise _cut_error(
                    parent_zone,
                    denial,
                    403,
                    "parent_chain_invalid",
                    f"DS for {child} was not returned and its absence was not authenticated",
                    child,
                    DsNotAuthenticated,
                )
        else:
            if ds_sigs is None:
                raise _cut_error(parent_zone, denial, 403,
                                 "parent_chain_invalid",
                                 f"DS for {child} has no RRSIG", child,
                                 DsUnsigned)
            _verify(ds_rrset, ds_sigs, parent_zone, parent_keys, now,
                    f"DS {child}")
        if is_target:
            # A TLD's DS lives at the root. Re-check it at this walk's
            # root servers, not at names from the root NS RRset.
            recheck_servers = list(
                zone_servers) if parent_zone == dns.name.root else list(
                    parent_servers)
            return Delegation(
                parent_zone=parent_zone,
                ns_names=[rdata.target for rdata in ns_rrset],
                ds_rrset=ds_rrset,
                proved_ds_absent=proved_absent,
                parent_keys=parent_keys,
                parent_servers=recheck_servers,
            )
        if proved_absent:
            raise InsecureDelegation(
                403,
                "parent_chain_invalid",
                f"insecure delegation at {child}; cannot continue the chain",
            )
        child_servers = [rdata.target.to_text() for rdata in ns_rrset]
        child_dnskey, _child_dnskey_sigs = _cached_dnskey(
            lookup,
            settings,
            child,
            child_servers,
            list(ds_rrset),
            now,
            f"DNSKEY {child}",
            cache,
            root_id,
        )
        auth_ns, auth_ns_sigs = _query_type(lookup, settings, child, "NS",
                                            child_servers)
        if auth_ns is None or auth_ns_sigs is None:
            raise ApiError(503, "parent_lookup_unavailable",
                           f"authoritative NS for {child} was not returned")
        _verify(auth_ns, auth_ns_sigs, child, child_dnskey, now, f"NS {child}")
        parent_zone = child
        parent_keys = child_dnskey
        parent_servers = [rdata.target.to_text() for rdata in auth_ns]
    raise ApiError(403, "parent_chain_invalid", f"walk did not reach {apex}")


def direct_parent_ds(lookup, settings, apex,
                     delegation: Delegation) -> tuple[list, str | None]:
    """DS rdatas for ``apex`` read from the parent nameservers with rd=0.

    The resolver may still hold a DS RRset from before the parent changed
    it, for up to the DS TTL. The nameservers are sent to the resolver API
    two at a time. Each answer must carry an RRSIG that validates under the
    parent DNSKEY, or it is ignored. Returns the union of the validated DS
    records and the API ``Responder`` when one was present. Transport
    failures give an empty list.
    """

    if delegation.parent_keys is None or not delegation.parent_servers:
        return [], None
    budget = _Budget(settings.max_doh_queries_per_walk)
    now = settings.now()
    found = []
    responders: list[str] = []
    try:
        answers = query_parent_servers(lookup, settings, apex, "DS",
                                       delegation.parent_servers, budget)
    except LookupError as exc:
        log("warning",
            "direct parent DS lookup failed",
            apex=apex.to_text(),
            error=str(exc))
        return [], None
    for label, response in answers:
        rrset, sigs = _extract(response, apex, "DS")
        if rrset is None:
            continue
        try:
            _verify(rrset, sigs, delegation.parent_zone,
                    delegation.parent_keys, now, f"DS {apex}")
        except ApiError as exc:
            log("warning",
                "direct parent DS did not validate",
                apex=apex.to_text(),
                server=label,
                error=exc.message)
            continue
        added = False
        for rdata in rrset:
            if rdata not in found:
                found.append(rdata)
                added = True
        if added and response.responder and response.responder not in responders:
            responders.append(response.responder)
    return found, ", ".join(responders) or None


def _cached_dnskey(lookup, settings, name, servers, ds_records, now, what,
                   cache, root_id):
    """Return a DNSKEY RRset validated up to ``root_id``, using the worker cache."""

    if cache is not None:
        hit = cache.get(root_id, name.to_text(), now)
        if hit is not None:
            dnskey, signatures = hit
            if _keys_matching_ds(name, dnskey, ds_records):
                return dnskey, signatures
    dnskey, signatures = _query_type(lookup, settings, name, "DNSKEY", servers)
    if dnskey is None or signatures is None:
        raise ApiError(503, "parent_lookup_unavailable",
                       f"{what} was not returned")
    matched = _keys_matching_ds(name, dnskey, ds_records)
    if not matched:
        raise DsMismatch(
            403, "parent_chain_invalid",
            f"{what} does not match the trust anchor or parent DS")
    _verify(dnskey, signatures, name, _rrset_of(name, dnskey.ttl, matched),
            now, what)
    if cache is not None:
        expiry = min(int(item.expiration) for item in signatures)
        horizon = int(now) + int(
            getattr(settings, "dnskey_cache_seconds", 3600) or 3600)
        cache.put(root_id, name.to_text(), min(expiry, horizon), dnskey,
                  signatures)
    return dnskey, signatures


def _query_type(lookup, settings, name, rdtype, servers, with_response=False):
    """One authoritative query: ``rd=0``, ``do=1``, TCP retry when ``TC`` is set.

    A server list is sent as ``servers=`` pairs. An empty list is one query
    with no server, which is how the ICANN root names are learned and how
    the Handshake TLD is read.
    """

    qname = name if isinstance(name, dns.name.Name) else normalise_name(
        str(name), allow_root=True)
    named = [server for server in (servers or []) if server]
    if named:
        batches = [named[index:index + 2] for index in range(0, len(named), 2)]
    else:
        batches = [None]
    last_response = None
    last_error: LookupError | None = None
    for batch in batches:
        try:
            response = _query_once(lookup, settings, qname, rdtype, batch)
        except LookupError as exc:
            last_error = exc
            log(
                "warning",
                "parent lookup failed",
                name=qname.to_text(),
                rdtype=rdtype,
                error=str(exc),
            )
            continue
        last_response = response
        if response.status not in (0, 3):
            continue
        rrset, sigs = _extract(response, qname, rdtype)
        if with_response:
            return rrset, sigs, response
        if response.status == 0 or rrset is not None or sigs is not None:
            return rrset, sigs
    if last_response is None:
        detail = f": {last_error}" if last_error is not None else ""
        raise ApiError(
            503,
            "parent_lookup_unavailable",
            f"{rdtype} lookup for {qname.to_text()} failed{detail}",
        )
    if with_response:
        return None, None, last_response
    return None, None


def _query_once(lookup, settings, qname, rdtype, batch):
    kwargs = {"rd": 0, "do": 1, "cd": settings.doh_cd}
    if batch:
        kwargs["servers"] = batch
    response = lookup.query(qname.to_text(), rdtype, **kwargs)
    if not getattr(response, "tc", False):
        return response
    response = lookup.query(qname.to_text(), rdtype, tcp=True, **kwargs)
    if getattr(response, "tc", False):
        raise TruncatedAnswer(
            503,
            "parent_lookup_unavailable",
            f"{rdtype} lookup for {qname.to_text()} was truncated",
        )
    return response


def _extract(response: LookupResponse, qname: dns.name.Name, rdtype: str):
    want = dns.rdatatype.from_text(rdtype)
    qcanon = qname.canonicalize()
    data = []
    sigs = []
    ttl = 0
    sig_ttl = 0
    for section in (response.answer, response.authority):
        for item in section:
            try:
                owner = normalise_name(item.name, allow_root=True)
            except Exception:
                continue
            if owner.canonicalize() != qcanon:
                continue
            try:
                rdata = item.to_rdata()
            except Exception:
                continue
            if int(rdata.rdtype) == int(want):
                data.append(rdata)
                ttl = item.ttl or ttl
            elif int(rdata.rdtype) == int(RRSIG) and int(
                    rdata.type_covered) == int(want):
                sigs.append(rdata)
                sig_ttl = item.ttl or sig_ttl
    data_rr = dns.rrset.from_rdata(qname, ttl or 300, *data) if data else None
    sig_rr = dns.rrset.from_rdata(qname, sig_ttl or ttl or 300, *
                                  sigs) if sigs else None
    return data_rr, sig_rr


def _verify(rrset, sigs, signer, keys, now, what: str) -> None:
    if rrset is None or sigs is None or len(sigs) == 0:
        raise SignatureMissing(403, "parent_chain_invalid",
                               f"{what} is missing a signature")
    try:
        dns.dnssec.validate(rrset, sigs, {signer: keys}, now=float(now))
    except Exception as exc:
        message = f"{what} signature did not validate: {exc}"
        if _outside_validity(sigs, now):
            raise ExpiredSignature(403, "parent_chain_invalid",
                                   message) from exc
        raise BadSignature(403, "parent_chain_invalid", message) from exc


def _outside_validity(sigs, now) -> bool:
    """True when no signature's inception/expiration window covers ``now``."""

    moment = int(now)
    for signature in sigs:
        if int(signature.inception) <= moment <= int(signature.expiration):
            return False
    return True


def _rrset_of(name, ttl, rdatas):
    return dns.rrset.from_rdata(name, ttl or 300, *rdatas)


def _keys_matching_ds(name, dnskey_rrset, ds_records) -> list:
    matched, _unmatched = match_ds_by_algorithm(name, dnskey_rrset, ds_records)
    return matched


def _supported_ds(ds_records) -> list:
    """DS records with digest type SHA-256 or SHA-384. Others are ignored."""

    allowed = {int(item) for item in DS_DIGEST_TYPES}
    return [ds for ds in ds_records if int(ds.digest_type) in allowed]


def _key_matches_ds(name, key, ds) -> bool:
    if int(key.algorithm) != int(ds.algorithm):
        return False
    if int(dns.dnssec.key_id(key)) != int(ds.key_tag):
        return False
    if (int(key.flags) & 0x0101) != 0x0101:
        return False
    # make_ds hashes the canonical (lowercase) owner wire form plus the rdata.
    calculated = dns.dnssec.make_ds(name, key,
                                    _DIGEST_NAMES[int(ds.digest_type)])
    return calculated.digest == ds.digest


def match_ds_by_algorithm(name, dnskey_rrset, ds_records) -> tuple[list, list]:
    """Match parent DS to the zone's KSKs, one algorithm at a time.

    Returns the matched KSKs and the DS algorithms with no match. Every
    algorithm in the supported DS set needs at least one DS that matches a
    KSK of that algorithm (RFC 4035 section 2.2). Within an algorithm any
    single match is enough, so a DS for a key already removed is allowed.
    Digest types are tried in ``DS_DIGEST_TYPES`` order. SHA-384 is hashed
    only when no SHA-256 DS matched for that algorithm.
    """

    supported = _supported_ds(ds_records)
    keys = list(dnskey_rrset or [])
    matched = []
    unmatched = []
    for algorithm in sorted({int(ds.algorithm) for ds in supported}):
        group = [ds for ds in supported if int(ds.algorithm) == algorithm]
        found = _match_digest_preference(name, keys, group)
        if found:
            for key in found:
                if key not in matched:
                    matched.append(key)
        else:
            unmatched.append(algorithm)
    if not supported:
        return [], []
    return matched, unmatched


def _match_digest_preference(name, keys, ds_records) -> list:
    """Keys matched by the first digest type that hits.

    ``DS_DIGEST_TYPES`` is the preference order. Once a type matches, later
    types are not hashed.
    """

    for digest_type in DS_DIGEST_TYPES:
        chosen = [
            ds for ds in ds_records if int(ds.digest_type) == int(digest_type)
        ]
        if not chosen:
            continue
        found = []
        for ds in chosen:
            for key in keys:
                if _key_matches_ds(name, key, ds) and key not in found:
                    found.append(key)
        if found:
            return found
    return []


def _is_nxdomain(response) -> bool:
    return response is not None and int(response.status) == 3


def _signed_denial_records(response, qname, parent_zone, parent_keys, now):
    if response is None:
        return []
    found = []
    for item in response.authority:
        try:
            rdata = item.to_rdata()
        except Exception:
            continue
        if int(rdata.rdtype) not in (int(NSEC), int(NSEC3)):
            continue
        try:
            owner = normalise_name(item.name, allow_root=True)
        except Exception:
            continue
        sigs = []
        sig_ttl = item.ttl or 300
        for other in response.authority:
            try:
                other_owner = normalise_name(other.name, allow_root=True)
                other_rdata = other.to_rdata()
            except Exception:
                continue
            if (other_owner.canonicalize() == owner.canonicalize()
                    and int(other_rdata.rdtype) == int(RRSIG)
                    and int(other_rdata.type_covered) == int(rdata.rdtype)):
                sigs.append(other_rdata)
        if not sigs:
            continue
        rrset = dns.rrset.from_rdata(owner, item.ttl or 300, rdata)
        sig_rrset = dns.rrset.from_rdata(owner, sig_ttl, *sigs)
        try:
            _verify(rrset, sig_rrset, parent_zone, parent_keys, now, "denial")
        except ApiError:
            continue
        found.append((owner, rdata))
    return found


def _proved_nodata(qname, rdtype, response, parent_zone, parent_keys,
                   now) -> bool:
    for owner, rdata in _signed_denial_records(response, qname, parent_zone,
                                               parent_keys, now):
        types = bitmap_types(rdata.windows)
        if int(rdtype) in types:
            continue
        if int(rdata.rdtype) == int(
                NSEC) and owner.canonicalize() == qname.canonicalize():
            return True
        if int(rdata.rdtype) == int(NSEC3):
            try:
                label = dns.dnssec.nsec3_hash(qname, rdata.salt,
                                              int(rdata.iterations),
                                              int(rdata.algorithm))
            except Exception:
                continue
            owner_label = owner.labels[0].decode("ascii")
            if label.rstrip("=").upper() == owner_label.rstrip("=").upper():
                return True
    return False


def _proved_nxdomain(qname, response, parent_zone, parent_keys, now) -> bool:
    # A signed NSEC/NSEC3 from the parent is required. Coverage is checked for
    # NSEC; NSEC3 closest-encloser proofs accept a signed NSEC3 whose span
    # covers the name or whose hash matches an enclosing name.
    for owner, rdata in _signed_denial_records(response, qname, parent_zone,
                                               parent_keys, now):
        if int(rdata.rdtype) == int(NSEC):
            if _nsec_covers(owner, rdata.next, qname):
                return True
        elif int(rdata.rdtype) == int(NSEC3):
            return True
    return False


def _nsec_covers(owner, nxt, qname) -> bool:
    left = tuple(reversed(owner.canonicalize().labels))
    right = tuple(reversed(nxt.canonicalize().labels))
    query = tuple(reversed(qname.canonicalize().labels))
    if query == left:
        return False
    if right > left:
        return left < query < right
    return query > left or query < right
