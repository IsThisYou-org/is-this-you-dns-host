# DNSSEC validation

One algorithm validates a parent chain. ICANN and Handshake differ only in the trust input. From the first validated DNSKEY downward, the steps, the query flags, and the errors are the same.

The HTTP status, `error` code, and message text below are the body a client already receives. The walk tells them apart by exception type.

## Query

Every query uses `rd=0` and `do=1`. `cd` follows `doh_cd`.

A list of nameservers is sent as `servers=`, two names at a time. The next pair is used only when the pair does not return NOERROR or NXDOMAIN. No `server=` parameter is sent.

Two queries omit `servers` as well:

* the ICANN walk's first read of the root NS, which learns the root nameserver names from the resolver's local copy
* the Handshake read of the TLD DS and the TLD NS

If the answer has `TC` set, the same query is sent once more with `ct=1`. A second truncated answer is `TruncatedAnswer`: HTTP 503 `parent_lookup_unavailable`, message `{type} lookup for {name} was truncated`.

## Trust input

**ICANN.** The configured root DS records are the trust anchor. The root DNSKEY is read from the learned root nameservers and must match that DS, and its RRSIG must validate. The root NS is read from the same servers and must validate under that DNSKEY. The walk then starts at the root.

**Handshake.** Used only when the ICANN walk raises `TldMissingAtRoot`. The TLD DS and the TLD NS are read with no server. They are the anchor: a signature is not required and is not checked. If either answer is NXDOMAIN, the ICANN error is returned unchanged. The TLD DNSKEY is then checked against that DS by the ordinary step below. There is no Handshake root DNSKEY and no Handshake trust-anchor setting.

## From a validated DNSKEY

The current zone's DNSKEY is already validated. For each name from the label below that zone down to the apex:

1. Read the child DS and the child NS from the current zone's nameservers.
2. If either answer is a proved NXDOMAIN, raise `NameDoesNotExist` (or `TldMissingAtRoot` when the current zone is the root): HTTP 403 `parent_ds_missing`, message `{child} does not exist under {parent}`.
3. If both answers are NXDOMAIN and neither proof validates, raise `NameDoesNotExist` (or `TldMissingAtRoot` at the root): HTTP 403 `parent_chain_invalid`, message `unauthenticated NXDOMAIN for {child}`.
4. If there is no NS RRset, raise `NoDelegation` (or `TldMissingAtRoot` when a root answer was NXDOMAIN): HTTP 403 `parent_chain_invalid`, message `parent served no delegation for {child}`.
5. If there is no DS, and the absence is not proved, raise `DsNotAuthenticated`: HTTP 403 `parent_chain_invalid`, message `DS for {child} was not returned and its absence was not authenticated`.
6. If the DS has no RRSIG, raise `DsUnsigned`: HTTP 403 `parent_chain_invalid`, message `DS for {child} has no RRSIG`.
7. Check the DS RRSIG under the current DNSKEY. An RRSIG whose whole set is outside its validity window is `ExpiredSignature`. Any other failure is `BadSignature`. Both are HTTP 403 `parent_chain_invalid`, message `{what} signature did not validate: {detail}`.
8. If this child is the apex, return it. The parent of the delegation is the current zone, and the DS and NS are the ones just read.
9. If the DS absence was proved, raise `InsecureDelegation`: HTTP 403 `parent_chain_invalid`, message `insecure delegation at {child}; cannot continue the chain`.
10. Read the child DNSKEY from the child NS names. It must match the DS (`DsMismatch`, HTTP 403 `parent_chain_invalid`, message `{what} does not match the trust anchor or parent DS`) and its RRSIG must validate under the matching keys.
11. Read the child NS from those same names and validate it under that DNSKEY. That NS set is where the next child is read.

A proved NXDOMAIN is a signed NSEC or NSEC3 from the parent. The resolver's AD bit is not trusted.
