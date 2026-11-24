"""Pre-built TCP AXFR payloads.

User zones are encoded once by the API. The catalog zone is encoded by the
controller whenever the catalog changes. The TCP service streams the bytes
and only rewrites the DNS message id so it matches the query.
"""

from __future__ import annotations

import dns.flags
import dns.message

from dns_host.catalog import catalog_rrsets


def tcp_bytes(rrsets: list) -> bytes:
    if not rrsets:
        return b""
    return _frames(_chunks(rrsets))


def _chunks(rrsets: list) -> list[list]:
    soa = rrsets[0]
    chunks: list[list] = []
    current: list = [soa]
    for rrset in rrsets[1:]:
        current.append(rrset)
        if len(current) >= 8:
            chunks.append(current)
            current = []
    chunks.append(current + [soa])
    return chunks


def _frames(chunks: list[list]) -> bytes:
    out = bytearray()
    for records in chunks:
        message = dns.message.Message(id=0)
        message.flags |= dns.flags.QR | dns.flags.AA
        for rrset in records:
            message.answer.append(rrset)
        wire = message.to_wire()
        out += len(wire).to_bytes(2, "big")
        out += wire
    return bytes(out)


def with_query_id(blob: bytes, query_id: int) -> bytes:
    """Copy of a pre-built stream whose message ids match ``query_id``."""

    ident = int(query_id).to_bytes(2, "big")
    out = bytearray()
    offset = 0
    while offset + 2 <= len(blob):
        length = int.from_bytes(blob[offset : offset + 2], "big")
        offset += 2
        end = offset + length
        if end > len(blob) or length < 2:
            break
        message = bytearray(blob[offset:end])
        message[0:2] = ident
        out += len(message).to_bytes(2, "big")
        out += message
        offset = end
    return bytes(out)


def catalog_tcp_bytes(settings, serial: int, members: list[str]) -> bytes:
    return tcp_bytes(catalog_rrsets(settings, serial, members))
