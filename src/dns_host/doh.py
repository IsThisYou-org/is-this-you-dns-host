"""DNS lookup interface and the Web3DNS-compatible DoH JSON client.

Only the parameters documented for https://api.isthisyou.org/ are sent:
``name``, ``type``, ``do``, ``rd``, ``server``, ``servers``, ``cd``, and
``ct``. ``ct=1`` is sent only when retrying an answer whose ``TC`` flag is
set, which asks the API to use TCP. ``servers`` is a comma-separated pair
(or a final single name) of FQDNs or addresses; the API asks that pair and
returns the fastest answer. ``do=1`` responses may carry base64 ``rdata``;
that wire form is preferred over presentation text. A top-level
``Responder`` is kept when the API sends one. ``TC`` is kept on the
response.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import dns.rdataclass
import dns.rdata
import dns.rdatatype

from dns_host.names import normalise_name
from dns_host.rrtypes import parse_type, rdata_from_text


class LookupError(Exception):
    """Transport or decode failure talking to the resolver."""


@dataclass
class LookupRR:
    name: str
    rdtype: str
    ttl: int
    data: str
    wire: bytes | None = None

    def to_rdata(self):
        try:
            rdtype = parse_type(self.rdtype)
        except Exception:
            rdtype = dns.rdatatype.from_text(self.rdtype)
        if self.wire is not None:
            try:
                return dns.rdata.from_wire(dns.rdataclass.IN, rdtype,
                                           self.wire, 0, len(self.wire))
            except Exception:
                if not self.data:
                    raise
        if not self.data:
            raise LookupError(
                f"RR {self.name}/{self.rdtype} has neither rdata nor data")
        return rdata_from_text(rdtype, self.data)


@dataclass
class LookupResponse:
    status: int
    answer: list[LookupRR] = field(default_factory=list)
    authority: list[LookupRR] = field(default_factory=list)
    additional: list[LookupRR] = field(default_factory=list)
    aa: bool = False
    responder: str | None = None
    tc: bool = False


class Lookup:
    """Narrow query interface. Backends are swappable."""

    def query(
        self,
        name: str,
        rdtype: str,
        *,
        server: str | None = None,
        servers: list[str] | None = None,
        rd: int = 0,
        do: int = 1,
        cd: int | None = None,
        tcp: bool = False,
    ) -> LookupResponse:
        raise NotImplementedError


def _flag(value) -> bool:
    return value is True or value == 1 or value == "1"


def _responder(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _servers_param(servers) -> str:
    """Comma-separated ``servers=`` value. Hostnames go through ``_fqdn``."""

    tokens = []
    for item in servers:
        text = str(item).strip()
        if not text:
            continue
        try:
            ipaddress.ip_address(text)
        except ValueError:
            text = _fqdn(text)
        tokens.append(text)
    return ",".join(tokens)


def _fqdn(text: str) -> str:
    """Absolute name with a trailing dot, matching the spec's server example."""

    name = normalise_name(text, what="lookup name", allow_root=True)
    return name.to_text()


def _section(items) -> list[LookupRR]:
    out: list[LookupRR] = []
    if not items:
        return out
    for item in items:
        if "typename" in item and item["typename"]:
            rdtype = str(item["typename"])
        elif "type" in item:
            rdtype = dns.rdatatype.to_text(int(item["type"]))
        else:
            raise LookupError("DoH RR missing type")
        wire = None
        if item.get("rdata"):
            try:
                wire = base64.b64decode(item["rdata"], validate=True)
            except Exception as exc:
                raise LookupError("DoH rdata is not valid base64") from exc
        ttl = item.get("TTL", item.get("ttl", 0))
        out.append(
            LookupRR(
                name=str(item.get("name", "")),
                rdtype=rdtype,
                ttl=int(ttl or 0),
                data=str(item.get("data") or ""),
                wire=wire,
            ))
    return out


def parse_doh_json(body: dict) -> LookupResponse:
    if not isinstance(body, dict):
        raise LookupError("DoH response is not a JSON object")
    return LookupResponse(
        status=int(body.get("Status", 0)),
        answer=_section(body.get("Answer")),
        authority=_section(body.get("Authority")),
        additional=_section(body.get("Additional")),
        aa=bool(body.get("AA", False)),
        responder=_responder(body.get("Responder")),
        tc=_flag(body.get("TC")),
    )


class DohClient(Lookup):

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url
        self.timeout = timeout

    def query(
        self,
        name: str,
        rdtype: str,
        *,
        server: str | None = None,
        servers: list[str] | None = None,
        rd: int = 0,
        do: int = 1,
        cd: int | None = None,
        tcp: bool = False,
    ) -> LookupResponse:
        # Documented parameters only. ct=1 is the TCP retry.
        params = {
            "name": _fqdn(name),
            "type": str(rdtype),
            "do": str(int(do)),
            "rd": str(int(rd)),
        }
        if servers:
            params["servers"] = _servers_param(servers)
        elif server:
            text = str(server).strip()
            try:
                ipaddress.ip_address(text)
            except ValueError:
                text = _fqdn(text)
            params["server"] = text
        if cd is not None:
            params["cd"] = str(int(cd))
        if tcp:
            params["ct"] = "1"
        parts = urllib.parse.urlsplit(self.base_url)
        path = parts.path or "/"
        query = urllib.parse.urlencode(params)
        url = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, path, query, ""))
        request = urllib.request.Request(
            url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(request,
                                        timeout=self.timeout) as response:
                payload = response.read()
        except urllib.error.URLError as exc:
            raise LookupError(f"resolver request failed: {exc}") from exc
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LookupError("resolver returned non-JSON") from exc
        return parse_doh_json(decoded)
