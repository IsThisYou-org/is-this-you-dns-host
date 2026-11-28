"""Apex and owner-name normalisation.

Choice (configurable only by the rules below, which are fixed):

* Trim surrounding whitespace.
* If the text has no trailing dot, one is added. A name is always stored absolute.
* Non-ASCII labels are converted with IDNA (punycode). ASCII is lowercased.
* The result is a single fully-qualified name with one trailing dot.
* Labels may contain letters, digits, underscore and hyphen. A hyphen may not
  start or end a label. Wildcards are rejected. This admits ``_auth`` labels.
* URL apex and JSON apex must be identical after this normalisation.
"""

from __future__ import annotations

import re

import dns.exception
import dns.name

from dns_host.errors import ApiError

_LABEL = re.compile(rb"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


def bad_label(message: str) -> ApiError:
    return ApiError(422, "bad_label", message)


def normalise_name(text: str, *, what: str = "name", allow_root: bool = False) -> dns.name.Name:
    if not isinstance(text, str):
        raise ApiError(400, "bad_request", f"{what} must be a string")
    raw = text.strip()
    if not raw or "/" in raw or " " in raw or "\\" in raw:
        raise bad_label(f"{what} is not a DNS name")
    if not raw.endswith("."):
        raw = raw + "."
    try:
        parsed = dns.name.from_text(raw)
    except dns.exception.DNSException as exc:
        raise bad_label(f"{what} is not a valid DNS name") from exc
    try:
        lowered = dns.name.from_text(parsed.to_text().lower())
    except dns.exception.DNSException as exc:
        raise bad_label(f"{what} is not a valid DNS name") from exc
    if lowered == dns.name.root and not allow_root:
        raise bad_label(f"{what} must not be the root")
    wire = lowered.to_wire()
    if len(wire) > 255:
        raise bad_label(f"{what} is longer than 255 octets")
    for label in lowered.labels[:-1]:
        if label == b"*":
            raise bad_label(f"{what} must not contain a wildcard label")
        if not _LABEL.fullmatch(label):
            raise bad_label(f"{what} has an illegal label")
    return lowered


def normalise_apex(text: str) -> dns.name.Name:
    return normalise_name(text, what="apex")


def name_in_bailiwick(owner: dns.name.Name, apex: dns.name.Name) -> bool:
    return owner == apex or owner.is_subdomain(apex)


def comparison_labels(text: str) -> tuple[str, ...] | None:
    """Labels for ``allow-domains`` matching.

    Lower-case and strip trailing dots, then split on dots. A missing name
    or an empty label (``..``) does not match. This does not apply the other
    name rules: those run only after a name has been allowed.
    """

    if not isinstance(text, str):
        return None
    raw = text.strip().lower().rstrip(".")
    if not raw:
        return None
    labels = tuple(raw.split("."))
    if any(label == "" for label in labels):
        return None
    return labels


def name_is_allowed(name: object, allow_domains) -> bool:
    """Return whether ``name`` may be accepted under ``allow-domains``.

    A missing or empty list allows every name. Otherwise the name must be a
    strict child of a listed domain: more labels, and those final labels
    equal the listed name. The listed name itself does not match.
    ``notisthisyou.me`` is not a child of ``isthisyou.me``. A deeper name
    such as ``a.b.isthisyou.me`` is.
    """

    if not allow_domains:
        return True
    parents = _parent_labels(allow_domains)
    if not parents:
        return False
    text = _allow_text(name)
    if text is None:
        return False
    labels = comparison_labels(text)
    if labels is not None and _strict_child(labels, parents):
        return True
    # Punycode and Unicode are the same DNS name. Try that form only when
    # the lower-cased labels did not already match, and do not report a
    # name-rule failure from here.
    if not _needs_dns_form(text):
        return False
    canonical = _dns_labels(text)
    if canonical is None:
        return False
    return _strict_child(canonical, parents)


def allow_domain_error(name: object) -> ApiError:
    """Refusal for a name that ``allow-domains`` does not accept."""

    shown = _allow_text(name)
    if not shown:
        shown = str(name).strip()
    return ApiError(
        403,
        "domain_not_allowed",
        f"{shown} is not a child of a domain listed in allow-domains",
    )


def _allow_text(name: object) -> str | None:
    if hasattr(name, "to_text"):
        text = name.to_text()
    elif isinstance(name, str):
        text = name
    else:
        return None
    if not isinstance(text, str):
        return None
    return text


def _parent_labels(allow_domains) -> list[tuple[str, ...]]:
    parents = []
    for item in allow_domains:
        labels = comparison_labels(_allow_text(item) or "")
        if labels is not None:
            parents.append(labels)
    return parents


def _strict_child(labels: tuple[str, ...], parents: list[tuple[str, ...]]) -> bool:
    for parent in parents:
        if len(labels) > len(parent) and labels[-len(parent):] == parent:
            return True
    return False


def _needs_dns_form(text: str) -> bool:
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return True
    return False


def _dns_labels(text: str) -> tuple[str, ...] | None:
    """DNS form of ``text`` (lower case, punycode), without other name rules."""

    raw = text.strip()
    if not raw:
        return None
    if not raw.endswith("."):
        raw = raw + "."
    try:
        parsed = dns.name.from_text(raw)
        lowered = dns.name.from_text(parsed.to_text().lower())
    except Exception:
        return None
    if not lowered.labels or lowered == dns.name.root:
        return None
    try:
        return tuple(label.decode("ascii") for label in lowered.labels[:-1])
    except UnicodeDecodeError:
        return None
