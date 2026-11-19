"""Which NOTIFY messages to send after the catalog file changes.

The catalog is notified when its serial changes. A member is notified when it
is new or its SOA serial changed. A removal notifies the catalog only.
"""

from __future__ import annotations

import dns.rdatatype
import dns.rrset

from dns_host.catalog import catalog_soa


def plan_notifies(settings, before: tuple, after_catalog) -> list[tuple[str, object]]:
    old_serial, old_zones = before
    messages = []
    if int(after_catalog.serial) != int(old_serial):
        messages.append(
            (settings.catalog_zone.to_text(), catalog_soa(settings, after_catalog.serial))
        )
    for apex, member in sorted(after_catalog.zones.items()):
        previous = dict(old_zones).get(apex)
        if previous is None or int(previous) != int(member.serial):
            messages.append((apex, _member_soa(apex, member)))
    return messages


def _member_soa(apex: str, member):
    return dns.rrset.from_text(apex, int(member.ttl) or 300, "IN", "SOA", member.soa)


def send_plan(notifier, messages) -> None:
    if notifier is None:
        return
    for zone, soa in messages:
        notifier.notify(zone, soa)
