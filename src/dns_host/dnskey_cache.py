"""Per-process cache of DNSKEY RRsets already validated to a trust anchor.

Gunicorn workers are separate processes, so each worker keeps its own cache.
Entries expire with the signature, or earlier when ``dnskey_cache_seconds``
says so. Handshake and ICANN anchors are cached separately: a key validated
under one root is not reused for the other.
"""

from __future__ import annotations

import threading


class DnskeyCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], tuple] = {}

    def get(self, root_id: str, name: str, now: int):
        key = (root_id, name)
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            expires_at, dnskey, signatures = item
            if int(expires_at) <= int(now):
                self._items.pop(key, None)
                return None
            return dnskey, signatures

    def put(self, root_id: str, name: str, expires_at: int, dnskey, signatures) -> None:
        with self._lock:
            self._items[(root_id, name)] = (int(expires_at), dnskey, signatures)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


_PROCESS_CACHE = DnskeyCache()


def get_process_cache() -> DnskeyCache:
    return _PROCESS_CACHE
