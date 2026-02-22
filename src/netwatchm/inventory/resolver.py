"""Async reverse-DNS hostname resolver with LRU cache."""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from functools import lru_cache

logger = logging.getLogger(__name__)

_NEGATIVE_TTL = 300.0  # 5 minutes for failed lookups
_CACHE_SIZE = 2048


@lru_cache(maxsize=_CACHE_SIZE)
def _sync_resolve(ip: str) -> str | None:
    """Synchronous DNS lookup, cached with LRU."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


class DNSResolver:
    """Async wrapper around reverse-DNS with timeout and negative-result caching."""

    def __init__(self, timeout: float = 2.0, cache_ttl: float = _NEGATIVE_TTL) -> None:
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        # IP → (hostname_or_None, expiry_epoch) for negative/positive caching
        self._negative_cache: dict[str, float] = {}

    async def resolve(self, ip: str) -> str | None:
        """Resolve ip to hostname. Returns None on failure."""
        # Check negative cache
        if ip in self._negative_cache:
            if time.time() < self._negative_cache[ip]:
                return None
            del self._negative_cache[ip]

        loop = asyncio.get_event_loop()
        try:
            hostname = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_resolve, ip),
                timeout=self._timeout,
            )
            if hostname is None:
                self._negative_cache[ip] = time.time() + self._cache_ttl
            return hostname
        except asyncio.TimeoutError:
            logger.debug("DNS timeout for %s", ip)
            self._negative_cache[ip] = time.time() + self._cache_ttl
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("DNS error for %s: %s", ip, exc)
            self._negative_cache[ip] = time.time() + self._cache_ttl
            return None

    async def run_resolver_loop(
        self,
        store: "DeviceStore",  # type: ignore[name-defined]  # noqa: F821
        stop_event: asyncio.Event,
        interval: float = 5.0,
    ) -> None:
        """Periodically resolve unresolved IPs from the DeviceStore."""
        # Import here to avoid circular imports
        from ..inventory.store import DeviceStore  # noqa: F401

        while not stop_event.is_set():
            await asyncio.sleep(interval)
            if stop_event.is_set():
                break
            ips = await store.get_unresolved_ips()
            for ip in ips:
                if stop_event.is_set():
                    break
                hostname = await self.resolve(ip)
                await store.update_hostname(ip, hostname)
