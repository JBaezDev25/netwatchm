"""Tests for DNSResolver."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatchm.inventory.resolver import DNSResolver


class TestDNSResolver:
    @pytest.mark.asyncio
    async def test_resolve_success(self) -> None:
        resolver = DNSResolver(timeout=2.0)
        with patch("netwatchm.inventory.resolver._sync_resolve", return_value="myhost.local"):
            result = await resolver.resolve("10.0.0.1")
        assert result == "myhost.local"

    @pytest.mark.asyncio
    async def test_resolve_failure_returns_none(self) -> None:
        resolver = DNSResolver(timeout=2.0)
        with patch("netwatchm.inventory.resolver._sync_resolve", return_value=None):
            result = await resolver.resolve("10.0.0.99")
        assert result is None

    @pytest.mark.asyncio
    async def test_negative_cache_prevents_retry(self) -> None:
        resolver = DNSResolver(timeout=2.0, cache_ttl=9999)
        call_count = 0

        def slow_resolver(ip: str) -> None:
            nonlocal call_count
            call_count += 1
            return None

        with patch("netwatchm.inventory.resolver._sync_resolve", side_effect=slow_resolver):
            await resolver.resolve("10.0.0.50")
            await resolver.resolve("10.0.0.50")  # Should hit negative cache

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_timeout_caches_negative(self) -> None:
        resolver = DNSResolver(timeout=0.001, cache_ttl=9999)

        async def slow(_ip: str) -> str:
            await asyncio.sleep(1.0)
            return "host"

        with patch.object(
            asyncio.get_event_loop(),
            "run_in_executor",
            new=AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            result = await resolver.resolve("10.0.0.1")
        assert result is None
        assert "10.0.0.1" in resolver._negative_cache
