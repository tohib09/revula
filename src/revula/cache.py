"""
Revula Result Cache — LRU cache for expensive tool results.

Caches results of expensive operations (disassembly, decompilation, etc.)
to avoid redundant computation. Keyed by (tool_name, args_hash).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)


class ResultCache:
    """Thread-safe LRU cache for tool results."""

    def __init__(
        self,
        max_entries: int = 256,
        ttl_seconds: int = 600,
    ) -> None:
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> list[dict[str, Any]] | None:
        """Get a cached result, or None if not found/expired."""
        entry = self._cache.get(key)
        if entry is None:
            self._misses += 1
            return None

        if time.monotonic() - entry.timestamp > self._ttl:
            # Expired
            del self._cache[key]
            self._misses += 1
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._hits += 1
        return entry.result

    def put(self, key: str, result: list[dict[str, Any]]) -> None:
        """Cache a result."""
        if key in self._cache:
            self._cache.move_to_end(key)
            self._cache[key] = _CacheEntry(result=result, timestamp=time.monotonic())
        else:
            if len(self._cache) >= self._max_entries:
                self._cache.popitem(last=False)  # Remove oldest
            self._cache[key] = _CacheEntry(result=result, timestamp=time.monotonic())

    def invalidate(self, key: str) -> None:
        """Remove a specific entry."""
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear entire cache."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict[str, int]:
        """Return cache statistics."""
        total = self._hits + self._misses
        return {
            "entries": len(self._cache),
            "max_entries": self._max_entries,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_pct": int(self._hits * 100 / total) if total > 0 else 0,
        }

    @staticmethod
    def make_key(tool_name: str, arguments: dict[str, Any]) -> str:
        """Create a cache key from tool name and arguments."""
        # Strip internal keys
        clean_args = {
            k: v for k, v in sorted(arguments.items())
            if not k.startswith("__")
        }
        args_json = json.dumps(clean_args, sort_keys=True, default=str)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()[:16]
        return f"{tool_name}:{args_hash}"


class _CacheEntry:
    """Internal cache entry."""

    __slots__ = ("result", "timestamp")

    def __init__(self, result: list[dict[str, Any]], timestamp: float) -> None:
        self.result = result
        self.timestamp = timestamp
