"""
Revula Rate Limiter — token-bucket rate limiting for tool calls.

Prevents abuse and resource exhaustion by limiting tool call frequency.
Configurable per-tool and global limits.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    global_rpm: int = 120  # requests per minute (global)
    per_tool_rpm: int = 30  # per-tool requests per minute
    burst_size: int = 10  # max burst allowance
    enabled: bool = True


class RateLimiter:
    """Token-bucket rate limiter with per-tool tracking."""

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._global_bucket = _TokenBucket(
            rate=self._config.global_rpm / 60.0,
            capacity=self._config.burst_size,
        )
        self._tool_buckets: dict[str, _TokenBucket] = {}
        self._stats: dict[str, int] = {"allowed": 0, "denied": 0}

    def check(self, tool_name: str) -> bool:
        """Check if a tool call is allowed. Returns True if allowed."""
        if not self._config.enabled:
            return True

        # Global limit
        if not self._global_bucket.consume():
            self._stats["denied"] = self._stats.get("denied", 0) + 1
            logger.warning("Rate limit: global limit exceeded for %s", tool_name)
            return False

        # Per-tool limit
        if tool_name not in self._tool_buckets:
            self._tool_buckets[tool_name] = _TokenBucket(
                rate=self._config.per_tool_rpm / 60.0,
                capacity=self._config.burst_size,
            )

        if not self._tool_buckets[tool_name].consume():
            self._stats["denied"] = self._stats.get("denied", 0) + 1
            logger.warning("Rate limit: per-tool limit exceeded for %s", tool_name)
            return False

        self._stats["allowed"] = self._stats.get("allowed", 0) + 1
        return True

    def stats(self) -> dict[str, Any]:
        """Return rate limiter statistics."""
        return {
            "enabled": self._config.enabled,
            "global_rpm": self._config.global_rpm,
            "per_tool_rpm": self._config.per_tool_rpm,
            "allowed": self._stats.get("allowed", 0),
            "denied": self._stats.get("denied", 0),
            "active_tool_buckets": len(self._tool_buckets),
        }


class _TokenBucket:
    """Simple token bucket implementation."""

    def __init__(self, rate: float, capacity: int) -> None:
        self._rate = rate  # tokens per second
        self._capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self._capacity),
            self._tokens + elapsed * self._rate,
        )
        self._last_refill = now
