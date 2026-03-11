"""
Revula Admin Tools — server introspection and management tools.

Provides tools for cache management, rate-limit monitoring, and server health.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from revula import __version__
from revula.tools import TOOL_REGISTRY, text_result

# ---------------------------------------------------------------------------
# re_admin_status — server health / summary
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_admin_status",
    description=(
        "Return Revula server health and configuration summary. "
        "Shows version, Python info, registered tools, cache and rate-limit stats."
    ),
    input_schema={
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    category="admin",
)
async def _admin_status(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    from revula.server import RATE_LIMITER, RESULT_CACHE

    config = arguments.get("__config__")
    info: dict[str, Any] = {
        "version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.system(),
        "tools_registered": TOOL_REGISTRY.count(),
        "categories": sorted({t.category for t in TOOL_REGISTRY.all()}),
        "cache": RESULT_CACHE.stats(),
        "rate_limit": RATE_LIMITER.stats(),
    }
    if config is not None:
        info["available_ext_tools"] = [
            name for name, ti in config.tools.items() if ti.available
        ]
    return text_result(info)


# ---------------------------------------------------------------------------
# re_admin_cache — cache management
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_admin_cache",
    description=(
        "Manage the result cache. Actions: stats (show cache stats), "
        "clear (flush all entries), invalidate (remove one entry by key)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["stats", "clear", "invalidate"],
                "description": "Cache management action",
            },
            "key": {
                "type": "string",
                "description": "Cache key to invalidate (only for 'invalidate' action)",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    category="admin",
)
async def _admin_cache(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    from revula.server import RESULT_CACHE

    action = arguments.get("action", "stats")

    if action == "stats":
        return text_result(RESULT_CACHE.stats())
    elif action == "clear":
        RESULT_CACHE.clear()
        return text_result({"status": "cache cleared"})
    elif action == "invalidate":
        key = arguments.get("key", "")
        if not key:
            return text_result({"error": "key is required for invalidate action"})
        RESULT_CACHE.invalidate(key)
        return text_result({"status": f"invalidated key: {key}"})
    else:
        return text_result({"error": f"unknown action: {action}"})
