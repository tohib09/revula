"""
Revula Hex Utilities — hexdump, pattern search, binary diff.

Features:
- Classic xxd-style hexdump with structure annotation
- Wildcard byte pattern search: "55 8B EC ?? ?? 83 EC"
- Binary diff with change map
"""

from __future__ import annotations

import re
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

# ---------------------------------------------------------------------------
# Hexdump
# ---------------------------------------------------------------------------


def hexdump(
    data: bytes,
    offset: int = 0,
    length: int = 0,
    width: int = 16,
    base_addr: int = 0,
) -> str:
    """Generate xxd-style hexdump."""
    if length > 0:
        data = data[offset:offset + length]
    elif offset > 0:
        data = data[offset:]

    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        addr = base_addr + offset + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr:08x}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pattern search
# ---------------------------------------------------------------------------


def pattern_to_regex(pattern: str) -> bytes:
    """
    Convert a hex pattern with wildcards to a regex.
    Pattern: "55 8B EC ?? ?? 83 EC" where ?? matches any byte.
    """
    tokens = pattern.strip().split()
    regex_parts: list[str] = []

    for token in tokens:
        token = token.strip()
        if token in ("??", "?"):
            regex_parts.append(".")
        elif all(c in "0123456789abcdefABCDEF" for c in token) and len(token) == 2:
            regex_parts.append(re.escape(bytes.fromhex(token)).decode("latin-1"))
        else:
            raise ValueError(f"Invalid pattern token: {token}")

    pattern_str = "".join(regex_parts)
    return pattern_str.encode("latin-1")


def search_pattern(
    data: bytes,
    pattern: str,
    max_results: int = 100,
    context_bytes: int = 16,
) -> list[dict[str, Any]]:
    """Search for a byte pattern with wildcards in binary data."""
    regex = pattern_to_regex(pattern)
    compiled = re.compile(regex, re.DOTALL)

    results: list[dict[str, Any]] = []
    for m in compiled.finditer(data):
        if len(results) >= max_results:
            break

        offset = m.start()
        matched = m.group()
        ctx_start = max(0, offset - context_bytes)
        ctx_end = min(len(data), offset + len(matched) + context_bytes)

        results.append({
            "offset": offset,
            "address": f"0x{offset:x}",
            "matched_bytes": matched.hex(),
            "matched_length": len(matched),
            "context_hex": data[ctx_start:ctx_end].hex(),
            "context_start": ctx_start,
        })

    return results


# ---------------------------------------------------------------------------
# Binary diff
# ---------------------------------------------------------------------------


def binary_diff(
    data_a: bytes,
    data_b: bytes,
    max_diffs: int = 200,
) -> dict[str, Any]:
    """Compare two binary blobs and return change map."""
    min_len = min(len(data_a), len(data_b))
    max(len(data_a), len(data_b))

    diffs: list[dict[str, Any]] = []
    diff_ranges: list[tuple[int, int]] = []  # (start, end) of contiguous diff regions
    current_start: int | None = None

    for i in range(min_len):
        if data_a[i] != data_b[i]:
            if current_start is None:
                current_start = i
            if len(diffs) < max_diffs:
                diffs.append({
                    "offset": i,
                    "old": f"0x{data_a[i]:02x}",
                    "new": f"0x{data_b[i]:02x}",
                })
        else:
            if current_start is not None:
                diff_ranges.append((current_start, i))
                current_start = None

    if current_start is not None:
        diff_ranges.append((current_start, min_len))

    return {
        "size_a": len(data_a),
        "size_b": len(data_b),
        "size_diff": len(data_b) - len(data_a),
        "total_byte_differences": sum(1 for i in range(min_len) if data_a[i] != data_b[i]),
        "diff_regions": [{"start": s, "end": e, "length": e - s} for s, e in diff_ranges],
        "diffs": diffs,
        "truncated": len(diffs) >= max_diffs,
    }


# ---------------------------------------------------------------------------
# Tool registrations
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_hexdump",
    description=(
        "Generate annotated hexdump of binary data. Classic xxd-style output. "
        "Supports offset/length ranges and custom width."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary file.",
            },
            "hex_bytes": {
                "type": "string",
                "description": "Hex string to dump (alternative to binary_path).",
            },
            "offset": {
                "type": "integer",
                "description": "Start offset. Default: 0.",
                "default": 0,
            },
            "length": {
                "type": "integer",
                "description": "Number of bytes to dump. Default: 256.",
                "default": 256,
            },
            "width": {
                "type": "integer",
                "description": "Bytes per line. Default: 16.",
                "default": 16,
            },
        },
    },
    category="utility",
)
async def handle_hexdump(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate hexdump."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    offset = arguments.get("offset", 0)
    length = arguments.get("length", 256)
    width = arguments.get("width", 16)

    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif binary_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
    else:
        return error_result("Provide binary_path or hex_bytes")

    dump = hexdump(data, offset=offset, length=length, width=width)
    return text_result({"hexdump": dump, "offset": offset, "length": min(length, len(data))})


@TOOL_REGISTRY.register(
    name="re_pattern_search",
    description=(
        "Search for wildcard byte patterns in binary data. "
        "Pattern syntax: '55 8B EC ?? ?? 83 EC' where ?? matches any byte. "
        "Returns all matches with context."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to binary file.",
            },
            "hex_bytes": {
                "type": "string",
                "description": "Hex data to search in (alternative to binary_path).",
            },
            "pattern": {
                "type": "string",
                "description": "Byte pattern with wildcards, e.g., '55 8B EC ?? ?? 83 EC'.",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum results. Default: 100.",
                "default": 100,
            },
            "context_bytes": {
                "type": "integer",
                "description": "Context bytes around each match. Default: 16.",
                "default": 16,
            },
        },
        "required": ["pattern"],
    },
    category="utility",
)
async def handle_pattern_search(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Search for byte patterns."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    pattern = arguments["pattern"]
    max_results = arguments.get("max_results", 100)
    context_bytes = arguments.get("context_bytes", 16)

    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif binary_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
    else:
        return error_result("Provide binary_path or hex_bytes")

    results = search_pattern(data, pattern, max_results=max_results, context_bytes=context_bytes)

    return text_result({
        "pattern": pattern,
        "data_size": len(data),
        "match_count": len(results),
        "matches": results,
    })


@TOOL_REGISTRY.register(
    name="re_bindiff",
    description=(
        "Diff two binary files at byte level. Returns change map with "
        "diff regions and individual byte differences."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path_a": {
                "type": "string",
                "description": "Absolute path to first binary file.",
            },
            "path_b": {
                "type": "string",
                "description": "Absolute path to second binary file.",
            },
            "max_diffs": {
                "type": "integer",
                "description": "Maximum individual diffs to return. Default: 200.",
                "default": 200,
            },
        },
        "required": ["path_a", "path_b"],
    },
    category="utility",
)
async def handle_bindiff(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Binary diff."""
    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None

    path_a = validate_binary_path(arguments["path_a"], allowed_dirs=allowed_dirs)
    path_b = validate_binary_path(arguments["path_b"], allowed_dirs=allowed_dirs)

    data_a = path_a.read_bytes()
    data_b = path_b.read_bytes()

    result = binary_diff(data_a, data_b, max_diffs=arguments.get("max_diffs", 200))
    result["path_a"] = str(path_a)
    result["path_b"] = str(path_b)

    return text_result(result)
