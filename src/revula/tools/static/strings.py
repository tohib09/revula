"""
Revula String Extraction — multi-backend string analysis with classification.

Backends:
- FLOSS (primary — handles stack strings + obfuscated strings, slow but thorough)
- strings binary (fast, ASCII/UTF-16)
- Custom regex (pattern-based extraction + classification)

Classifies strings by type: URL, IP, registry key, file path, crypto constant,
base64 blob, etc.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, text_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# String classification patterns
# ---------------------------------------------------------------------------

STRING_CLASSIFIERS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"https?://[^\s\"'<>]{5,}", re.IGNORECASE)),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"\b[0-9a-fA-F:]{6,39}\b")),
    ("email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("domain", re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,6}\b")),
    ("registry_key", re.compile(r"(HKEY_|HKLM\\|HKCU\\|SOFTWARE\\)", re.IGNORECASE)),
    ("file_path_win", re.compile(r"[A-Z]:\\[^\s\"']{3,}", re.IGNORECASE)),
    ("file_path_unix", re.compile(r"/(?:usr|etc|tmp|var|home|opt|proc|dev|bin|sbin)/[^\s\"']{2,}")),
    ("pe_section", re.compile(r"\.(text|data|rdata|rsrc|reloc|bss|idata|edata|tls|CRT)\b")),
    ("dll_name", re.compile(r"\b\w+\.dll\b", re.IGNORECASE)),
    ("crypto_const", re.compile(r"\b(AES|RSA|SHA|MD5|RC4|DES|Blowfish|Camellia|ChaCha|Salsa|HMAC)\b", re.IGNORECASE)),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")),
    ("hex_string", re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")),
    ("guid", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("mutex", re.compile(r"(?:Global|Local)\\[^\s]{3,}")),
    ("pdb_path", re.compile(r"[A-Z]:\\.*\.pdb", re.IGNORECASE)),
    ("user_agent", re.compile(r"Mozilla/\d|User-Agent:", re.IGNORECASE)),
    ("command_exec", re.compile(r"\b(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wscript|cscript)\b", re.IGNORECASE)),
]


def classify_string(s: str) -> list[str]:
    """Classify a string into categories based on patterns."""
    tags: list[str] = []
    for tag, pattern in STRING_CLASSIFIERS:
        if pattern.search(s):
            tags.append(tag)

    # Check if it looks like base64 that decodes to something meaningful
    if "base64_blob" in tags and len(s) >= 20:
        try:
            decoded = base64.b64decode(s, validate=True)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:50]):
                tags.append("base64_decoded_ascii")
        except Exception:
            # Not valid base64
            if "base64_blob" in tags:
                tags.remove("base64_blob")

    return tags


# ---------------------------------------------------------------------------
# Custom regex extraction
# ---------------------------------------------------------------------------


def _extract_strings_regex(
    data: bytes,
    min_length: int = 4,
    encoding: str = "all",
) -> list[dict[str, Any]]:
    """Extract strings using regex patterns on raw binary data."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add_matches(pattern: re.Pattern[bytes], enc_name: str) -> None:
        for m in pattern.finditer(data):
            try:
                if enc_name == "utf16le":
                    s = m.group().decode("utf-16-le").rstrip("\x00")
                else:
                    s = m.group().decode("ascii", errors="ignore")
            except Exception:
                continue

            if len(s) >= min_length and s not in seen:
                seen.add(s)
                tags = classify_string(s)
                results.append({
                    "string": s,
                    "offset": m.start(),
                    "encoding": enc_name,
                    "length": len(s),
                    "tags": tags,
                })

    # ASCII strings
    if encoding in ("ascii", "all"):
        ascii_pat = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
        _add_matches(ascii_pat, "ascii")

    # UTF-16LE strings (common in Windows PE)
    if encoding in ("utf16", "utf16le", "all"):
        utf16_pat = re.compile(
            rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
        )
        _add_matches(utf16_pat, "utf16le")

    # UTF-32 (rare but exists)
    if encoding in ("utf32", "all"):
        utf32_pat = re.compile(
            rb"(?:[\x20-\x7e]\x00\x00\x00){" + str(min_length).encode() + rb",}"
        )
        for m in utf32_pat.finditer(data):
            try:
                s = m.group().decode("utf-32-le").rstrip("\x00")
                if len(s) >= min_length and s not in seen:
                    seen.add(s)
                    tags = classify_string(s)
                    results.append({
                        "string": s,
                        "offset": m.start(),
                        "encoding": "utf32le",
                        "length": len(s),
                        "tags": tags,
                    })
            except Exception:
                continue

    return results


# ---------------------------------------------------------------------------
# FLOSS backend
# ---------------------------------------------------------------------------


async def _extract_strings_floss(
    binary_path: str,
    min_length: int = 4,
) -> dict[str, Any]:
    """Extract strings using FLOSS (including stack/obfuscated strings)."""
    from revula.config import get_config

    config = get_config()
    floss_path = config.require_tool("floss")

    cmd = [
        floss_path,
        "--json",
        "--minimum-length", str(min_length),
        binary_path,
    ]

    result = await safe_subprocess(
        cmd,
        timeout=300,  # FLOSS can be very slow on complex binaries
        max_memory_mb=1024,
    )

    if not result.success:
        raise RuntimeError(f"FLOSS failed: {result.stderr[:500]}")

    try:
        floss_data = __import__("json").loads(result.stdout)
    except Exception as e:
        raise RuntimeError(f"Failed to parse FLOSS JSON output: {e}") from e

    return floss_data  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# strings binary backend
# ---------------------------------------------------------------------------


async def _extract_strings_binary(
    binary_path: str,
    min_length: int = 4,
    encoding: str = "all",
) -> list[dict[str, Any]]:
    """Extract strings using the strings binary."""
    from revula.config import get_config

    config = get_config()
    strings_path = config.require_tool("strings")

    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    async def _run_strings(enc_flag: str, enc_name: str) -> None:
        cmd = [strings_path, "-n", str(min_length), "-t", "x"]
        if enc_flag:
            cmd.extend(["-e", enc_flag])
        cmd.append(binary_path)

        result = await safe_subprocess(cmd, timeout=60)
        if result.success:
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    try:
                        offset = int(parts[0], 16)
                    except ValueError:
                        offset = 0
                    s = parts[1]
                    if s not in seen:
                        seen.add(s)
                        tags = classify_string(s)
                        results.append({
                            "string": s,
                            "offset": offset,
                            "encoding": enc_name,
                            "length": len(s),
                            "tags": tags,
                        })

    if encoding in ("ascii", "all"):
        await _run_strings("s", "ascii")
    if encoding in ("utf16", "utf16le", "all"):
        await _run_strings("l", "utf16le")

    return results


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_extract_strings",
    description=(
        "Extract and classify strings from binary files. "
        "Backends: FLOSS (decodes stack/obfuscated strings — slow but thorough), "
        "strings binary (fast), custom regex (always available). "
        "Classifies strings by type: URL, IP, registry key, file path, crypto, base64, "
        "PDB path, mutex, command execution, etc."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file.",
            },
            "min_length": {
                "type": "integer",
                "description": "Minimum string length. Default: 4.",
                "default": 4,
            },
            "encoding": {
                "type": "string",
                "enum": ["ascii", "utf16", "utf32", "all"],
                "description": "String encoding to search for. Default: all.",
                "default": "all",
            },
            "use_floss": {
                "type": "boolean",
                "description": "Use FLOSS for stack/obfuscated string recovery (slow). Default: false.",
                "default": False,
            },
            "max_strings": {
                "type": "integer",
                "description": "Maximum number of strings to return. Default: 500.",
                "default": 500,
            },
            "filter_tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Only return strings matching these tags (e.g., ['url', 'ip_address']).",
            },
        },
        "required": ["binary_path"],
    },
    category="static",
)
async def handle_extract_strings(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract and classify strings from a binary."""
    binary_path_str = arguments["binary_path"]
    min_length = arguments.get("min_length", 4)
    encoding = arguments.get("encoding", "all")
    use_floss = arguments.get("use_floss", False)
    max_strings = arguments.get("max_strings", 500)
    filter_tags = arguments.get("filter_tags")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    all_strings: list[dict[str, Any]] = []
    backend_used = "regex"

    if use_floss:
        try:
            floss_result = await _extract_strings_floss(str(file_path), min_length)

            # Parse FLOSS output
            for category in ["static_strings", "stack_strings", "decoded_strings", "tight_strings"]:
                for s in floss_result.get("strings", {}).get(category, []):
                    string_val = s if isinstance(s, str) else s.get("string", "")
                    if len(string_val) >= min_length:
                        tags = classify_string(string_val)
                        source_tag = category.replace("_strings", "")
                        tags.insert(0, f"floss_{source_tag}")
                        all_strings.append({
                            "string": string_val,
                            "offset": s.get("offset", 0) if isinstance(s, dict) else 0,
                            "encoding": s.get("encoding", "unknown") if isinstance(s, dict) else "unknown",
                            "length": len(string_val),
                            "tags": tags,
                        })

            backend_used = "floss"
        except Exception as e:
            logger.warning("FLOSS failed, falling back to regex: %s", e)

    if backend_used != "floss":
        # Try strings binary first, fall back to regex
        try:
            all_strings = await _extract_strings_binary(str(file_path), min_length, encoding)
            backend_used = "strings"
        except Exception:
            # Fall back to regex
            data = file_path.read_bytes()
            all_strings = _extract_strings_regex(data, min_length, encoding)
            backend_used = "regex"

    # Filter by tags if specified
    if filter_tags:
        filter_set = set(filter_tags)
        all_strings = [s for s in all_strings if filter_set.intersection(s.get("tags", []))]

    # Sort by relevance: tagged strings first, then by offset
    all_strings.sort(key=lambda s: (0 if s.get("tags") else 1, s.get("offset", 0)))

    # Cap results
    total_found = len(all_strings)
    all_strings = all_strings[:max_strings]

    # Summary stats
    tag_counts: dict[str, int] = {}
    for s in all_strings:
        for tag in s.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    return text_result({
        "file_path": str(file_path),
        "backend": backend_used,
        "total_found": total_found,
        "returned": len(all_strings),
        "encoding_filter": encoding,
        "min_length": min_length,
        "tag_summary": dict(sorted(tag_counts.items(), key=lambda x: -x[1])),
        "strings": all_strings,
    })
