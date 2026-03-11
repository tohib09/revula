"""
Revula Entropy Analysis — sliding window entropy over sections and byte ranges.

Computes Shannon entropy per section and over arbitrary byte ranges with
configurable window size. Flags sections likely packed (>7.0) or sparse (<1.0).
Returns per-section entropy curves as float arrays for visualization.
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Entropy computation
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        if count > 0:
            freq = count / length
            entropy -= freq * math.log2(freq)

    return entropy


def sliding_window_entropy(
    data: bytes,
    window_size: int = 256,
    step: int = 0,
) -> list[float]:
    """
    Compute entropy over a sliding window.

    Args:
        data: Raw bytes to analyze
        window_size: Size of the sliding window in bytes
        step: Step size (0 = same as window_size for non-overlapping)

    Returns:
        List of entropy values (one per window position)
    """
    if not data:
        return []

    if step <= 0:
        step = window_size

    entropy_curve: list[float] = []

    for offset in range(0, len(data) - window_size + 1, step):
        window = data[offset:offset + window_size]
        entropy_curve.append(round(shannon_entropy(window), 4))

    return entropy_curve


def analyze_byte_distribution(data: bytes) -> dict[str, Any]:
    """Analyze byte value distribution for additional heuristics."""
    if not data:
        return {"unique_bytes": 0, "zero_ratio": 0, "printable_ratio": 0}

    length = len(data)
    counts = Counter(data)

    zero_count = counts.get(0, 0)
    printable_count = sum(counts.get(b, 0) for b in range(32, 127))

    return {
        "unique_bytes": len(counts),
        "total_bytes": length,
        "zero_ratio": round(zero_count / length, 4),
        "printable_ratio": round(printable_count / length, 4),
        "most_common": [
            {"byte": f"0x{byte:02x}", "count": cnt, "ratio": round(cnt / length, 4)}
            for byte, cnt in counts.most_common(10)
        ],
    }


# ---------------------------------------------------------------------------
# Section-level entropy analysis
# ---------------------------------------------------------------------------


def _analyze_sections_lief(file_path: str) -> list[dict[str, Any]]:
    """Analyze per-section entropy using LIEF."""
    import lief

    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"LIEF could not parse: {file_path}")

    sections = []
    for sec in binary.sections:
        content = bytes(sec.content)
        entropy = shannon_entropy(content)
        byte_dist = analyze_byte_distribution(content)

        status = "normal"
        if entropy > 7.0:
            status = "high_entropy"
        elif entropy > 6.5:
            status = "elevated_entropy"
        elif entropy < 1.0 and len(content) > 512:
            status = "low_entropy"
        elif entropy < 0.5 and len(content) > 256:
            status = "near_zero_entropy"

        section_info: dict[str, Any] = {
            "name": sec.name.strip(b"\x00"),  # type: ignore[arg-type]
            "virtual_address": sec.virtual_address if hasattr(sec, "virtual_address") else 0,
            "size": len(content),
            "entropy": round(entropy, 4),
            "status": status,
            "byte_distribution": byte_dist,
        }

        # Add entropy curve for sections > 1KB
        if len(content) > 1024:
            window = max(256, len(content) // 64)  # ~64 data points
            section_info["entropy_curve"] = sliding_window_entropy(content, window_size=window)

        sections.append(section_info)

    return sections


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_entropy",
    description=(
        "Compute Shannon entropy over binary sections and arbitrary byte ranges. "
        "Flags sections with entropy > 7.0 (likely encrypted/packed) and < 1.0 "
        "(zero-padded/sparse). Returns per-section entropy curves as float arrays "
        "for visualization. Also analyzes byte distribution patterns."
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
                "description": "Raw hex bytes to compute entropy on (alternative to binary_path).",
            },
            "offset": {
                "type": "integer",
                "description": "Start offset for byte range analysis (used with binary_path). Default: 0.",
                "default": 0,
            },
            "length": {
                "type": "integer",
                "description": "Length of byte range to analyze. Default: entire file.",
                "default": 0,
            },
            "window_size": {
                "type": "integer",
                "description": "Sliding window size for entropy curve. Default: 256.",
                "default": 256,
            },
            "include_sections": {
                "type": "boolean",
                "description": "Analyze per-section entropy (requires LIEF). Default: true.",
                "default": True,
            },
        },
        "oneOf": [
            {"required": ["binary_path"]},
            {"required": ["hex_bytes"]},
        ],
    },
    category="static",
)
async def handle_entropy(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Compute entropy analysis on binary data."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    offset = arguments.get("offset", 0)
    length = arguments.get("length", 0)
    window_size = arguments.get("window_size", 256)
    include_sections = arguments.get("include_sections", True)

    if hex_bytes:
        try:
            data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
        except ValueError as e:
            return error_result(f"Invalid hex string: {e}")

        overall = shannon_entropy(data)
        curve = sliding_window_entropy(data, window_size=window_size)
        dist = analyze_byte_distribution(data)

        return text_result({
            "source": "hex_bytes",
            "size": len(data),
            "overall_entropy": round(overall, 4),
            "status": "high_entropy" if overall > 7.0 else "low_entropy" if overall < 1.0 else "normal",
            "entropy_curve": curve,
            "byte_distribution": dist,
        })

    if not binary_path:
        return error_result("Either 'binary_path' or 'hex_bytes' must be provided.")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)

    data = file_path.read_bytes()
    file_size = len(data)

    # Apply offset/length if specified
    if offset > 0 or length > 0:
        end = offset + length if length > 0 else file_size
        data = data[offset:end]

    result: dict[str, Any] = {
        "file_path": str(file_path),
        "file_size": file_size,
        "analyzed_range": {
            "offset": offset,
            "length": len(data),
        },
        "overall_entropy": round(shannon_entropy(data), 4),
    }

    # Overall status
    overall = result["overall_entropy"]
    if overall > 7.0:
        result["status"] = "high_entropy"
        result["assessment"] = "Binary appears to be packed or encrypted (entropy > 7.0)"
    elif overall > 6.5:
        result["status"] = "elevated_entropy"
        result["assessment"] = "Entropy is elevated; some sections may be compressed"
    elif overall < 1.0:
        result["status"] = "low_entropy"
        result["assessment"] = "Very low entropy; binary may be mostly zero-padded"
    else:
        result["status"] = "normal"
        result["assessment"] = "Entropy is within normal range for compiled code"

    # Entropy curve over full file
    result["entropy_curve"] = sliding_window_entropy(data, window_size=window_size)
    result["byte_distribution"] = analyze_byte_distribution(data)

    # Per-section analysis
    if include_sections:
        try:
            result["sections"] = _analyze_sections_lief(str(file_path))
        except ImportError:
            result["sections_error"] = "LIEF not available for section analysis"
        except Exception as e:
            result["sections_error"] = f"Section analysis failed: {e}"

    return text_result(result)
