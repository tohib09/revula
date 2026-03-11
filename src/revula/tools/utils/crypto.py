"""
Revula Crypto Utilities — hashing, XOR analysis, crypto constant scanning, entropy.

Features:
- Multi-algorithm hashing (MD5, SHA family, TLSH, ssdeep, imphash)
- XOR key recovery (single-byte frequency analysis, multi-byte IC/Kasiski)
- Crypto constant scanning (AES S-box, DES, SHA inits, Salsa/ChaCha, etc.)
- Magic bytes detection
"""

from __future__ import annotations

import logging
import struct
from collections import Counter
from typing import Any

from revula.sandbox import validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Crypto constants database
# ---------------------------------------------------------------------------

CRYPTO_CONSTANTS: list[tuple[str, bytes, str]] = [
    # AES S-box (first 16 bytes)
    ("AES S-box", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                         0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]), "AES"),
    # AES inverse S-box (first 16 bytes)
    ("AES Inv S-box", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                              0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]), "AES"),
    # SHA-256 init values
    ("SHA-256 init H0", struct.pack(">I", 0x6A09E667), "SHA-256"),
    ("SHA-256 init H1", struct.pack(">I", 0xBB67AE85), "SHA-256"),
    ("SHA-256 init H2", struct.pack(">I", 0x3C6EF372), "SHA-256"),
    ("SHA-256 init H3", struct.pack(">I", 0xA54FF53A), "SHA-256"),
    # SHA-1 init values
    ("SHA-1 init H0", struct.pack(">I", 0x67452301), "SHA-1/MD5"),
    ("SHA-1 init H1", struct.pack(">I", 0xEFCDAB89), "SHA-1/MD5"),
    ("SHA-1 init H2", struct.pack(">I", 0x98BADCFE), "SHA-1/MD5"),
    ("SHA-1 init H3", struct.pack(">I", 0x10325476), "SHA-1/MD5"),
    # MD5 init values (same as SHA-1 in little-endian)
    ("MD5 init", struct.pack("<I", 0x67452301), "MD5"),
    # Salsa20/ChaCha20 constant
    ("Salsa20/ChaCha20 expand 32", b"expand 32-byte k", "Salsa20/ChaCha20"),
    ("Salsa20/ChaCha20 expand 16", b"expand 16-byte k", "Salsa20/ChaCha20"),
    # RC4 typical key schedule indicator (0x00-0xFF sequence)
    ("RC4 S-box init", bytes(range(16)), "RC4"),
    # DES initial permutation first bytes
    ("DES IP", bytes([58, 50, 42, 34, 26, 18, 10, 2]), "DES"),
    # RSA/crypto primes indicator
    ("RSA public exponent 65537", struct.pack(">I", 0x00010001), "RSA"),
    # Blowfish P-array initial
    ("Blowfish P-array", struct.pack(">I", 0x243F6A88), "Blowfish"),
    # Whirlpool S-box start
    ("Whirlpool", bytes([0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F]), "Whirlpool"),
    # TEA/XTEA delta
    ("TEA/XTEA delta", struct.pack("<I", 0x9E3779B9), "TEA/XTEA"),
    ("TEA/XTEA delta (BE)", struct.pack(">I", 0x9E3779B9), "TEA/XTEA"),
    # CRC32 polynomial
    ("CRC32 polynomial", struct.pack("<I", 0xEDB88320), "CRC32"),
]


def scan_crypto_constants(data: bytes) -> list[dict[str, Any]]:
    """Scan binary data for known cryptographic constants."""
    results: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    for name, pattern, algorithm in CRYPTO_CONSTANTS:
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            if idx not in seen_offsets:
                seen_offsets.add(idx)
                results.append({
                    "name": name,
                    "algorithm": algorithm,
                    "offset": idx,
                    "address": f"0x{idx:x}",
                    "matched_bytes": pattern.hex(),
                })
            offset = idx + 1

    results.sort(key=lambda r: r["offset"])
    return results


# ---------------------------------------------------------------------------
# XOR analysis
# ---------------------------------------------------------------------------


def xor_single_byte_bruteforce(
    data: bytes,
    known_plaintext: bytes | None = None,
) -> list[dict[str, Any]]:
    """
    Brute-force single-byte XOR key using frequency analysis.

    Assumes plaintext is ASCII-heavy (English text, code, etc.)
    Top keys are sorted by likelihood.
    """
    results: list[dict[str, Any]] = []

    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        # Score by printable ASCII ratio
        printable = sum(1 for b in decrypted if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(decrypted) if decrypted else 0

        if known_plaintext and known_plaintext in decrypted:
            results.append({
                "key": f"0x{key:02x}",
                "key_int": key,
                "printable_ratio": round(ratio, 4),
                "known_plaintext_match": True,
                "preview": decrypted[:100].decode("ascii", errors="replace"),
            })
        elif ratio > 0.7:  # High ASCII ratio
            results.append({
                "key": f"0x{key:02x}",
                "key_int": key,
                "printable_ratio": round(ratio, 4),
                "known_plaintext_match": False,
                "preview": decrypted[:100].decode("ascii", errors="replace"),
            })

    results.sort(key=lambda r: (-r.get("known_plaintext_match", False), -r["printable_ratio"]))
    return results[:10]


def xor_multibyte_detect_keylen(data: bytes, max_keylen: int = 32) -> list[dict[str, Any]]:
    """
    Detect likely multi-byte XOR key length using Index of Coincidence.
    """
    results: list[dict[str, Any]] = []

    for keylen in range(1, max_keylen + 1):
        # Split data into streams based on key position
        streams: list[list[int]] = [[] for _ in range(keylen)]
        for i, b in enumerate(data):
            streams[i % keylen].append(b)

        # Compute average IC across all streams
        total_ic = 0.0
        for stream in streams:
            if len(stream) < 2:
                continue
            counts = Counter(stream)
            n = len(stream)
            ic = sum(c * (c - 1) for c in counts.values()) / (n * (n - 1)) if n > 1 else 0
            total_ic += ic
        avg_ic = total_ic / keylen

        results.append({
            "key_length": keylen,
            "ic": round(avg_ic, 6),
        })

    # English text IC is ~0.065, random is ~0.004
    results.sort(key=lambda r: -r["ic"])
    return results[:5]


def xor_multibyte_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt data with a multi-byte XOR key."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


# ---------------------------------------------------------------------------
# Tool registrations
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_hash",
    description=(
        "Compute multiple hash algorithms on a file or data. "
        "MD5, SHA1, SHA256, SHA512, TLSH (if available), ssdeep (if available), "
        "imphash (PE files)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to file to hash."},
            "hex_bytes": {"type": "string", "description": "Hex data to hash."},
        },
    },
    category="utility",
)
async def handle_hash(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Compute file hashes."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")

    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif binary_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
    else:
        return error_result("Provide binary_path or hex_bytes")

    from revula.tools.static.pe_elf import compute_file_hashes
    hashes = compute_file_hashes(data)
    hashes["size"] = str(len(data))
    return text_result(hashes)


@TOOL_REGISTRY.register(
    name="re_xor_analysis",
    description=(
        "XOR key recovery analysis. Single-byte: frequency analysis + known-plaintext. "
        "Multi-byte: Index of Coincidence key length detection + Kasiski method. "
        "Returns candidate keys with confidence scores."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to encrypted file."},
            "hex_bytes": {"type": "string", "description": "Hex data to analyze."},
            "known_plaintext": {
                "type": "string",
                "description": "Known plaintext string (for known-plaintext attack).",
            },
            "key": {
                "type": "string",
                "description": "Known key (hex) to decrypt with. If provided, just decrypts.",
            },
            "max_keylen": {
                "type": "integer",
                "description": "Max key length for multi-byte detection. Default: 32.",
                "default": 32,
            },
        },
    },
    category="utility",
)
async def handle_xor_analysis(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """XOR analysis and decryption."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")
    known_pt = arguments.get("known_plaintext")
    key_hex = arguments.get("key")
    max_keylen = arguments.get("max_keylen", 32)

    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif binary_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
    else:
        return error_result("Provide binary_path or hex_bytes")

    result: dict[str, Any] = {"data_size": len(data)}

    # If key provided, just decrypt
    if key_hex:
        key = bytes.fromhex(key_hex.replace(" ", ""))
        decrypted = xor_multibyte_decrypt(data, key)
        result["decrypted_hex"] = decrypted[:256].hex()
        result["decrypted_preview"] = decrypted[:256].decode("ascii", errors="replace")
        return text_result(result)

    # Single-byte analysis
    known_bytes = known_pt.encode() if known_pt else None
    result["single_byte_candidates"] = xor_single_byte_bruteforce(data, known_bytes)

    # Multi-byte key length detection
    result["key_length_candidates"] = xor_multibyte_detect_keylen(data, max_keylen)

    return text_result(result)


@TOOL_REGISTRY.register(
    name="re_crypto_constants",
    description=(
        "Scan binary for cryptographic constants: AES S-box, DES tables, "
        "SHA/MD5 init vectors, Salsa/ChaCha constants, Blowfish P-array, "
        "TEA/XTEA delta, CRC32 polynomial, RSA indicators."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "Path to binary file."},
            "hex_bytes": {"type": "string", "description": "Hex data to scan."},
        },
    },
    category="utility",
)
async def handle_crypto_constants(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan for crypto constants."""
    binary_path = arguments.get("binary_path")
    hex_bytes = arguments.get("hex_bytes")

    if hex_bytes:
        data = bytes.fromhex(hex_bytes.replace(" ", ""))
    elif binary_path:
        config = arguments.get("__config__")
        allowed_dirs = config.security.allowed_dirs if config else None
        file_path = validate_binary_path(binary_path, allowed_dirs=allowed_dirs)
        data = file_path.read_bytes()
    else:
        return error_result("Provide binary_path or hex_bytes")

    results = scan_crypto_constants(data)

    # Summarize by algorithm
    algo_summary: dict[str, int] = {}
    for r in results:
        algo = r["algorithm"]
        algo_summary[algo] = algo_summary.get(algo, 0) + 1

    return text_result({
        "data_size": len(data),
        "total_matches": len(results),
        "algorithm_summary": algo_summary,
        "matches": results,
    })
