"""
Revula Test Suite — Static analysis tool tests.

Uses minimal test fixtures (small binaries, test data).
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_elf() -> Path:
    """Create a minimal ELF binary for testing."""
    # Minimal ELF header (x86-64, no sections, just valid enough to parse)
    elf = bytearray()
    # ELF magic
    elf += b"\x7fELF"
    # Class: 64-bit
    elf += b"\x02"
    # Data: little-endian
    elf += b"\x01"
    # Version
    elf += b"\x01"
    # OS/ABI
    elf += b"\x00"
    # Padding
    elf += b"\x00" * 8
    # Type: executable
    elf += struct.pack("<H", 2)
    # Machine: x86-64
    elf += struct.pack("<H", 0x3E)
    # Version
    elf += struct.pack("<I", 1)
    # Entry point
    elf += struct.pack("<Q", 0x401000)
    # Program header offset
    elf += struct.pack("<Q", 64)
    # Section header offset
    elf += struct.pack("<Q", 0)
    # Flags
    elf += struct.pack("<I", 0)
    # ELF header size
    elf += struct.pack("<H", 64)
    # Program header entry size
    elf += struct.pack("<H", 56)
    # Program header count
    elf += struct.pack("<H", 0)
    # Section header entry size
    elf += struct.pack("<H", 64)
    # Section header count
    elf += struct.pack("<H", 0)
    # Section name string table index
    elf += struct.pack("<H", 0)

    # Add some code bytes (x86-64 NOP sled + ret)
    elf += b"\x90" * 16 + b"\xc3"

    # Add some test strings
    elf += b"\x00" * 16
    elf += b"http://malware.example.com\x00"
    elf += b"C:\\Windows\\System32\\cmd.exe\x00"
    elf += b"password123\x00"

    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(bytes(elf))

    yield Path(f.name)
    os.unlink(f.name)


@pytest.fixture
def minimal_pe() -> Path:
    """Create a minimal PE binary for testing."""
    pe = bytearray()
    # DOS header
    pe += b"MZ"
    pe += b"\x00" * 58
    pe += struct.pack("<I", 128)  # e_lfanew

    # Padding to PE header
    pe += b"\x00" * (128 - len(pe))

    # PE signature
    pe += b"PE\x00\x00"
    # Machine: x86-64
    pe += struct.pack("<H", 0x8664)
    # Number of sections
    pe += struct.pack("<H", 1)
    # TimeDateStamp
    pe += struct.pack("<I", 0)
    # PointerToSymbolTable, NumberOfSymbols
    pe += struct.pack("<I", 0)
    pe += struct.pack("<I", 0)
    # SizeOfOptionalHeader
    pe += struct.pack("<H", 240)
    # Characteristics
    pe += struct.pack("<H", 0x22)

    # Optional header (PE32+)
    pe += struct.pack("<H", 0x20B)  # Magic
    pe += b"\x00" * 238  # Rest of optional header

    # Section header (.text)
    pe += b".text\x00\x00\x00"
    pe += struct.pack("<I", 0x1000)  # VirtualSize
    pe += struct.pack("<I", 0x1000)  # VirtualAddress
    pe += struct.pack("<I", 0x200)   # SizeOfRawData
    pe += struct.pack("<I", 0x200)   # PointerToRawData
    pe += b"\x00" * 12  # Relocations, Linenumbers
    pe += struct.pack("<I", 0x60000020)  # Characteristics (code, exec, read)

    # Pad to raw data offset
    pe += b"\x00" * (0x200 - len(pe))

    # Code section (.text)
    pe += b"\x90" * 16 + b"\xc3"
    pe += b"\x00" * (0x200 - 17)

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(bytes(pe))

    yield Path(f.name)
    os.unlink(f.name)


@pytest.fixture
def binary_with_strings() -> Path:
    """Create a binary with various string types for extraction testing."""
    data = bytearray()
    data += b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8  # ELF header start
    data += b"\x00" * 48  # Rest of header

    # Test strings
    strings = [
        b"http://evil.com/c2",
        b"192.168.1.100",
        b"admin@example.com",
        b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft",
        b"cmd.exe /c whoami",
        b"CreateRemoteThread",
        b"VirtualAllocEx",
        b"kernel32.dll",
        b"/etc/passwd",
        b"Mozilla/5.0 (compatible; malware)",
    ]

    for s in strings:
        data += s + b"\x00" * 4

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(bytes(data))

    yield Path(f.name)
    os.unlink(f.name)


# ---------------------------------------------------------------------------
# Entropy Tests
# ---------------------------------------------------------------------------


class TestEntropy:
    """Test entropy analysis."""

    def test_shannon_entropy_zeros(self) -> None:
        from revula.tools.static.entropy import shannon_entropy

        # All zeros = 0 entropy
        result = shannon_entropy(b"\x00" * 1000)
        assert result == 0.0

    def test_shannon_entropy_random(self) -> None:
        from revula.tools.static.entropy import shannon_entropy

        # High entropy data
        data = bytes(range(256)) * 4
        result = shannon_entropy(data)
        assert result > 7.9  # Should be close to 8.0

    def test_byte_distribution(self) -> None:
        from revula.tools.static.entropy import analyze_byte_distribution

        data = b"\x41" * 100 + b"\x42" * 100
        dist = analyze_byte_distribution(data)
        assert dist["unique_bytes"] == 2
        assert dist["total_bytes"] == 200
        # most_common should list both bytes
        common_bytes = {entry["byte"] for entry in dist["most_common"]}
        assert "0x41" in common_bytes
        assert "0x42" in common_bytes


# ---------------------------------------------------------------------------
# Hex Utility Tests
# ---------------------------------------------------------------------------


class TestHexUtils:
    """Test hex dump and pattern search."""

    def test_hexdump(self) -> None:
        from revula.tools.utils.hex import hexdump

        data = b"Hello, World!"
        result = hexdump(data, offset=0, length=len(data))
        assert "Hello" in result  # ASCII column should show

    def test_pattern_to_regex(self) -> None:
        from revula.tools.utils.hex import pattern_to_regex

        regex = pattern_to_regex("55 8B EC ?? ??")
        assert regex is not None
        # Should match \x55\x8b\xec + any two bytes
        import re
        m = re.search(regex, b"\x55\x8b\xec\x00\x01")
        assert m is not None

    def test_binary_diff(self) -> None:
        from revula.tools.utils.hex import binary_diff

        data1 = b"\x00\x01\x02\x03\x04"
        data2 = b"\x00\x01\xFF\x03\x04"
        result = binary_diff(data1, data2)
        assert result["total_byte_differences"] == 1
        assert result["diffs"][0]["offset"] == 2


# ---------------------------------------------------------------------------
# Crypto Utility Tests
# ---------------------------------------------------------------------------


class TestCryptoUtils:
    """Test crypto utilities."""

    def test_xor_single_byte(self) -> None:
        from revula.tools.utils.crypto import xor_single_byte_bruteforce

        # XOR encrypt a longer English-like plaintext with key 0x42
        plaintext = b"hello"
        ciphertext = bytes(b ^ 0x42 for b in plaintext)

        # Use known_plaintext hint so bruteforce can identify correct key
        results = xor_single_byte_bruteforce(ciphertext, known_plaintext=b"hello")
        assert any(r["key_int"] == 0x42 for r in results)

    def test_xor_multibyte_keylen(self) -> None:
        from revula.tools.utils.crypto import xor_multibyte_detect_keylen

        # Create data XORed with 3-byte key
        key = b"\x11\x22\x33"
        plain = b"This is a test message for key length detection!" * 10
        cipher = bytes(p ^ key[i % 3] for i, p in enumerate(plain))

        keylens = xor_multibyte_detect_keylen(cipher, max_keylen=8)
        # Key length 3 should score highly
        assert 3 in [kl["key_length"] for kl in keylens[:3]]


# ---------------------------------------------------------------------------
# String Tests
# ---------------------------------------------------------------------------


class TestStringExtraction:
    """Test string classification."""

    def test_string_classifiers(self) -> None:
        from revula.tools.static.strings import classify_string

        assert "url" in classify_string("http://evil.com/malware")
        assert "ip_address" in classify_string("192.168.1.1")
        assert "email" in classify_string("user@example.com")
        assert "registry_key" in classify_string("HKEY_LOCAL_MACHINE\\Software")
        assert "dll_name" in classify_string("kernel32.dll")
