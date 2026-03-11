"""Shared test fixtures and configuration."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_dir() -> Path:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory(prefix="revula_test_") as d:
        yield Path(d)


@pytest.fixture
def sample_binary(tmp_dir: Path) -> Path:
    """Create a simple binary file for testing."""
    binary = tmp_dir / "sample.bin"
    # Simple data with identifiable patterns
    data = bytearray()
    data += b"\x7fELF"  # ELF magic
    data += b"\x02\x01\x01\x00" + b"\x00" * 8
    data += b"\x00" * 48  # Minimal header
    data += b"\x90" * 100  # NOP sled
    data += b"\xc3"  # RET
    data += b"Hello World\x00"
    data += b"test_string_value\x00"
    binary.write_bytes(bytes(data))
    return binary
