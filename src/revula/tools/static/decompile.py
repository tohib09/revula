"""
Revula Decompiler — multi-backend decompilation with caching.

Backends:
- Ghidra headless (analyzeHeadless) — primary, with project caching by binary hash
- Binary Ninja API (if licensed)
- RetDec (open source fallback)

Ghidra headless takes ~30s on first run — streams progress.
Caches analysis DB in ~/.revula/ghidra_projects/ keyed by binary hash.
Never re-analyzes the same binary twice.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from revula.config import CACHE_DIR, GHIDRA_PROJECTS_DIR
from revula.sandbox import safe_subprocess, validate_binary_path
from revula.tools import TOOL_REGISTRY, error_result, text_result

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ghidra headless backend
# ---------------------------------------------------------------------------


def _get_binary_hash(file_path: Path) -> str:
    """Compute SHA256 hash of binary for caching."""
    return hashlib.sha256(file_path.read_bytes()).hexdigest()


async def _decompile_ghidra(
    binary_path: Path,
    function: str,
    binary_hash: str,
) -> dict[str, Any]:
    """
    Decompile using Ghidra headless.

    Caches the analysis project by binary hash. Re-uses existing analysis
    if the binary hasn't changed.
    """
    from revula.config import get_config

    config = get_config()
    ghidra_path = config.require_tool("ghidra_headless")

    project_dir = GHIDRA_PROJECTS_DIR / binary_hash[:16]
    project_name = f"revula_{binary_hash[:8]}"

    # Check if project already exists (cached analysis)
    project_exists = (project_dir / f"{project_name}.gpr").exists()

    if not project_exists:
        # Import and analyze binary
        project_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            ghidra_path,
            str(project_dir),
            project_name,
            "-import", str(binary_path),
            "-overwrite",
            "-scriptPath", str(Path(__file__).parent.parent.parent / "scripts"),
            "-postScript", "DecompileFunction.py", function,
        ]

        result = await safe_subprocess(
            cmd,
            timeout=300,
            max_memory_mb=2048,
        )

        if not result.success:
            # Fall back to basic analysis without custom script
            cmd_basic = [
                ghidra_path,
                str(project_dir),
                project_name,
                "-import", str(binary_path),
                "-overwrite",
                "-postScript", "ExportDecompilation.java",
            ]

            result = await safe_subprocess(
                cmd_basic,
                timeout=300,
                max_memory_mb=2048,
            )

            if not result.success:
                raise RuntimeError(f"Ghidra analysis failed: {result.stderr[:500]}")
    else:
        # Process existing project
        cmd = [
            ghidra_path,
            str(project_dir),
            project_name,
            "-process", binary_path.name,
            "-noanalysis",
            "-postScript", "DecompileFunction.py", function,
        ]

        result = await safe_subprocess(
            cmd,
            timeout=120,
            max_memory_mb=2048,
        )

        if not result.success:
            raise RuntimeError(f"Ghidra decompilation failed: {result.stderr[:500]}")

    # Look for output file
    output_file = project_dir / f"{function}_decompiled.c"
    code = output_file.read_text() if output_file.exists() else _extract_decompiled_from_output(result.stdout)

    return {
        "backend": "ghidra",
        "function": function,
        "cached": project_exists,
        "project_dir": str(project_dir),
        "decompiled_code": code,
    }


def _extract_decompiled_from_output(output: str) -> str:
    """Extract decompiled code from Ghidra stdout (fallback)."""
    lines = output.splitlines()
    in_code = False
    code_lines: list[str] = []

    for line in lines:
        if "Decompiled" in line or "/* Function" in line:
            in_code = True
            continue
        if in_code:
            if line.strip() == "" and code_lines and code_lines[-1].strip() == "}":
                break
            code_lines.append(line)

    return "\n".join(code_lines) if code_lines else "(Decompiled output not captured — check Ghidra project directly)"


# ---------------------------------------------------------------------------
# RetDec backend
# ---------------------------------------------------------------------------


async def _decompile_retdec(
    binary_path: Path,
    function: str | None = None,
) -> dict[str, Any]:
    """Decompile using RetDec (open source)."""
    from revula.config import get_config

    config = get_config()
    retdec_path = config.require_tool("retdec_decompiler")

    output_dir = CACHE_DIR / "retdec"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{binary_path.stem}.c"

    cmd = [retdec_path, str(binary_path), "-o", str(output_file)]

    if function:
        # Try to pass function address/name
        try:
            addr = int(function, 16) if function.startswith("0x") else int(function)
            cmd.extend(["--select-ranges", f"{addr:#x}-{addr + 0x1000:#x}"])
        except ValueError:
            cmd.extend(["--select-functions", function])

    result = await safe_subprocess(
        cmd,
        timeout=300,
        max_memory_mb=2048,
    )

    if not result.success:
        raise RuntimeError(f"RetDec failed: {result.stderr[:500]}")

    code = ""
    if output_file.exists():
        code = output_file.read_text()

    return {
        "backend": "retdec",
        "function": function,
        "output_file": str(output_file),
        "decompiled_code": code,
    }


# ---------------------------------------------------------------------------
# Binary Ninja backend (requires license)
# ---------------------------------------------------------------------------


async def _decompile_binja(
    binary_path: Path,
    function: str,
) -> dict[str, Any]:
    """Decompile using Binary Ninja API (requires license)."""
    import asyncio

    loop = asyncio.get_running_loop()

    def _do_binja() -> dict[str, Any]:
        import binaryninja  # type: ignore[import-not-found]

        bv = binaryninja.open_view(str(binary_path))
        try:
            # Find function by name or address
            func = None
            try:
                addr = int(function, 16) if function.startswith("0x") else int(function)
                func = bv.get_function_at(addr)
            except ValueError:
                for f in bv.functions:
                    if f.name == function:
                        func = f
                        break

            if func is None:
                raise ValueError(f"Function not found: {function}")

            # Get high-level IL (decompiled)
            hlil = func.hlil
            code_lines = []
            for line in hlil.root.lines:
                code_lines.append(str(line))

            return {
                "backend": "binaryninja",
                "function": function,
                "function_name": func.name,
                "address": f"0x{func.start:x}",
                "decompiled_code": "\n".join(code_lines),
            }
        finally:
            bv.file.close()

    return await loop.run_in_executor(None, _do_binja)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@TOOL_REGISTRY.register(
    name="re_decompile",
    description=(
        "Decompile a function from a binary file to C pseudocode. "
        "Backends: Ghidra headless (primary, ~30s first run, cached by binary hash), "
        "Binary Ninja API (if licensed), RetDec (open source fallback). "
        "Specify function by address (0x...) or name."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "binary_path": {
                "type": "string",
                "description": "Absolute path to the binary file.",
            },
            "function": {
                "type": "string",
                "description": "Function address (e.g., '0x401000') or name (e.g., 'main').",
            },
            "backend": {
                "type": "string",
                "enum": ["ghidra", "retdec", "binaryninja", "auto"],
                "description": "Decompilation backend. 'auto' selects best available. Default: auto.",
                "default": "auto",
            },
        },
        "required": ["binary_path", "function"],
    },
    category="static",
)
async def handle_decompile(arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Decompile a function from a binary."""
    binary_path_str = arguments["binary_path"]
    function = arguments["function"]
    backend = arguments.get("backend", "auto")

    config = arguments.get("__config__")
    allowed_dirs = config.security.allowed_dirs if config else None
    file_path = validate_binary_path(binary_path_str, allowed_dirs=allowed_dirs)

    binary_hash = _get_binary_hash(file_path)

    if backend == "auto":
        # Priority: ghidra > binja > retdec
        if config and config.is_available("ghidra_headless"):
            backend = "ghidra"
        else:
            try:
                import importlib.util
                if importlib.util.find_spec("binaryninja"):
                    backend = "binaryninja"
                else:
                    raise ImportError("binaryninja not found")
            except ImportError:
                if config and config.is_available("retdec_decompiler"):
                    backend = "retdec"
                else:
                    return error_result(
                        "No decompilation backend available. Install one of: "
                        "Ghidra (https://ghidra-sre.org/), "
                        "Binary Ninja (https://binary.ninja/), "
                        "RetDec (https://github.com/avast/retdec)"
                    )

    try:
        if backend == "ghidra":
            result = await _decompile_ghidra(file_path, function, binary_hash)
        elif backend == "binaryninja":
            result = await _decompile_binja(file_path, function)
        elif backend == "retdec":
            result = await _decompile_retdec(file_path, function)
        else:
            return error_result(f"Unknown backend: {backend}")
    except Exception as e:
        return error_result(f"Decompilation failed ({backend}): {e}")

    result["binary_path"] = str(file_path)
    result["binary_hash"] = binary_hash

    return text_result(result)
