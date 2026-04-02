"""Python executor: run Python code snippets for custom exploit logic.

Enables the agent to write and execute Python code for:
- Custom payload generation
- Response parsing and data extraction
- API interaction (AWS, GCP, Azure SDKs)
- Cryptographic operations (JWT forging, hash cracking)
- Complex data transformations
"""

from __future__ import annotations

import ast
import asyncio
import logging
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 50_000

BLOCKED_MODULES = {"os", "subprocess", "shutil", "sys", "ctypes", "importlib", "pathlib"}
BLOCKED_BUILTINS = {
    "exec", "eval", "compile", "__import__", "open", "breakpoint",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
    "type", "memoryview", "bytearray",
}
BLOCKED_DUNDER = {"__import__", "__builtins__", "__loader__", "__spec__"}


def _validate_code(code: str) -> Tuple[bool, str]:
    """Validate Python code is safe to execute."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

    for node in ast.walk(tree):
        # Block dangerous imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [alias.name for alias in node.names]
            for name in ([module] if module else []) + names:
                if name and name.split(".")[0] in BLOCKED_MODULES:
                    return False, f"Blocked module: {name}"

        # Block dangerous function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in BLOCKED_BUILTINS:
                return False, f"Blocked builtin: {node.func.id}"
            # Block method calls on __builtins__ etc.
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id.startswith("__"):
                    return False, f"Blocked dunder access: {node.func.value.id}"

        # Block direct dunder attribute access (e.g., __builtins__, __import__)
        if isinstance(node, ast.Attribute):
            if node.attr in BLOCKED_DUNDER or node.attr.startswith("__"):
                return False, f"Blocked dunder attribute: {node.attr}"

        # Block string-based chr() obfuscation patterns
        if isinstance(node, ast.Name) and node.id in BLOCKED_DUNDER:
            return False, f"Blocked dunder name: {node.id}"

    return True, "OK"


@register_tool(
    description="Execute Python code and return output. "
    "Use for custom payloads, API calls, data parsing, crypto operations.",
)
async def python_execute(
    code: str,
    timeout: int = 60,
) -> Dict[str, object]:
    """Execute a Python code snippet and capture output.

    Args:
        code: Python source code to execute.
        timeout: Max execution time in seconds.

    Returns:
        Dict with stdout, stderr, exit_code.
    """
    if not code.strip():
        return {"error": "Empty code", "exit_code": -1}

    # Validate code safety before execution
    is_safe, reason = _validate_code(code)
    if not is_safe:
        return {"error": f"Code validation failed: {reason}", "exit_code": -1}

    logger.info("Python executing: %s...", code[:100])

    # Write code to temp file and execute in subprocess
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(code)
        script_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-S", "-I", script_path,  # -S: no site-packages, -I: isolated mode
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "stdout": "",
                "stderr": f"Execution timed out after {timeout}s",
                "exit_code": -1,
                "timed_out": True,
            }

        stdout = stdout_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]
        stderr = stderr_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_SIZE]

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": proc.returncode,
            "timed_out": False,
        }
    except Exception as e:
        logger.error("Python execution failed: %s", e)
        return {"error": str(e), "exit_code": -1}
    finally:
        Path(script_path).unlink(missing_ok=True)
