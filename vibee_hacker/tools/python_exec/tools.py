"""Python executor: run Python code snippets for custom exploit logic.

Enables the agent to write and execute Python code for:
- Custom payload generation
- Response parsing and data extraction
- API interaction (AWS, GCP, Azure SDKs)
- Cryptographic operations (JWT forging, hash cracking)
- Complex data transformations
"""

from __future__ import annotations

import asyncio
import logging
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 50_000


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

    logger.info("Python executing: %s...", code[:100])

    # Write code to temp file and execute in subprocess
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(code)
        script_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, script_path,
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
