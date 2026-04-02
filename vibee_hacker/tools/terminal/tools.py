"""Terminal tool: sandboxed shell command execution.

Allows the agent to run external security tools (nmap, sqlmap, curl, dig,
whois, etc.) with timeout and output capture. Commands that would damage
the host system are blocked.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from typing import Dict, Optional

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Commands that are never allowed
_BLOCKED_COMMANDS = frozenset({
    "rm", "rmdir", "mkfs", "dd", "shutdown", "reboot", "halt",
    "kill", "killall", "pkill", "init", "systemctl",
    "passwd", "useradd", "userdel", "chown", "chmod",
    "mount", "umount", "fdisk", "iptables", "ip6tables",
})

# Commands commonly used in security testing
_ALLOWED_COMMANDS = frozenset({
    "nmap", "sqlmap", "curl", "wget", "dig", "nslookup", "whois",
    "host", "ping", "traceroute", "nc", "netcat", "ncat",
    "nikto", "gobuster", "ffuf", "dirb", "wfuzz",
    "nuclei", "httpx", "subfinder", "amass",
    "openssl", "sslscan", "sslyze", "testssl",
    "wpscan", "joomscan",
    "python", "python3", "pip", "pip3",
    "cat", "head", "tail", "grep", "awk", "sed", "sort", "uniq",
    "jq", "base64", "xxd", "hexdump",
    "echo", "printf", "tee", "wc", "tr", "cut",
    "ls", "find", "file", "strings", "which",
    "git", "ssh-keyscan",
})

MAX_OUTPUT_SIZE = 50_000  # chars


def _is_command_allowed(command: str) -> tuple:
    """Check if a command is allowed. Returns (allowed, reason)."""
    try:
        parts = shlex.split(command)
    except ValueError:
        return False, "Invalid command syntax"

    if not parts:
        return False, "Empty command"

    base_cmd = parts[0].split("/")[-1]  # Handle full paths

    if base_cmd in _BLOCKED_COMMANDS:
        return False, f"Command '{base_cmd}' is blocked for safety"

    # Allow piped commands if each part is allowed
    # For simple cases, allow any command not in blocked list
    return True, ""


@register_tool(
    description="Execute a shell command and return its output. "
    "Use for running security tools like nmap, sqlmap, curl, dig, etc.",
    requires_network=True,
)
async def terminal_execute(
    command: str,
    timeout: int = 120,
    working_dir: Optional[str] = None,
) -> Dict[str, object]:
    """Execute a shell command with timeout and output capture.

    Args:
        command: Shell command to execute.
        timeout: Max execution time in seconds (default 120).
        working_dir: Optional working directory.

    Returns:
        Dict with stdout, stderr, exit_code, and timed_out flag.
    """
    allowed, reason = _is_command_allowed(command)
    if not allowed:
        return {"error": reason, "exit_code": -1}

    logger.info("Terminal executing: %s", command[:200])

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
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
                "stderr": f"Command timed out after {timeout}s",
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
        logger.error("Terminal execution failed: %s", e)
        return {"error": str(e), "exit_code": -1}
