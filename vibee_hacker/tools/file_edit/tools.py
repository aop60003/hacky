"""File viewing and editing tools for whitebox analysis.

Allows the agent to read source code files and apply fixes.
Restricted to the scan target directory for safety.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from vibee_hacker.tools.registry import register_tool

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_VIEW_LINES = 500


@register_tool(
    description="View a source code file with line numbers. "
    "Supports offset/limit for large files.",
)
def view_file(
    file_path: str,
    start_line: int = 1,
    end_line: Optional[int] = None,
) -> Dict[str, Any]:
    """View file contents with line numbers.

    Args:
        file_path: Path to the file to view.
        start_line: First line to display (1-based).
        end_line: Last line to display. Default: start_line + 500.
    """
    p = Path(file_path)
    if not p.exists():
        return {"error": f"File not found: {file_path}"}
    if not p.is_file():
        return {"error": f"Not a file: {file_path}"}
    if p.stat().st_size > MAX_FILE_SIZE:
        return {"error": f"File too large ({p.stat().st_size} bytes). Max: {MAX_FILE_SIZE}"}

    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception as e:
        return {"error": f"Cannot read file: {e}"}

    total_lines = len(lines)
    start = max(1, start_line) - 1
    end = min(total_lines, end_line or start + MAX_VIEW_LINES)

    numbered = []
    for i in range(start, end):
        numbered.append(f"{i + 1:>5} | {lines[i]}")

    return {
        "file": file_path,
        "total_lines": total_lines,
        "showing": f"{start + 1}-{end}",
        "content": "\n".join(numbered),
    }


@register_tool(
    description="Edit a file by replacing a specific text segment. "
    "Provide old_text and new_text for precise replacement.",
)
def edit_file(
    file_path: str,
    old_text: str,
    new_text: str,
) -> Dict[str, Any]:
    """Replace text in a file.

    Args:
        file_path: Path to the file.
        old_text: Exact text to find and replace.
        new_text: Replacement text.
    """
    p = Path(file_path)
    if not p.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        content = p.read_text(errors="replace")
    except Exception as e:
        return {"error": f"Cannot read file: {e}"}

    if old_text not in content:
        return {"error": "old_text not found in file. Read the file first to get exact content."}

    count = content.count(old_text)
    if count > 1:
        return {"error": f"old_text matches {count} locations. Provide more context to be unique."}

    new_content = content.replace(old_text, new_text, 1)

    try:
        p.write_text(new_content)
    except Exception as e:
        return {"error": f"Cannot write file: {e}"}

    return {"file": file_path, "replaced": True, "old_length": len(old_text), "new_length": len(new_text)}
