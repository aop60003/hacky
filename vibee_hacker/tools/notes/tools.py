"""Notes system for agent working memory.

Allows the agent to record findings, methodology decisions, and
plans that persist across iterations and can be shared between agents.
Categories: findings, methodology, plan, wiki, general.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vibee_hacker.tools.registry import register_tool

_notes: Dict[str, Dict[str, Any]] = {}
_lock = threading.RLock()
_CATEGORIES = ("findings", "methodology", "plan", "wiki", "general")


@register_tool(
    description="Create a note to record findings, methodology, or plans. "
    "Notes persist across agent iterations.",
)
def create_note(
    title: str,
    content: str,
    category: str = "general",
) -> Dict[str, Any]:
    """Create a new note.

    Args:
        title: Note title.
        content: Note content (markdown supported).
        category: One of: findings, methodology, plan, wiki, general.
    """
    if category not in _CATEGORIES:
        return {"error": f"Invalid category. Use: {', '.join(_CATEGORIES)}"}

    note_id = f"note-{uuid4().hex[:8]}"
    with _lock:
        _notes[note_id] = {
            "id": note_id,
            "title": title,
            "content": content,
            "category": category,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    return {"id": note_id, "title": title, "category": category}


@register_tool(
    description="List all notes, optionally filtered by category.",
)
def list_notes(category: Optional[str] = None) -> Dict[str, Any]:
    """List all notes with previews."""
    with _lock:
        notes = []
        for n in _notes.values():
            if category and n["category"] != category:
                continue
            notes.append({
                "id": n["id"],
                "title": n["title"],
                "category": n["category"],
                "preview": n["content"][:150],
                "updated_at": n["updated_at"],
            })
    return {"notes": notes, "count": len(notes)}


@register_tool(description="Get the full content of a note by ID.")
def get_note(note_id: str) -> Dict[str, Any]:
    """Get full note content."""
    with _lock:
        note = _notes.get(note_id)
        if not note:
            return {"error": f"Note {note_id} not found"}
        return dict(note)


@register_tool(description="Update an existing note's content or title.")
def update_note(
    note_id: str,
    content: Optional[str] = None,
    title: Optional[str] = None,
    append: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a note. Use append to add content without replacing."""
    with _lock:
        note = _notes.get(note_id)
        if not note:
            return {"error": f"Note {note_id} not found"}
        if title:
            note["title"] = title
        if content:
            note["content"] = content
        if append:
            note["content"] += "\n" + append
        note["updated_at"] = datetime.now(timezone.utc).isoformat()
    return {"id": note_id, "updated": True}


@register_tool(description="Delete a note by ID.")
def delete_note(note_id: str) -> Dict[str, Any]:
    """Delete a note."""
    with _lock:
        if note_id not in _notes:
            return {"error": f"Note {note_id} not found"}
        del _notes[note_id]
    return {"deleted": note_id}
