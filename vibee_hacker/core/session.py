"""Scan session management — save and resume scans."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from vibee_hacker.core.models import Result, Severity


@dataclass
class ScanSession:
    """Represents a scan session that can be saved and resumed."""
    session_id: str = ""
    target: str = ""
    mode: str = "blackbox"
    scan_date: str = ""
    completed_plugins: list[str] = field(default_factory=list)
    pending_plugins: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    options: dict = field(default_factory=dict)
    status: str = "in_progress"  # in_progress, completed, failed
    spec_version: str = "1.0"

    def add_result(self, result: Result) -> None:
        """Append a Result to the session's result list."""
        self.results.append(result.to_dict())

    def mark_plugin_complete(self, plugin_name: str) -> None:
        """Mark a plugin as completed and remove it from pending list."""
        if plugin_name not in self.completed_plugins:
            self.completed_plugins.append(plugin_name)
        if plugin_name in self.pending_plugins:
            self.pending_plugins.remove(plugin_name)

    def is_plugin_completed(self, plugin_name: str) -> bool:
        """Return True if the plugin has already completed in this session."""
        return plugin_name in self.completed_plugins

    @property
    def checksum(self) -> str:
        """SHA-256 checksum (first 16 hex chars) of the serialised results list."""
        content = json.dumps(self.results, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class SessionManager:
    """Save and load scan sessions to/from JSON files."""

    def __init__(self, session_dir: str = ".vibee-sessions"):
        self.session_dir = Path(session_dir)

    def save(self, session: ScanSession, path: str | None = None) -> str:
        """Persist a session to disk and return the file path."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', session.session_id):
            raise ValueError(f"Invalid session_id: {session.session_id!r}. Only alphanumeric, dash, underscore allowed.")
        if not path:
            self.session_dir.mkdir(parents=True, exist_ok=True)
            path = str(self.session_dir / f"{session.session_id}.json")

        data = {
            "session_id": session.session_id,
            "target": session.target,
            "mode": session.mode,
            "scan_date": session.scan_date or datetime.now(timezone.utc).isoformat(),
            "completed_plugins": session.completed_plugins,
            "pending_plugins": session.pending_plugins,
            "results": session.results,
            "options": session.options,
            "status": session.status,
            "spec_version": session.spec_version,
            "checksum": session.checksum,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    def load(self, path: str) -> ScanSession:
        """Load a session from disk, verifying its integrity checksum."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Session file not found: {path}")

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        session = ScanSession(
            session_id=data.get("session_id", ""),
            target=data.get("target", ""),
            mode=data.get("mode", "blackbox"),
            scan_date=data.get("scan_date", ""),
            completed_plugins=data.get("completed_plugins", []),
            pending_plugins=data.get("pending_plugins", []),
            results=data.get("results", []),
            options=data.get("options", {}),
            status=data.get("status", "in_progress"),
            spec_version=data.get("spec_version", "1.0"),
        )

        stored_checksum = data.get("checksum", "")
        if stored_checksum and session.checksum != stored_checksum:
            raise ValueError(
                f"Session file integrity check failed: {path}"
            )

        return session

    def list_sessions(self) -> list[dict]:
        """Return a list of session summaries, newest first."""
        if not self.session_dir.exists():
            return []
        sessions = []
        for f in self.session_dir.glob("*.json"):
            try:
                with open(f, encoding="utf-8") as fh:
                    data = json.load(fh)
                sessions.append({
                    "session_id": data.get("session_id"),
                    "target": data.get("target"),
                    "status": data.get("status"),
                    "scan_date": data.get("scan_date"),
                    "path": str(f),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return sorted(sessions, key=lambda s: s.get("scan_date") or "", reverse=True)
