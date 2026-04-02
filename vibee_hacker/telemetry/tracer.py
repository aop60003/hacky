"""Structured event tracer for scan execution.

Records scan lifecycle events to JSONL files for auditing, debugging,
and CI/CD integration. Follows Strix's tracer pattern with local-only output.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from vibee_hacker.config import Config

logger = logging.getLogger(__name__)

# Patterns for sanitizing sensitive data
_SENSITIVE_PATTERNS = [
    re.compile(r"(Authorization:\s*)(Bearer\s+)?\S+", re.I),
    re.compile(r"(Cookie:\s*)\S+", re.I),
    re.compile(r"(api[_-]?key[\"']?\s*[:=]\s*[\"']?)\S+", re.I),
    re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)\S+", re.I),
    re.compile(r"(token[\"']?\s*[:=]\s*[\"']?)\S+", re.I),
]

# Additional patterns for response bodies
_BODY_SENSITIVE_PATTERNS = [
    re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', re.I),  # JWT
    re.compile(r'("password"\s*:\s*")[^"]+(")', re.I),  # JSON password field
    re.compile(r'("secret"\s*:\s*")[^"]+(")', re.I),  # JSON secret field
    re.compile(r'("token"\s*:\s*")[^"]+(")', re.I),  # JSON token field
    re.compile(r'(AKIA[A-Z0-9]{16})', re.I),  # AWS Access Key
]

_global_tracer: Optional[Tracer] = None


def get_global_tracer() -> Optional["Tracer"]:
    """Get the global tracer instance."""
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    """Set the global tracer instance."""
    global _global_tracer
    _global_tracer = tracer


def _sanitize(text: str) -> str:
    """Remove sensitive data from text."""
    for pattern in _SENSITIVE_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    # Apply body-specific patterns
    for pattern in _BODY_SENSITIVE_PATTERNS:
        def _replace(m: re.Match) -> str:
            if m.lastindex and m.lastindex >= 2:
                # Two-group pattern: keep surrounding delimiters, redact value
                return m.group(1) + "[REDACTED]" + m.group(2)
            elif m.lastindex and m.lastindex >= 1:
                # Single-group pattern capturing the whole sensitive value
                return "[REDACTED]"
            return "[REDACTED]"
        text = pattern.sub(_replace, text)
    return text


class Tracer:
    """Structured event tracer for scan lifecycle.

    Records events as JSONL to vibee_runs/<scan_id>/events.jsonl.
    Supports optional callbacks for real-time vulnerability display.
    """

    def __init__(
        self,
        scan_id: Optional[str] = None,
        enabled: Optional[bool] = None,
        output_dir: Optional[str] = None,
    ):
        self.scan_id = scan_id or f"scan-{uuid4().hex[:8]}"
        self._enabled = enabled if enabled is not None else Config.get_bool("vibee_telemetry", fallback=True)
        self._lock = threading.Lock()

        # Output directory
        if output_dir:
            self._run_dir = Path(output_dir) / self.scan_id
        else:
            self._run_dir = Path("vibee_runs") / self.scan_id

        # Stats
        self.plugins_started: int = 0
        self.plugins_completed: int = 0
        self.plugins_failed: int = 0
        self.findings_count: int = 0
        self.findings: List[Dict[str, Any]] = []

        # Directory creation flag
        self._run_dir_created: bool = False

        # Callbacks
        self.on_finding: Optional[Callable[[Dict[str, Any]], None]] = None
        self.on_plugin_start: Optional[Callable[[str], None]] = None
        self.on_plugin_complete: Optional[Callable[[str, int], None]] = None

    @property
    def run_dir(self) -> Path:
        """Get the run output directory."""
        return self._run_dir

    @property
    def events_file(self) -> Path:
        """Get the events JSONL file path."""
        return self._run_dir / "events.jsonl"

    def _emit_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        status: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """Write a structured event to the JSONL file."""
        if not self._enabled:
            return

        event: Dict[str, Any] = {
            "event_type": event_type,
            "scan_id": self.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if payload:
            event["payload"] = payload
        if status:
            event["status"] = status
        if error:
            event["error"] = _sanitize(str(error))

        self._append_record(event)

    def _ensure_run_dir(self) -> None:
        """Create run directory if it doesn't exist (cached)."""
        if not self._run_dir_created:
            self._run_dir.mkdir(parents=True, exist_ok=True)
            self._run_dir_created = True

    def _append_record(self, record: Dict[str, Any]) -> None:
        """Thread-safe append of a JSON record to events.jsonl."""
        try:
            with self._lock:
                self._ensure_run_dir()
                events_path = self.events_file
                file_exists = events_path.exists()
                with events_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, default=str) + "\n")
                # Set restrictive permissions (0o600) on newly created files
                if not file_exists:
                    try:
                        os.chmod(events_path, 0o600)
                    except OSError:
                        pass  # Non-fatal on platforms that don't support it (e.g. Windows)
        except OSError as e:
            logger.debug("Failed to write telemetry event: %s", e)

    # --- Scan lifecycle events ---

    def log_scan_started(
        self,
        target: str,
        mode: str,
        plugin_count: int,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log scan start event."""
        self._emit_event(
            "scan.started",
            payload={
                "target": _sanitize(target),
                "mode": mode,
                "plugin_count": plugin_count,
                **(options or {}),
            },
            status="running",
        )

    def log_scan_completed(
        self,
        total_findings: int,
        duration_seconds: float,
        severity_summary: Optional[Dict[str, int]] = None,
    ) -> None:
        """Log scan completion event."""
        self._emit_event(
            "scan.completed",
            payload={
                "total_findings": total_findings,
                "duration_seconds": round(duration_seconds, 2),
                "plugins_run": self.plugins_completed + self.plugins_failed,
                "plugins_failed": self.plugins_failed,
                "severity_summary": severity_summary or {},
            },
            status="completed",
        )

    # --- Plugin lifecycle events ---

    def log_plugin_started(self, plugin_name: str, phase: int = 0) -> None:
        """Log plugin execution start."""
        self.plugins_started += 1
        self._emit_event(
            "plugin.started",
            payload={"plugin_name": plugin_name, "phase": phase},
            status="running",
        )
        if self.on_plugin_start:
            try:
                self.on_plugin_start(plugin_name)
            except Exception as exc:
                logger.debug("Tracer callback error: %s", exc)

    def log_plugin_completed(
        self,
        plugin_name: str,
        finding_count: int,
        duration_seconds: float,
    ) -> None:
        """Log plugin execution completion."""
        self.plugins_completed += 1
        self._emit_event(
            "plugin.completed",
            payload={
                "plugin_name": plugin_name,
                "finding_count": finding_count,
                "duration_seconds": round(duration_seconds, 2),
            },
            status="completed",
        )
        if self.on_plugin_complete:
            try:
                self.on_plugin_complete(plugin_name, finding_count)
            except Exception as exc:
                logger.debug("Tracer callback error: %s", exc)

    def log_plugin_failed(
        self,
        plugin_name: str,
        error: str,
        duration_seconds: float = 0,
    ) -> None:
        """Log plugin execution failure."""
        self.plugins_failed += 1
        self._emit_event(
            "plugin.failed",
            payload={
                "plugin_name": plugin_name,
                "duration_seconds": round(duration_seconds, 2),
            },
            status="failed",
            error=error,
        )

    # --- Finding events ---

    def log_finding(self, finding: Dict[str, Any]) -> None:
        """Log a vulnerability finding."""
        self.findings_count += 1
        sanitized = {k: _sanitize(str(v)) if isinstance(v, str) else v for k, v in finding.items()}
        # Keep in-memory list bounded to avoid unbounded growth
        if len(self.findings) < 10000:
            self.findings.append(sanitized)
        self._emit_event(
            "finding.created",
            payload=sanitized,
        )
        if self.on_finding:
            try:
                self.on_finding(sanitized)
            except Exception as exc:
                logger.debug("Tracer callback error: %s", exc)

    # --- Crawl events ---

    def log_crawl_completed(self, urls_found: int, forms_found: int) -> None:
        """Log crawler completion."""
        self._emit_event(
            "crawl.completed",
            payload={"urls_found": urls_found, "forms_found": forms_found},
            status="completed",
        )

    def log_crawl_failed(self, error: str) -> None:
        """Log crawler failure."""
        self._emit_event(
            "crawl.failed",
            status="failed",
            error=error,
        )

    # --- Data export ---

    def save_run_data(self, mark_complete: bool = False) -> None:
        """Save run summary data."""
        if not self._enabled:
            return

        summary = {
            "scan_id": self.scan_id,
            "plugins_started": self.plugins_started,
            "plugins_completed": self.plugins_completed,
            "plugins_failed": self.plugins_failed,
            "findings_count": self.findings_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if mark_complete:
            summary["status"] = "completed"

        summary_path = self._run_dir / "summary.json"
        try:
            self._run_dir.mkdir(parents=True, exist_ok=True)
            with summary_path.open("w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, default=str)
        except OSError as e:
            logger.debug("Failed to save run summary: %s", e)
