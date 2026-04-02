"""Scan state machine for lifecycle management.

Pydantic-based state tracking with iteration budgets, pause/resume,
and progress monitoring. Follows Strix's AgentState pattern.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

logger = logging.getLogger(__name__)

# Valid state transitions
VALID_TRANSITIONS: Dict[str, set] = {
    "idle": {"running"},
    "running": {"paused", "completed", "failed"},
    "paused": {"running", "failed"},
    "completed": set(),  # terminal
    "failed": set(),     # terminal
}


class ScanState(BaseModel):
    """State machine for scan execution lifecycle."""

    # Identity
    scan_id: str = Field(default_factory=lambda: f"scan-{uuid4().hex[:8]}")

    # Task
    target: str = ""
    mode: str = "blackbox"

    # Iteration tracking
    iteration: int = 0
    max_iterations: int = 10
    phase: int = 0

    # Formal status for state-machine transitions
    status: str = "idle"

    # Status flags
    completed: bool = False
    stop_requested: bool = False
    paused: bool = False
    pause_reason: Optional[str] = None

    # Progress tracking
    completed_plugins: List[str] = Field(default_factory=list)
    failed_plugins: List[str] = Field(default_factory=list)
    total_plugins: int = 0

    # Results
    results: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Options
    options: Dict[str, Any] = Field(default_factory=dict)

    # Internal lookup sets (excluded from serialization)
    _completed_set: set = PrivateAttr(default_factory=set)
    _failed_set: set = PrivateAttr(default_factory=set)

    def model_post_init(self, __context: Any) -> None:
        """Rebuild internal sets from deserialized lists."""
        self._completed_set = set(self.completed_plugins)
        self._failed_set = set(self.failed_plugins)

    def increment_iteration(self) -> None:
        """Increment iteration counter with budget warnings."""
        self.iteration += 1
        if self.max_iterations > 0 and self.is_approaching_max_iterations():
            remaining = self.max_iterations - self.iteration
            logger.warning(
                "Scan %s: %d iterations remaining (at %.0f%%)",
                self.scan_id,
                remaining,
                (self.iteration / self.max_iterations) * 100,
            )

    def should_stop(self) -> bool:
        """Check if scan should stop."""
        return (
            self.completed
            or self.stop_requested
            or self.has_reached_max_iterations()
        )

    def has_reached_max_iterations(self) -> bool:
        """Check if max iterations reached."""
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        """Check if approaching iteration limit."""
        if self.max_iterations <= 0:
            return False
        return self.iteration / self.max_iterations >= threshold

    def request_stop(self, reason: str = "") -> None:
        """Request scan to stop."""
        self.stop_requested = True
        if reason:
            self.errors.append(f"Stop requested: {reason}")

    def set_completed(self) -> None:
        """Mark scan as completed."""
        self.completed = True
        self.completed_at = datetime.now(timezone.utc)

    def mark_plugin_complete(self, plugin_name: str) -> None:
        """Record a plugin as completed."""
        if plugin_name not in self._completed_set:
            self.completed_plugins.append(plugin_name)
            self._completed_set.add(plugin_name)

    def mark_plugin_failed(self, plugin_name: str, error: str) -> None:
        """Record a plugin as failed."""
        if plugin_name not in self._failed_set:
            self.failed_plugins.append(plugin_name)
            self._failed_set.add(plugin_name)
        self.errors.append(f"{plugin_name}: {error}")

    def add_results(self, results: List[Dict[str, Any]]) -> None:
        """Add scan results."""
        self.results.extend(results)

    def enter_waiting_state(self, reason: str = "") -> None:
        """Pause scan execution."""
        self.paused = True
        self.pause_reason = reason

    def resume(self, new_target: Optional[str] = None) -> None:
        """Resume from paused state."""
        self.paused = False
        self.pause_reason = None
        if new_target:
            self.target = new_target

    @property
    def progress_pct(self) -> float:
        """Get progress percentage based on plugin completion."""
        if self.total_plugins <= 0:
            return 0.0
        return len(self.completed_plugins) / self.total_plugins * 100

    def set_status(self, new_status: str) -> None:
        """Set status with transition validation."""
        current = self.status
        valid_next = VALID_TRANSITIONS.get(current, set())
        if new_status not in valid_next:
            raise ValueError(f"Invalid transition: {current} -> {new_status}")
        self.status = new_status

    @classmethod
    def get_state_diagram(cls) -> str:
        """Return human-readable state transition diagram."""
        return """
    idle → running → completed
                   → failed
                   → paused → running
                            → failed
    """

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "iteration": self.iteration,
            "completed": self.completed,
            "plugins_completed": len(self.completed_plugins),
            "plugins_failed": len(self.failed_plugins),
            "total_plugins": self.total_plugins,
            "results_count": len(self.results),
            "errors_count": len(self.errors),
            "progress_pct": round(self.progress_pct, 1),
        }
