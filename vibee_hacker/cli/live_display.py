"""Real-time scan progress display using Rich Live.

Provides a live-updating terminal UI showing plugin execution progress,
findings as they arrive, and scan statistics.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


class LiveScanDisplay:
    """Live-updating scan progress display.

    Uses Rich Live to show real-time scan progress with plugin status,
    findings as they arrive, and overall statistics.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._lock = threading.Lock()

        # Tracking state
        self._current_plugins: set = set()
        self._completed_count: int = 0
        self._failed_count: int = 0
        self._findings: List[Dict[str, Any]] = []
        self._total_plugins: int = 0
        self._start_time: float = time.monotonic()
        self._target: str = ""
        self._mode: str = ""

        pass  # Progress tracking via _completed_count / _total_plugins

    def set_scan_info(self, target: str, mode: str, total_plugins: int) -> None:
        """Set scan metadata."""
        self._target = target
        self._mode = mode
        self._total_plugins = total_plugins

    def on_plugin_start(self, plugin_name: str) -> None:
        """Callback when a plugin starts executing."""
        with self._lock:
            self._current_plugins.add(plugin_name)

    def on_plugin_complete(self, plugin_name: str, finding_count: int) -> None:
        """Callback when a plugin completes."""
        with self._lock:
            self._current_plugins.discard(plugin_name)
            self._completed_count += 1

    def on_plugin_failed(self, plugin_name: str) -> None:
        """Callback when a plugin fails."""
        with self._lock:
            self._current_plugins.discard(plugin_name)
            self._failed_count += 1

    def on_finding(self, finding: Dict[str, Any]) -> None:
        """Callback when a vulnerability is found."""
        with self._lock:
            # Keep only last 100 findings in memory for display
            if len(self._findings) >= 100:
                self._findings.pop(0)
            self._findings.append(finding)

    def _build_display(self) -> Panel:
        """Build the live display panel."""
        with self._lock:
            elapsed = time.monotonic() - self._start_time
            completed = self._completed_count
            failed = self._failed_count
            total = self._total_plugins or 1
            pct = min(100, int((completed + failed) / total * 100))

            # Header
            header = Text()
            header.append("VIBEE-Hacker ", style="bold cyan")
            header.append(f"| {self._target} ", style="dim")
            header.append(f"[{self._mode}] ", style="cyan")
            header.append(f"| {elapsed:.0f}s", style="dim")

            # Progress bar
            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = Text()
            bar.append("[")
            bar.append("=" * filled, style="green")
            bar.append(" " * (bar_width - filled))
            bar.append(f"] {pct}%  ")
            bar.append(f"{completed}/{total} done", style="green")
            if failed:
                bar.append(f", {failed} failed", style="red")

            # Running plugins
            if self._current_plugins:
                running_list = sorted(self._current_plugins)[:3]
                running = ", ".join(running_list)
                if len(self._current_plugins) > 3:
                    running += f" +{len(self._current_plugins) - 3}"
                bar.append(f" | {running}", style="dim")

            # Findings summary
            severity_counts: Dict[str, int] = {}
            for f in self._findings:
                sev = str(f.get("base_severity", f.get("context_severity", "info")))
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            findings_text = Text()
            findings_text.append(f"Findings: {len(self._findings)}", style="bold")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    color = SEVERITY_COLORS.get(sev, "white")
                    findings_text.append(f" | {sev}: {count}", style=color)

            # Recent findings (last 3)
            recent = Text()
            for f in self._findings[-3:]:
                sev = str(f.get("base_severity", f.get("context_severity", "info")))
                color = SEVERITY_COLORS.get(sev, "white")
                title = str(f.get("title", ""))[:55]
                plugin = str(f.get("plugin_name", ""))
                recent.append(f"  [{sev.upper()}]", style=color)
                recent.append(f" {title} ")
                recent.append(f"({plugin})\n", style="dim")

            content = Text.assemble(
                header, "\n",
                bar, "\n",
                findings_text, "\n",
                recent,
            )

            return Panel(
                content,
                title="[bold cyan]Scan Progress[/bold cyan]",
                border_style="cyan",
            )

    def start(self) -> "LiveContext":
        """Start the live display. Returns a context manager."""
        return LiveContext(self)


class LiveContext:
    """Context manager for the live scan display."""

    def __init__(self, display: LiveScanDisplay):
        self._display = display
        self._live: Optional[Live] = None
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None

    def __enter__(self) -> LiveScanDisplay:
        self._live = Live(
            self._display._build_display(),
            console=self._display.console,
            refresh_per_second=2,
            transient=False,
        )
        self._live.__enter__()

        # Start background update thread
        self._stop_event.clear()
        self._update_thread = threading.Thread(
            target=self._update_loop, daemon=True
        )
        self._update_thread.start()

        return self._display

    def __exit__(self, *args: Any) -> None:
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=3)
        if self._live:
            # Final update
            self._live.update(self._display._build_display())
            self._live.__exit__(*args)

    def _update_loop(self) -> None:
        """Background thread that refreshes the display."""
        while not self._stop_event.is_set():
            if self._live:
                try:
                    self._live.update(self._display._build_display())
                except Exception:
                    pass
            self._stop_event.wait(timeout=1)
