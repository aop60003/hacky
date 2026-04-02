"""Scan scheduler for periodic security scanning."""

from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ScheduledScan:
    """A scheduled scan configuration."""
    name: str
    target_url: str = ""
    target_path: str = ""
    mode: str = "blackbox"
    interval_minutes: int = 1440  # daily
    policy: str = "default"
    enabled: bool = True
    last_run: datetime | None = None
    next_run: datetime | None = None
    run_count: int = 0

    def should_run(self, now: datetime | None = None) -> bool:
        if not self.enabled:
            return False
        now = now or datetime.now(timezone.utc)
        if self.next_run is None:
            return True
        return now >= self.next_run

    def mark_completed(self):
        now = datetime.now(timezone.utc)
        self.last_run = now
        self.next_run = now + timedelta(minutes=self.interval_minutes)
        self.run_count += 1


@dataclass
class TrendPoint:
    """A single data point in trend tracking."""
    timestamp: datetime
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanScheduler:
    """Manages scheduled scans."""

    def __init__(self):
        self.schedules: list[ScheduledScan] = []
        self.trends: dict[str, list[TrendPoint]] = {}  # name -> trend history

    def add(self, schedule: ScheduledScan):
        self.schedules.append(schedule)
        if schedule.name not in self.trends:
            self.trends[schedule.name] = []

    def remove(self, name: str) -> bool:
        before = len(self.schedules)
        self.schedules = [s for s in self.schedules if s.name != name]
        return len(self.schedules) < before

    def get_due(self, now: datetime | None = None) -> list[ScheduledScan]:
        """Get all schedules that are due to run."""
        return [s for s in self.schedules if s.should_run(now)]

    def record_trend(self, name: str, point: TrendPoint):
        if name not in self.trends:
            self.trends[name] = []
        self.trends[name].append(point)
        # Keep last 365 entries
        if len(self.trends[name]) > 365:
            self.trends[name] = self.trends[name][-365:]

    def get_trend(self, name: str, days: int = 30) -> list[TrendPoint]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return [t for t in self.trends.get(name, []) if t.timestamp >= cutoff]

    def get_trend_summary(self, name: str) -> dict:
        points = self.trends.get(name, [])
        if not points:
            return {"scans": 0, "trend": "none"}
        first = points[0].total_findings
        last = points[-1].total_findings
        return {
            "scans": len(points),
            "first_findings": first,
            "last_findings": last,
            "trend": "improving" if last < first else "worsening" if last > first else "stable",
        }
