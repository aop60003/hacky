"""Tests for scan scheduler and trend analysis."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

from vibee_hacker.core.scheduler import ScheduledScan, ScanScheduler, TrendPoint


# ── helpers ──────────────────────────────────────────────────────────────────

def _utc(**kw) -> datetime:
    return datetime.now(timezone.utc) + timedelta(**kw)


def _make_point(total: int, offset_days: int = 0) -> TrendPoint:
    return TrendPoint(
        timestamp=_utc(days=-offset_days),
        total_findings=total,
        critical=0, high=0, medium=0, low=0, info=0,
    )


# ── ScheduledScan ─────────────────────────────────────────────────────────────

def test_add_schedule():
    scheduler = ScanScheduler()
    scan = ScheduledScan(name="test-scan", target_url="http://example.com")
    scheduler.add(scan)
    assert len(scheduler.schedules) == 1
    assert scheduler.schedules[0].name == "test-scan"


def test_remove_schedule():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="alpha"))
    scheduler.add(ScheduledScan(name="beta"))
    removed = scheduler.remove("alpha")
    assert removed is True
    assert len(scheduler.schedules) == 1
    assert scheduler.schedules[0].name == "beta"


def test_remove_nonexistent_returns_false():
    scheduler = ScanScheduler()
    assert scheduler.remove("ghost") is False


def test_should_run_enabled_no_next_run():
    """A scan with no next_run and enabled=True should always be due."""
    scan = ScheduledScan(name="s", enabled=True, next_run=None)
    assert scan.should_run() is True


def test_should_run_disabled():
    scan = ScheduledScan(name="s", enabled=False, next_run=None)
    assert scan.should_run() is False


def test_should_run_not_due():
    """If next_run is in the future the scan is not due."""
    future = _utc(minutes=60)
    scan = ScheduledScan(name="s", enabled=True, next_run=future)
    assert scan.should_run() is False


def test_should_run_past_due():
    past = _utc(minutes=-5)
    scan = ScheduledScan(name="s", enabled=True, next_run=past)
    assert scan.should_run() is True


def test_mark_completed():
    scan = ScheduledScan(name="s", interval_minutes=60)
    assert scan.run_count == 0
    scan.mark_completed()
    assert scan.run_count == 1
    assert scan.last_run is not None
    assert scan.next_run is not None
    # next_run should be ~60 min from now
    delta = scan.next_run - datetime.now(timezone.utc)
    assert 59 <= delta.total_seconds() / 60 <= 61


def test_get_due():
    scheduler = ScanScheduler()
    past = _utc(minutes=-1)
    future = _utc(minutes=60)
    scheduler.add(ScheduledScan(name="due", enabled=True, next_run=past))
    scheduler.add(ScheduledScan(name="not-due", enabled=True, next_run=future))
    scheduler.add(ScheduledScan(name="disabled", enabled=False, next_run=past))

    due = scheduler.get_due()
    assert len(due) == 1
    assert due[0].name == "due"


# ── Trend tracking ────────────────────────────────────────────────────────────

def test_record_trend():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="web"))
    point = _make_point(10)
    scheduler.record_trend("web", point)
    assert len(scheduler.trends["web"]) == 1


def test_get_trend_days_filter():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="web"))
    # one recent, one old
    scheduler.record_trend("web", _make_point(5, offset_days=1))
    scheduler.record_trend("web", _make_point(8, offset_days=40))
    result = scheduler.get_trend("web", days=30)
    assert len(result) == 1
    assert result[0].total_findings == 5


def test_trend_summary_improving():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="web"))
    scheduler.record_trend("web", _make_point(20, offset_days=5))
    scheduler.record_trend("web", _make_point(10, offset_days=1))
    summary = scheduler.get_trend_summary("web")
    assert summary["trend"] == "improving"
    assert summary["scans"] == 2


def test_trend_summary_stable():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="web"))
    scheduler.record_trend("web", _make_point(10, offset_days=2))
    scheduler.record_trend("web", _make_point(10, offset_days=1))
    summary = scheduler.get_trend_summary("web")
    assert summary["trend"] == "stable"


def test_trend_365_limit():
    scheduler = ScanScheduler()
    scheduler.add(ScheduledScan(name="web"))
    for i in range(400):
        scheduler.record_trend("web", _make_point(i))
    assert len(scheduler.trends["web"]) == 365
