"""Tests for Tracer event logging, sensitive data redaction, and JSONL format."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vibee_hacker.telemetry.tracer import Tracer, _sanitize


@pytest.fixture
def tmp_tracer(tmp_path):
    """Create a Tracer writing to a temp directory."""
    return Tracer(scan_id="test-scan-001", enabled=True, output_dir=str(tmp_path))


def test_tracer_initialization(tmp_tracer):
    assert tmp_tracer.scan_id == "test-scan-001"
    assert tmp_tracer.plugins_started == 0
    assert tmp_tracer.plugins_completed == 0
    assert tmp_tracer.plugins_failed == 0
    assert tmp_tracer.findings_count == 0
    assert tmp_tracer.findings == []


def test_tracer_disabled_writes_nothing(tmp_path):
    tracer = Tracer(scan_id="disabled-scan", enabled=False, output_dir=str(tmp_path))
    tracer.log_scan_started("http://example.com", "blackbox", 5)
    # Directory should not be created since disabled
    run_dir = Path(tmp_path) / "disabled-scan"
    assert not tracer.events_file.exists()


def test_log_scan_started_writes_jsonl(tmp_tracer, tmp_path):
    tmp_tracer.log_scan_started("http://example.com", "blackbox", 10)
    events = _read_events(tmp_tracer.events_file)
    assert len(events) == 1
    assert events[0]["event_type"] == "scan.started"
    assert events[0]["payload"]["mode"] == "blackbox"
    assert events[0]["scan_id"] == "test-scan-001"


def test_log_plugin_lifecycle_counters(tmp_tracer):
    tmp_tracer.log_plugin_started("sqli", phase=1)
    assert tmp_tracer.plugins_started == 1

    tmp_tracer.log_plugin_completed("sqli", finding_count=2, duration_seconds=1.5)
    assert tmp_tracer.plugins_completed == 1

    tmp_tracer.log_plugin_failed("xss", error="timeout", duration_seconds=0.5)
    assert tmp_tracer.plugins_failed == 1


def test_log_finding_increments_count(tmp_tracer):
    finding = {"title": "SQL Injection", "severity": "critical", "endpoint": "/api/users"}
    tmp_tracer.log_finding(finding)
    assert tmp_tracer.findings_count == 1
    assert len(tmp_tracer.findings) == 1


def test_sensitive_data_redaction_in_sanitize():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.signature"
    result = _sanitize(text)
    assert "secret" not in result
    assert "[REDACTED]" in result

    text2 = 'api_key: "my-super-secret-key-123"'
    result2 = _sanitize(text2)
    assert "my-super-secret-key-123" not in result2
    assert "[REDACTED]" in result2

    text3 = 'password: "hunter2"'
    result3 = _sanitize(text3)
    assert "hunter2" not in result3


def test_jsonl_format_valid_json(tmp_tracer):
    tmp_tracer.log_scan_started("http://example.com", "blackbox", 3)
    tmp_tracer.log_plugin_started("cors", phase=0)
    tmp_tracer.log_plugin_completed("cors", finding_count=1, duration_seconds=0.3)
    tmp_tracer.log_scan_completed(total_findings=1, duration_seconds=0.5)

    events = _read_events(tmp_tracer.events_file)
    assert len(events) == 4
    event_types = [e["event_type"] for e in events]
    assert "scan.started" in event_types
    assert "plugin.started" in event_types
    assert "plugin.completed" in event_types
    assert "scan.completed" in event_types


def test_save_run_data_creates_summary_json(tmp_tracer):
    tmp_tracer.log_plugin_started("test_plugin")
    tmp_tracer.log_plugin_completed("test_plugin", 0, 0.1)
    tmp_tracer.save_run_data(mark_complete=True)

    summary_path = tmp_tracer.run_dir / "summary.json"
    assert summary_path.exists()
    with summary_path.open() as f:
        summary = json.load(f)
    assert summary["scan_id"] == "test-scan-001"
    assert summary["status"] == "completed"


def _read_events(events_file: Path) -> list:
    """Read all JSONL events from the events file."""
    if not events_file.exists():
        return []
    events = []
    with events_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
