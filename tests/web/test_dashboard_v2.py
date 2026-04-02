"""Tests for Advanced Dashboard (Charts & Trends) API endpoints."""

from __future__ import annotations
import uuid
import pytest
from fastapi.testclient import TestClient

from vibee_hacker.web.app import app, _scan_results, scan_history


@pytest.fixture(autouse=True)
def clear_state():
    _scan_results.clear()
    scan_history.clear()
    yield
    _scan_results.clear()
    scan_history.clear()


def _inject_scan(
    total_findings: int = 0,
    timestamp: str = "2026-01-01T00:00:00+00:00",
    findings: list[dict] | None = None,
) -> dict:
    """Directly inject a scan entry into the shared stores (no HTTP round-trip)."""
    scan_id = str(uuid.uuid4())
    if findings is None:
        findings = []
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("base_severity", "")).lower()
        if sev in severity_summary:
            severity_summary[sev] += 1
    scan_data = {
        "id": scan_id,
        "target": "https://example.com",
        "mode": "blackbox",
        "scan_date": timestamp,
        "timestamp": timestamp,
        "total_findings": total_findings,
        "findings": findings,
        "severity_summary": severity_summary,
    }
    _scan_results[scan_id] = scan_data
    scan_history.append(scan_data)
    return scan_data


class TestStatsEndpoint:
    def test_stats_endpoint_returns_200(self):
        client = TestClient(app)
        resp = client.get("/api/stats")
        assert resp.status_code == 200

    def test_stats_empty(self):
        client = TestClient(app)
        resp = client.get("/api/stats")
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["total_findings"] == 0
        assert data["severity_distribution"] == {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        assert data["top_plugins"] == []
        assert data["recent_scans"] == []

    def test_stats_aggregates_findings(self):
        _inject_scan(total_findings=5)
        _inject_scan(total_findings=3)
        client = TestClient(app)
        resp = client.get("/api/stats")
        data = resp.json()
        assert data["total_scans"] == 2
        assert data["total_findings"] == 8

    def test_stats_recent_scans_max_10(self):
        for i in range(15):
            _inject_scan(total_findings=i)
        client = TestClient(app)
        resp = client.get("/api/stats")
        data = resp.json()
        assert len(data["recent_scans"]) <= 10

    def test_stats_severity_distribution(self):
        _inject_scan(
            total_findings=2,
            findings=[
                {"base_severity": "critical", "plugin_name": "p1"},
                {"base_severity": "high", "plugin_name": "p2"},
            ],
        )
        client = TestClient(app)
        resp = client.get("/api/stats")
        data = resp.json()
        assert data["severity_distribution"]["critical"] == 1
        assert data["severity_distribution"]["high"] == 1

    def test_stats_top_plugins(self):
        _inject_scan(
            total_findings=2,
            findings=[
                {"base_severity": "low", "plugin_name": "sqli"},
                {"base_severity": "low", "plugin_name": "sqli"},
            ],
        )
        client = TestClient(app)
        resp = client.get("/api/stats")
        data = resp.json()
        assert any(p["plugin"] == "sqli" and p["count"] == 2 for p in data["top_plugins"])


class TestTrendsEndpoint:
    def test_trends_endpoint_returns_200(self):
        client = TestClient(app)
        resp = client.get("/api/trends")
        assert resp.status_code == 200

    def test_trends_empty(self):
        client = TestClient(app)
        resp = client.get("/api/trends")
        data = resp.json()
        assert data == {"trends": []}

    def test_trends_contains_scan_data(self):
        _inject_scan(total_findings=5, timestamp="2026-03-01T00:00:00+00:00")
        client = TestClient(app)
        resp = client.get("/api/trends")
        data = resp.json()
        assert len(data["trends"]) == 1
        assert data["trends"][0]["total"] == 5
        assert data["trends"][0]["date"] == "2026-03-01T00:00:00+00:00"

    def test_trends_multiple_scans(self):
        _inject_scan(total_findings=2, timestamp="2026-01-01T00:00:00+00:00")
        _inject_scan(total_findings=7, timestamp="2026-02-01T00:00:00+00:00")
        client = TestClient(app)
        resp = client.get("/api/trends")
        data = resp.json()
        assert len(data["trends"]) == 2

    def test_trends_includes_critical_and_high(self):
        _inject_scan(
            total_findings=3,
            findings=[
                {"base_severity": "critical", "plugin_name": "p"},
                {"base_severity": "high", "plugin_name": "p"},
                {"base_severity": "low", "plugin_name": "p"},
            ],
        )
        client = TestClient(app)
        resp = client.get("/api/trends")
        data = resp.json()
        entry = data["trends"][0]
        assert entry["critical"] == 1
        assert entry["high"] == 1


class TestCompareEndpoint:
    def test_compare_endpoint_returns_200(self):
        _inject_scan(total_findings=3)
        _inject_scan(total_findings=7)
        client = TestClient(app)
        resp = client.get("/api/compare/0/1")
        assert resp.status_code == 200

    def test_compare_endpoint_result(self):
        _inject_scan(total_findings=3)
        _inject_scan(total_findings=7)
        client = TestClient(app)
        resp = client.get("/api/compare/0/1")
        data = resp.json()
        assert data["new_findings"] == 4
        assert "scan1" in data
        assert "scan2" in data

    def test_compare_same_scan(self):
        _inject_scan(total_findings=5)
        client = TestClient(app)
        resp = client.get("/api/compare/0/0")
        data = resp.json()
        assert data["new_findings"] == 0

    def test_compare_invalid_returns_error(self):
        # No scans injected, index 99 is invalid
        client = TestClient(app)
        resp = client.get("/api/compare/0/99")
        data = resp.json()
        assert "error" in data

    def test_compare_both_invalid(self):
        client = TestClient(app)
        resp = client.get("/api/compare/50/99")
        data = resp.json()
        assert "error" in data

    def test_compare_negative_new_findings(self):
        """Regression improved — new_findings can be negative (fixes regression)."""
        _inject_scan(total_findings=10)
        _inject_scan(total_findings=3)
        client = TestClient(app)
        resp = client.get("/api/compare/0/1")
        data = resp.json()
        assert data["new_findings"] == -7
