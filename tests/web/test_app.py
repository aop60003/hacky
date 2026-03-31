"""Tests for FastAPI web dashboard."""
import pytest
from fastapi.testclient import TestClient

from vibee_hacker.web.app import app, _scan_results


class TestDashboard:
    @pytest.fixture(autouse=True)
    def clear_results(self):
        _scan_results.clear()
        yield
        _scan_results.clear()

    def test_dashboard_page(self):
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "VIBEE-Hacker Dashboard" in resp.text

    def test_dashboard_html_contains_form(self):
        client = TestClient(app)
        resp = client.get("/")
        assert "scanForm" in resp.text
        assert "New Scan" in resp.text

    def test_list_results_empty(self):
        client = TestClient(app)
        resp = client.get("/api/results")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_scan_and_list(self):
        client = TestClient(app)
        resp = client.post("/api/scan", json={"target": "https://example.com", "mode": "blackbox"})
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert data["target"] == "https://example.com"
        assert data["mode"] == "blackbox"
        assert "total_findings" in data
        assert isinstance(data["total_findings"], int)
        assert "findings" in data
        # Check it appears in results list
        list_resp = client.get("/api/results")
        assert len(list_resp.json()) == 1

    def test_scan_whitebox_mode(self, tmp_path):
        client = TestClient(app)
        resp = client.post("/api/scan", json={"target": str(tmp_path), "mode": "whitebox"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "whitebox"

    def test_get_result_by_id(self):
        client = TestClient(app)
        post_resp = client.post("/api/scan", json={"target": "https://example.com", "mode": "blackbox"})
        scan_id = post_resp.json()["id"]
        get_resp = client.get(f"/api/results/{scan_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == scan_id

    def test_get_result_not_found(self):
        client = TestClient(app)
        resp = client.get("/api/results/nonexistent")
        assert resp.json()["error"] == "not found"

    def test_multiple_scans_listed(self):
        client = TestClient(app)
        client.post("/api/scan", json={"target": "https://example.com", "mode": "blackbox"})
        client.post("/api/scan", json={"target": "https://other.com", "mode": "blackbox"})
        list_resp = client.get("/api/results")
        assert len(list_resp.json()) == 2

    def test_results_sorted_by_date_descending(self):
        """Verify results list is sorted by scan_date descending using direct store injection."""
        from vibee_hacker.web.app import _scan_results
        import uuid
        # Inject two fake results with known dates directly (no actual scan needed)
        id1 = str(uuid.uuid4())
        id2 = str(uuid.uuid4())
        _scan_results[id1] = {
            "id": id1, "target": "https://first.com", "mode": "blackbox",
            "scan_date": "2026-01-01T00:00:00+00:00", "total_findings": 0, "findings": [],
        }
        _scan_results[id2] = {
            "id": id2, "target": "https://second.com", "mode": "blackbox",
            "scan_date": "2026-06-01T00:00:00+00:00", "total_findings": 0, "findings": [],
        }
        client = TestClient(app)
        list_resp = client.get("/api/results")
        results = list_resp.json()
        assert len(results) == 2
        # second.com has later date, should appear first
        assert results[0]["target"] == "https://second.com"
        assert results[1]["target"] == "https://first.com"
