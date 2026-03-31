"""Tests for scan session management (save/resume)."""

import json
import pytest
from vibee_hacker.core.session import ScanSession, SessionManager
from vibee_hacker.core.models import Result, Severity


class TestScanSession:
    def test_create_session(self):
        s = ScanSession(session_id="test-001", target="https://example.com")
        assert s.session_id == "test-001"
        assert s.status == "in_progress"

    def test_add_result(self):
        s = ScanSession()
        r = Result(plugin_name="sqli", base_severity=Severity.CRITICAL, title="SQLi", description="Found")
        s.add_result(r)
        assert len(s.results) == 1
        assert s.results[0]["plugin_name"] == "sqli"

    def test_mark_plugin_complete(self):
        s = ScanSession(pending_plugins=["sqli", "xss"])
        s.mark_plugin_complete("sqli")
        assert "sqli" in s.completed_plugins
        assert "sqli" not in s.pending_plugins

    def test_mark_plugin_complete_not_in_pending(self):
        s = ScanSession(pending_plugins=["xss"])
        s.mark_plugin_complete("sqli")  # not in pending — should still add to completed
        assert "sqli" in s.completed_plugins
        assert "xss" in s.pending_plugins

    def test_mark_plugin_complete_idempotent(self):
        s = ScanSession(completed_plugins=["sqli"])
        s.mark_plugin_complete("sqli")  # already completed
        assert s.completed_plugins.count("sqli") == 1

    def test_is_plugin_completed(self):
        s = ScanSession(completed_plugins=["sqli"])
        assert s.is_plugin_completed("sqli")
        assert not s.is_plugin_completed("xss")

    def test_checksum_consistent(self):
        s = ScanSession()
        r = Result(plugin_name="sqli", base_severity=Severity.HIGH, title="T", description="D")
        s.add_result(r)
        c1 = s.checksum
        c2 = s.checksum
        assert c1 == c2

    def test_checksum_changes_with_results(self):
        s = ScanSession()
        c_empty = s.checksum
        r = Result(plugin_name="sqli", base_severity=Severity.HIGH, title="T", description="D")
        s.add_result(r)
        c_with_result = s.checksum
        assert c_empty != c_with_result

    def test_checksum_is_16_chars(self):
        s = ScanSession()
        assert len(s.checksum) == 16

    def test_default_spec_version(self):
        s = ScanSession()
        assert s.spec_version == "1.0"

    def test_default_mode(self):
        s = ScanSession()
        assert s.mode == "blackbox"


class TestSessionManager:
    @pytest.fixture
    def manager(self, tmp_path):
        return SessionManager(session_dir=str(tmp_path / "sessions"))

    def test_save_and_load(self, manager):
        session = ScanSession(session_id="s001", target="https://example.com", mode="blackbox")
        r = Result(plugin_name="xss", base_severity=Severity.HIGH, title="XSS", description="Found XSS")
        session.add_result(r)
        path = manager.save(session)
        loaded = manager.load(path)
        assert loaded.session_id == "s001"
        assert loaded.target == "https://example.com"
        assert loaded.mode == "blackbox"
        assert len(loaded.results) == 1
        assert loaded.results[0]["plugin_name"] == "xss"

    def test_save_creates_session_dir(self, manager):
        session = ScanSession(session_id="s_dir", target="https://example.com")
        path = manager.save(session)
        assert manager.session_dir.exists()
        assert manager.session_dir.is_dir()

    def test_save_returns_path(self, manager):
        session = ScanSession(session_id="s_path", target="https://example.com")
        path = manager.save(session)
        assert path.endswith(".json")
        assert "s_path" in path

    def test_save_explicit_path(self, tmp_path, manager):
        session = ScanSession(session_id="s_explicit", target="https://example.com")
        explicit_path = str(tmp_path / "custom.json")
        path = manager.save(session, path=explicit_path)
        assert path == explicit_path

    def test_integrity_check_fails_on_tamper(self, manager, tmp_path):
        session = ScanSession(session_id="s002", target="https://example.com")
        path = manager.save(session)
        # Tamper with the file
        with open(path) as f:
            data = json.load(f)
        data["results"] = [{"fake": "data"}]
        with open(path, "w") as f:
            json.dump(data, f)
        with pytest.raises(ValueError, match="integrity"):
            manager.load(path)

    def test_integrity_check_passes_unmodified(self, manager):
        session = ScanSession(session_id="s_ok", target="https://example.com")
        r = Result(plugin_name="sqli", base_severity=Severity.MEDIUM, title="T", description="D")
        session.add_result(r)
        path = manager.save(session)
        loaded = manager.load(path)
        assert loaded.session_id == "s_ok"

    def test_list_sessions(self, manager):
        s1 = ScanSession(session_id="s1", target="t1", scan_date="2026-01-01T00:00:00+00:00")
        s2 = ScanSession(session_id="s2", target="t2", scan_date="2026-01-02T00:00:00+00:00")
        manager.save(s1)
        manager.save(s2)
        sessions = manager.list_sessions()
        assert len(sessions) == 2
        assert sessions[0]["session_id"] == "s2"  # Newer first

    def test_list_sessions_empty(self, manager):
        assert manager.list_sessions() == []

    def test_list_sessions_skips_corrupt_files(self, manager, tmp_path):
        session = ScanSession(session_id="s_good", target="t1", scan_date="2026-01-01T00:00:00+00:00")
        manager.save(session)
        # Write a corrupt JSON file into the sessions dir
        corrupt = manager.session_dir / "corrupt.json"
        corrupt.write_text("not valid json")
        sessions = manager.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "s_good"

    def test_load_nonexistent_raises(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.load("/nonexistent/path.json")

    def test_roundtrip_completed_and_pending_plugins(self, manager):
        session = ScanSession(
            session_id="s_plugins",
            target="https://example.com",
            completed_plugins=["sqli", "xss"],
            pending_plugins=["csrf", "ssrf"],
        )
        path = manager.save(session)
        loaded = manager.load(path)
        assert loaded.completed_plugins == ["sqli", "xss"]
        assert loaded.pending_plugins == ["csrf", "ssrf"]

    def test_roundtrip_options(self, manager):
        session = ScanSession(
            session_id="s_opts",
            target="https://example.com",
            options={"timeout": 30, "safe_mode": True},
        )
        path = manager.save(session)
        loaded = manager.load(path)
        assert loaded.options == {"timeout": 30, "safe_mode": True}

    def test_roundtrip_status(self, manager):
        session = ScanSession(session_id="s_status", target="https://example.com", status="completed")
        path = manager.save(session)
        loaded = manager.load(path)
        assert loaded.status == "completed"
