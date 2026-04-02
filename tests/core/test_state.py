"""Tests for ScanState lifecycle management."""
from __future__ import annotations

import pytest
from vibee_hacker.core.state import ScanState


def test_scan_state_default_initialization():
    state = ScanState()
    assert state.scan_id.startswith("scan-")
    assert state.target == ""
    assert state.mode == "blackbox"
    assert state.iteration == 0
    assert state.max_iterations == 10
    assert state.completed is False
    assert state.stop_requested is False
    assert state.paused is False
    assert state.total_plugins == 0
    assert state.completed_plugins == []
    assert state.failed_plugins == []
    assert state.results == []
    assert state.errors == []


def test_scan_state_custom_initialization():
    state = ScanState(target="http://example.com", mode="whitebox", max_iterations=5)
    assert state.target == "http://example.com"
    assert state.mode == "whitebox"
    assert state.max_iterations == 5


def test_status_transitions_complete():
    state = ScanState()
    assert state.completed is False
    state.set_completed()
    assert state.completed is True
    assert state.completed_at is not None


def test_status_transitions_stop_requested():
    state = ScanState()
    assert state.stop_requested is False
    state.request_stop("test reason")
    assert state.stop_requested is True
    assert any("test reason" in e for e in state.errors)


def test_should_stop_conditions():
    state = ScanState(max_iterations=3)
    assert state.should_stop() is False

    state.stop_requested = True
    assert state.should_stop() is True

    state2 = ScanState(max_iterations=3)
    state2.iteration = 3
    assert state2.should_stop() is True

    state3 = ScanState(max_iterations=3)
    state3.set_completed()
    assert state3.should_stop() is True


def test_mark_plugin_complete_and_failed_tracking():
    state = ScanState(total_plugins=3)
    state.mark_plugin_complete("plugin_a")
    state.mark_plugin_complete("plugin_b")
    assert "plugin_a" in state.completed_plugins
    assert "plugin_b" in state.completed_plugins
    assert len(state.completed_plugins) == 2

    # Duplicate should not double-add
    state.mark_plugin_complete("plugin_a")
    assert state.completed_plugins.count("plugin_a") == 1

    state.mark_plugin_failed("plugin_c", "timeout")
    assert "plugin_c" in state.failed_plugins
    assert any("plugin_c" in e for e in state.errors)

    # Duplicate failed should not double-add
    state.mark_plugin_failed("plugin_c", "timeout again")
    assert state.failed_plugins.count("plugin_c") == 1


def test_progress_calculation():
    state = ScanState(total_plugins=4)
    assert state.progress_pct == 0.0

    state.mark_plugin_complete("p1")
    state.mark_plugin_complete("p2")
    assert state.progress_pct == 50.0

    state.mark_plugin_complete("p3")
    state.mark_plugin_complete("p4")
    assert state.progress_pct == 100.0


def test_progress_pct_zero_when_no_plugins():
    state = ScanState(total_plugins=0)
    assert state.progress_pct == 0.0


def test_pause_and_resume():
    state = ScanState()
    state.enter_waiting_state("waiting for user input")
    assert state.paused is True
    assert state.pause_reason == "waiting for user input"

    state.resume()
    assert state.paused is False
    assert state.pause_reason is None

    state.enter_waiting_state()
    state.resume(new_target="http://new.example.com")
    assert state.target == "http://new.example.com"


def test_serialization_and_deserialization():
    state = ScanState(target="http://test.com", mode="blackbox", total_plugins=2)
    state.mark_plugin_complete("alpha")
    state.mark_plugin_failed("beta", "error")
    state.add_results([{"vuln": "xss"}])

    data = state.model_dump()
    restored = ScanState.model_validate(data)

    assert restored.target == state.target
    assert restored.completed_plugins == state.completed_plugins
    assert restored.failed_plugins == state.failed_plugins
    assert restored.results == state.results
    # Internal sets should be rebuilt from lists
    assert "alpha" in restored._completed_set
    assert "beta" in restored._failed_set


def test_get_summary():
    state = ScanState(target="http://example.com", total_plugins=5)
    state.mark_plugin_complete("p1")
    state.mark_plugin_failed("p2", "err")
    summary = state.get_summary()

    assert summary["target"] == "http://example.com"
    assert summary["plugins_completed"] == 1
    assert summary["plugins_failed"] == 1
    assert summary["total_plugins"] == 5
    assert "progress_pct" in summary
