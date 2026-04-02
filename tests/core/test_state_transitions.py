"""Tests for ScanState transition validation."""
from __future__ import annotations

import pytest

from vibee_hacker.core.state import ScanState


@pytest.fixture
def state():
    return ScanState()


def test_idle_to_running(state):
    state.set_status("running")
    assert state.status == "running"


def test_running_to_completed(state):
    state.set_status("running")
    state.set_status("completed")
    assert state.status == "completed"


def test_running_to_failed(state):
    state.set_status("running")
    state.set_status("failed")
    assert state.status == "failed"


def test_running_to_paused(state):
    state.set_status("running")
    state.set_status("paused")
    assert state.status == "paused"


def test_paused_to_running(state):
    state.set_status("running")
    state.set_status("paused")
    state.set_status("running")
    assert state.status == "running"


def test_invalid_idle_to_completed(state):
    with pytest.raises(ValueError, match="Invalid transition"):
        state.set_status("completed")


def test_invalid_completed_to_running(state):
    state.set_status("running")
    state.set_status("completed")
    with pytest.raises(ValueError, match="Invalid transition"):
        state.set_status("running")


def test_get_state_diagram():
    diagram = ScanState.get_state_diagram()
    assert "idle" in diagram
    assert "running" in diagram
    assert "completed" in diagram
    assert "failed" in diagram
    assert "paused" in diagram
