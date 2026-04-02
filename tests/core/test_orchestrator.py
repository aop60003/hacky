"""Tests for ScanOrchestrator."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vibee_hacker.core.orchestrator import ScanOrchestrator
from vibee_hacker.core.state import ScanState
from vibee_hacker.core.models import Target


def make_mock_loader(plugin_count: int = 2):
    loader = MagicMock()
    loader.plugins = [MagicMock() for _ in range(plugin_count)]
    return loader


def test_orchestrator_default_initialization():
    loader = make_mock_loader(3)
    orch = ScanOrchestrator(loader=loader)
    assert orch._timeout == 60
    assert orch._concurrency == 10
    assert orch._safe_mode is True
    assert orch._tracer is None
    assert isinstance(orch.state, ScanState)


def test_orchestrator_plugin_count():
    loader = make_mock_loader(5)
    orch = ScanOrchestrator(loader=loader)
    assert orch.plugin_count == 5


def test_orchestrator_accepts_external_state():
    loader = make_mock_loader()
    existing_state = ScanState(target="http://preset.com", mode="whitebox")
    orch = ScanOrchestrator(loader=loader, state=existing_state)
    assert orch.state is existing_state
    assert orch.state.target == "http://preset.com"


def test_orchestrator_create_engine():
    loader = make_mock_loader(2)
    orch = ScanOrchestrator(loader=loader)
    engine = orch._create_engine()
    from vibee_hacker.core.engine import ScanEngine
    assert isinstance(engine, ScanEngine)


@pytest.mark.asyncio
async def test_orchestrator_run_updates_state():
    loader = make_mock_loader(0)
    orch = ScanOrchestrator(loader=loader)

    mock_results = []
    with patch.object(orch, '_create_engine') as mock_create:
        mock_engine = MagicMock()
        mock_engine.scan = AsyncMock(return_value=mock_results)
        mock_create.return_value = mock_engine

        target = Target(url="http://example.com", mode="blackbox")
        results = await orch.run(target)

    assert orch.state.completed is True
    assert orch.state.started_at is not None
    assert orch.state.iteration == 1
    assert results == mock_results


def test_get_state_dict():
    loader = make_mock_loader()
    orch = ScanOrchestrator(loader=loader)
    state_dict = orch.get_state_dict()
    assert "scan_id" in state_dict
    assert "target" in state_dict
    assert "mode" in state_dict


def test_from_state_dict_restores_orchestrator():
    loader = make_mock_loader()
    orch = ScanOrchestrator(loader=loader)
    orch.state.target = "http://example.com"
    state_dict = orch.get_state_dict()

    with patch('vibee_hacker.core.orchestrator.PluginLoader') as mock_loader_cls:
        mock_loader_instance = MagicMock()
        mock_loader_instance.plugins = []
        mock_loader_cls.return_value = mock_loader_instance
        mock_loader_instance.load_builtin = MagicMock()

        restored = ScanOrchestrator.from_state_dict(state_dict)
        assert restored.state.target == "http://example.com"
