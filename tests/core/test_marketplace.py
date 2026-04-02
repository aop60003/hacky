"""Tests for Plugin Marketplace."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from vibee_hacker.core.marketplace import Marketplace, PluginInfo


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_plugin(name: str = "test-plugin", category: str = "blackbox", tags: list | None = None) -> PluginInfo:
    return PluginInfo(
        name=name,
        version="1.0.0",
        description=f"A {name} plugin",
        author="tester",
        category=category,
        tags=tags or [],
    )


# ── basic operations ──────────────────────────────────────────────────────────

def test_empty_marketplace():
    m = Marketplace()
    assert m.count == 0
    assert m.list_installed() == []


def test_add_plugin():
    m = Marketplace()
    m.add_to_registry(_make_plugin("sqli-scanner"))
    assert m.count == 1


def test_count_property():
    m = Marketplace()
    m.add_to_registry(_make_plugin("p1"))
    m.add_to_registry(_make_plugin("p2"))
    assert m.count == 2


# ── search ────────────────────────────────────────────────────────────────────

def test_search_by_name():
    m = Marketplace()
    m.add_to_registry(_make_plugin("sqli-scanner"))
    m.add_to_registry(_make_plugin("xss-scanner"))
    results = m.search(query="sqli")
    assert len(results) == 1
    assert results[0].name == "sqli-scanner"


def test_search_by_name_case_insensitive():
    m = Marketplace()
    m.add_to_registry(_make_plugin("SQLI-Scanner"))
    results = m.search(query="sqli")
    assert len(results) == 1


def test_search_by_category():
    m = Marketplace()
    m.add_to_registry(_make_plugin("bb-plugin", category="blackbox"))
    m.add_to_registry(_make_plugin("wb-plugin", category="whitebox"))
    results = m.search(category="whitebox")
    assert len(results) == 1
    assert results[0].name == "wb-plugin"


def test_search_by_tags():
    m = Marketplace()
    m.add_to_registry(_make_plugin("sqli-plugin", tags=["sqli", "injection"]))
    m.add_to_registry(_make_plugin("xss-plugin", tags=["xss", "injection"]))
    m.add_to_registry(_make_plugin("csrf-plugin", tags=["csrf"]))
    results = m.search(tags=["injection"])
    assert len(results) == 2


def test_search_no_filters_returns_all():
    m = Marketplace()
    m.add_to_registry(_make_plugin("a"))
    m.add_to_registry(_make_plugin("b"))
    assert len(m.search()) == 2


# ── install / uninstall ───────────────────────────────────────────────────────

def test_install_plugin():
    m = Marketplace()
    m.add_to_registry(_make_plugin("sqli-scanner"))
    result = m.install("sqli-scanner")
    assert result is True
    assert m.list_installed()[0].name == "sqli-scanner"


def test_install_nonexistent_returns_false():
    m = Marketplace()
    assert m.install("ghost-plugin") is False


def test_uninstall_plugin():
    m = Marketplace()
    m.add_to_registry(_make_plugin("sqli-scanner"))
    m.install("sqli-scanner")
    result = m.uninstall("sqli-scanner")
    assert result is True
    assert m.list_installed() == []


def test_uninstall_nonexistent_returns_false():
    m = Marketplace()
    assert m.uninstall("ghost") is False


def test_list_installed():
    m = Marketplace()
    m.add_to_registry(_make_plugin("p1"))
    m.add_to_registry(_make_plugin("p2"))
    m.add_to_registry(_make_plugin("p3"))
    m.install("p1")
    m.install("p3")
    installed = m.list_installed()
    assert len(installed) == 2
    names = {p.name for p in installed}
    assert names == {"p1", "p3"}


# ── registry file ─────────────────────────────────────────────────────────────

def test_load_registry_file(tmp_path: Path):
    registry = {
        "plugins": [
            {
                "name": "community-sqli",
                "version": "2.0.0",
                "description": "Community SQLi scanner",
                "author": "community",
                "category": "blackbox",
                "tags": ["sqli"],
                "url": "https://github.com/example/community-sqli",
                "installed": False,
                "downloads": 100,
            }
        ]
    }
    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps(registry))

    m = Marketplace(registry_path=registry_file)
    assert m.count == 1
    assert m.search("community-sqli")[0].author == "community"
    assert m.search("community-sqli")[0].downloads == 100
