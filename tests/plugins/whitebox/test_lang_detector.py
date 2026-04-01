# tests/plugins/whitebox/test_lang_detector.py
"""Tests for LangDetectorPlugin."""
import pytest
from pathlib import Path

from vibee_hacker.plugins.whitebox.lang_detector import LangDetectorPlugin
from vibee_hacker.core.models import Target, Severity


class TestLangDetector:
    @pytest.fixture
    def plugin(self):
        return LangDetectorPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Python + Flask project
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_python_flask_detected(self, plugin, tmp_path):
        """A directory with .py files and flask import is detected."""
        (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
        (tmp_path / "utils.py").write_text("def helper(): pass\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        r = results[0]
        assert r.base_severity == Severity.INFO
        assert r.rule_id == "lang_detected"
        assert "Python" in r.evidence
        assert "Flask" in r.evidence

    # ------------------------------------------------------------------ #
    # Test 2: Empty directory
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_empty_directory_returns_empty(self, plugin, tmp_path):
        """An empty directory returns no results."""
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Target with no path returns no results."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: Django detected from manage.py
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_django_detected(self, plugin, tmp_path):
        (tmp_path / "manage.py").write_text("#!/usr/bin/env python\n")
        (tmp_path / "views.py").write_text("# django view\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) == 1
        assert "Django" in results[0].evidence
