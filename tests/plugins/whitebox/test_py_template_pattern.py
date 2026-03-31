# tests/plugins/whitebox/test_py_template_pattern.py
"""Tests for PyTemplatePatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_template_pattern import PyTemplatePatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyTemplatePattern:
    @pytest.fixture
    def plugin(self):
        return PyTemplatePatternPlugin()

    @pytest.mark.asyncio
    async def test_safe_filter_detected(self, plugin, tmp_path):
        """Jinja2 |safe filter usage is flagged as HIGH."""
        (tmp_path / "views.py").write_text(
            'from jinja2 import Environment\n'
            'env = Environment()\n'
            'tmpl = env.from_string("{{ user_input | safe }}")\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "py_template_injection"
        assert r.cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_clean_templates(self, plugin, tmp_path):
        """Clean template code returns empty."""
        (tmp_path / "views.py").write_text(
            'from flask import render_template\n'
            'def index():\n'
            '    return render_template("index.html", name="World")\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
