# tests/plugins/whitebox/test_py_ssrf_pattern.py
"""Tests for PySsrfPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_ssrf_pattern import PySsrfPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestPySsrfPattern:
    @pytest.fixture
    def plugin(self):
        return PySsrfPatternPlugin()

    @pytest.mark.asyncio
    async def test_requests_get_variable_detected(self, plugin, tmp_path):
        """requests.get(user_url) with variable argument is flagged as CRITICAL."""
        (tmp_path / "app.py").write_text(
            "import requests\n"
            "from flask import request\n"
            "def fetch():\n"
            "    url = request.args.get('url')\n"
            "    resp = requests.get(url)\n"
            "    return resp.text\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "py_ssrf_pattern"
        assert r.cwe_id == "CWE-918"

    @pytest.mark.asyncio
    async def test_requests_get_literal_clean(self, plugin, tmp_path):
        """requests.get with a string literal is not flagged."""
        (tmp_path / "app.py").write_text(
            "import requests\n"
            "resp = requests.get('https://api.example.com/data')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
