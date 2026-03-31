# tests/plugins/whitebox/test_py_fastapi_check.py
"""Tests for PyFastapiCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.py_fastapi_check import PyFastapiCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestPyFastapiCheck:
    @pytest.fixture
    def plugin(self):
        return PyFastapiCheckPlugin()

    @pytest.mark.asyncio
    async def test_cors_wildcard_detected(self, plugin, tmp_path):
        """CORSMiddleware with allow_origins=['*'] is flagged as HIGH."""
        (tmp_path / "main.py").write_text(
            'from fastapi import FastAPI\n'
            'from fastapi.middleware.cors import CORSMiddleware\n'
            'app = FastAPI()\n'
            'app.add_middleware(\n'
            '    CORSMiddleware,\n'
            '    allow_origins=["*"],\n'
            '    allow_credentials=True,\n'
            ')\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id.startswith("py_fastapi_")
        assert r.cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_secure_config_clean(self, plugin, tmp_path):
        """Secure FastAPI config returns empty."""
        (tmp_path / "main.py").write_text(
            'from fastapi import FastAPI\n'
            'from fastapi.middleware.cors import CORSMiddleware\n'
            'app = FastAPI()\n'
            'app.add_middleware(\n'
            '    CORSMiddleware,\n'
            '    allow_origins=["https://myapp.example.com"],\n'
            ')\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
