# tests/plugins/whitebox/test_js_node_check.py
"""Tests for JsNodeCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_node_check import JsNodeCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsNodeCheck:
    @pytest.fixture
    def plugin(self):
        return JsNodeCheckPlugin()

    @pytest.mark.asyncio
    async def test_child_process_exec_detected(self, plugin, tmp_path):
        """child_process.exec with variable is flagged as HIGH."""
        (tmp_path / "server.js").write_text(
            "const { exec } = require('child_process');\n"
            "app.get('/run', (req, res) => {\n"
            "  const cmd = req.query.cmd;\n"
            "  exec(cmd, (err, stdout) => res.send(stdout));\n"
            "});\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id.startswith("js_node_")
        assert r.cwe_id == "CWE-78"

    @pytest.mark.asyncio
    async def test_execfile_clean(self, plugin, tmp_path):
        """execFile usage (safe) returns empty."""
        (tmp_path / "server.js").write_text(
            "const { execFile } = require('child_process');\n"
            "execFile('/usr/bin/ls', ['-la'], (err, stdout) => console.log(stdout));\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
