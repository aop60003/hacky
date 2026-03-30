"""End-to-end integration test."""

import json
import pytest
from click.testing import CliRunner

from vibee_hacker.cli.main import cli
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target, Result, Severity
from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.plugin_loader import PluginLoader


class IntegrationPlugin(PluginBase):
    name = "integration_test"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target, context=None):
        return [Result(
            plugin_name=self.name,
            base_severity=self.base_severity,
            title="Integration test finding",
            description="This is a test",
            endpoint=target.url or "",
        )]


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_scan_pipeline(self):
        engine = ScanEngine()
        engine.register_plugin(IntegrationPlugin())
        target = Target(url="https://example.com")
        results = await engine.scan(target)
        assert len(results) == 1
        assert results[0].title == "Integration test finding"

    def test_cli_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert "0.1.0" in result.output

    def test_plugin_loader_discovers_nothing_in_empty(self, tmp_path):
        loader = PluginLoader()
        plugins = loader.discover(str(tmp_path))
        assert plugins == []
