# tests/plugins/whitebox/test_yaml_deserialize.py
"""Tests for YamlDeserializePlugin."""
import pytest
from vibee_hacker.plugins.whitebox.yaml_deserialize import YamlDeserializePlugin
from vibee_hacker.core.models import Target, Severity


class TestYamlDeserialize:
    @pytest.fixture
    def plugin(self):
        return YamlDeserializePlugin()

    @pytest.mark.asyncio
    async def test_python_yaml_load_detected(self, plugin, tmp_path):
        """yaml.load() without SafeLoader in Python file is flagged."""
        (tmp_path / "loader.py").write_text(
            'import yaml\n'
            'def parse_config(data):\n'
            '    return yaml.load(data)\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "yaml_unsafe_load"
        assert r.cwe_id == "CWE-502"
        assert r.base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_python_safe_load_no_finding(self, plugin, tmp_path):
        """yaml.safe_load() in Python produces no findings."""
        (tmp_path / "safe_loader.py").write_text(
            'import yaml\n'
            'def parse_config(data):\n'
            '    return yaml.safe_load(data)\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_ruby_yaml_load_detected(self, plugin, tmp_path):
        """YAML.load() in Ruby file is flagged."""
        (tmp_path / "parser.rb").write_text(
            'require "yaml"\n'
            'def parse_config(data)\n'
            '  YAML.load(data)\n'
            'end\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "yaml_unsafe_load"
        assert r.cwe_id == "CWE-502"

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Plugin returns empty list when no path is provided."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
