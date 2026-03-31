# tests/plugins/whitebox/test_wb_race_condition.py
"""Tests for WbRaceConditionPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.wb_race_condition import WbRaceConditionPlugin
from vibee_hacker.core.models import Target, Severity


class TestWbRaceCondition:
    @pytest.fixture
    def plugin(self):
        return WbRaceConditionPlugin()

    @pytest.mark.asyncio
    async def test_toctou_detected(self, plugin, tmp_path):
        """os.path.exists() followed by open() (TOCTOU) is flagged."""
        (tmp_path / "file_handler.py").write_text(
            "import os\n"
            "def write_file(path, data):\n"
            "    if os.path.exists(path):\n"
            "        with open(path, 'w') as f:\n"
            "            f.write(data)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.MEDIUM
        assert r.rule_id == "wb_race_condition"
        assert r.cwe_id == "CWE-362"

    @pytest.mark.asyncio
    async def test_safe_file_handling_clean(self, plugin, tmp_path):
        """Safe file handling without TOCTOU returns empty."""
        (tmp_path / "file_handler.py").write_text(
            "import os\n"
            "def write_file(path, data):\n"
            "    with open(path, 'w') as f:\n"
            "        f.write(data)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
