# tests/plugins/whitebox/test_dangerous_defaults.py
"""Tests for DangerousDefaultsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.dangerous_defaults import DangerousDefaultsPlugin
from vibee_hacker.core.models import Target, Severity


class TestDangerousDefaults:
    @pytest.fixture
    def plugin(self):
        return DangerousDefaultsPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: DEBUG = True in settings.py
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_debug_true_detected(self, plugin, tmp_path):
        """DEBUG = True is flagged as HIGH severity."""
        (tmp_path / "settings.py").write_text(
            "DEBUG = True\n"
            "ALLOWED_HOSTS = ['localhost']\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "dangerous_default"
        assert r.cwe_id == "CWE-1188"

    # ------------------------------------------------------------------ #
    # Test 2: DEBUG = False — not flagged
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_debug_false_not_flagged(self, plugin, tmp_path):
        """DEBUG = False does not produce a result."""
        (tmp_path / "settings.py").write_text(
            "DEBUG = False\n"
            "ALLOWED_HOSTS = ['example.com']\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: Wildcard ALLOWED_HOSTS
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_wildcard_allowed_hosts(self, plugin, tmp_path):
        (tmp_path / "settings.py").write_text(
            "DEBUG = False\n"
            "ALLOWED_HOSTS = ['*']\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert any("ALLOWED_HOSTS" in r.title or "Wildcard" in r.title for r in results)
