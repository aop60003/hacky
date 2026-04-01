# tests/plugins/whitebox/test_env_file_detector.py
"""Tests for EnvFileDetectorPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.env_file_detector import EnvFileDetectorPlugin
from vibee_hacker.core.models import Target, Severity


class TestEnvFileDetector:
    @pytest.fixture
    def plugin(self):
        return EnvFileDetectorPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: .env with secrets
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_env_with_secrets_detected(self, plugin, tmp_path):
        """A .env file containing secrets is flagged as CRITICAL."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DATABASE_URL=postgres://localhost/db\n"
            "SECRET_KEY=supersecretvalue123\n"
            "API_KEY=sk-live-abcdef1234567890\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "env_file_committed"
        assert r.cwe_id == "CWE-798"
        assert "[REDACTED]" in r.evidence

    # ------------------------------------------------------------------ #
    # Test 2: No .env files
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_env_files_returns_empty(self, plugin, tmp_path):
        """A directory without .env files returns no results."""
        (tmp_path / "main.py").write_text("import os\nkey = os.environ['KEY']\n")
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
    # Bonus: .env.production also flagged
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_env_production_detected(self, plugin, tmp_path):
        env_prod = tmp_path / ".env.production"
        env_prod.write_text("PASSWORD=prod_secret_value\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert ".env.production" in results[0].evidence
