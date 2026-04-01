# tests/plugins/whitebox/test_hardcoded_secrets.py
"""Tests for HardcodedSecretsPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.hardcoded_secrets import HardcodedSecretsPlugin
from vibee_hacker.core.models import Target, Severity


class TestHardcodedSecrets:
    @pytest.fixture
    def plugin(self):
        return HardcodedSecretsPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: AWS key in code
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_aws_key_detected(self, plugin, tmp_path):
        """A hardcoded AWS access key is flagged as CRITICAL."""
        (tmp_path / "config.py").write_text(
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "region = 'us-east-1'\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "hardcoded_secret"
        assert r.cwe_id == "CWE-798"

    # ------------------------------------------------------------------ #
    # Test 2: Clean code returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_clean_code_returns_empty(self, plugin, tmp_path):
        """Source code using environment variables is not flagged."""
        (tmp_path / "config.py").write_text(
            "import os\n"
            "AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')\n"
            "password = os.getenv('DB_PASSWORD')\n"
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
    # Bonus: Private key in code
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_private_key_detected(self, plugin, tmp_path):
        (tmp_path / "keys.py").write_text(
            'PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"""\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "hardcoded_secret"
