# tests/plugins/whitebox/test_insecure_crypto.py
"""Tests for InsecureCryptoPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.insecure_crypto import InsecureCryptoPlugin
from vibee_hacker.core.models import Target, Severity


class TestInsecureCrypto:
    @pytest.fixture
    def plugin(self):
        return InsecureCryptoPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: md5 for password
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_md5_detected(self, plugin, tmp_path):
        """hashlib.md5() in source code is flagged as HIGH."""
        (tmp_path / "auth.py").write_text(
            "import hashlib\n"
            "def hash_password(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "insecure_crypto"
        assert r.cwe_id == "CWE-327"

    # ------------------------------------------------------------------ #
    # Test 2: Secure crypto only — no results
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_crypto_not_flagged(self, plugin, tmp_path):
        """bcrypt and secrets usage is not flagged."""
        (tmp_path / "auth.py").write_text(
            "import bcrypt\nimport secrets\n"
            "def hash_password(pw):\n"
            "    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())\n"
            "token = secrets.token_hex(32)\n"
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
    # Bonus: SHA-1 detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_sha1_detected(self, plugin, tmp_path):
        (tmp_path / "utils.py").write_text(
            "import hashlib\n"
            "digest = hashlib.sha1(data).hexdigest()\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "insecure_crypto"
