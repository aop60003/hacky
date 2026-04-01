# tests/plugins/whitebox/test_insecure_jwt.py
"""Tests for InsecureJwtPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.insecure_jwt import InsecureJwtPlugin
from vibee_hacker.core.models import Target, Severity


class TestInsecureJwt:
    @pytest.fixture
    def plugin(self):
        return InsecureJwtPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: verify=False in code
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_verify_false_detected(self, plugin, tmp_path):
        """jwt.decode with verify=False is flagged as CRITICAL."""
        (tmp_path / "auth.py").write_text(
            "import jwt\n"
            "payload = jwt.decode(token, verify=False)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "insecure_jwt"
        assert r.cwe_id == "CWE-347"

    # ------------------------------------------------------------------ #
    # Test 2: Proper verification — not flagged
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_proper_verification_not_flagged(self, plugin, tmp_path):
        """Proper jwt.decode with algorithms and secret is not flagged."""
        (tmp_path / "auth.py").write_text(
            "import jwt\n"
            "import os\n"
            "SECRET = os.environ['JWT_SECRET']\n"
            "payload = jwt.decode(token, SECRET, algorithms=['HS256'])\n"
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
    # Bonus: 'none' algorithm detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_none_algorithm_detected(self, plugin, tmp_path):
        (tmp_path / "auth.py").write_text(
            "import jwt\n"
            "token = jwt.encode(payload, '', algorithms=['none'])\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "insecure_jwt"
