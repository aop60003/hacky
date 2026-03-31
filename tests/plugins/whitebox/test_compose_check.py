# tests/plugins/whitebox/test_compose_check.py
"""Tests for ComposeCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.compose_check import ComposeCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestComposeCheck:
    @pytest.fixture
    def plugin(self):
        return ComposeCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Privileged + docker.sock mount detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_privileged_and_sock_detected(self, plugin, tmp_path):
        """privileged: true and /var/run/docker.sock mounts are flagged."""
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\n"
            "services:\n"
            "  app:\n"
            "    image: myapp\n"
            "    privileged: true\n"
            "    ports:\n"
            "      - '0.0.0.0:8080:8080'\n"
            "    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
            "      - /etc:/etc\n"
            "    environment:\n"
            "      - DB_PASSWORD=supersecret123\n"
            "      - API_SECRET=my_secret_key\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("compose_" in rid for rid in rule_ids)
        assert any("compose_privileged" in rid for rid in rule_ids)
        assert any("compose_sensitive_mount" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-250"

    # ------------------------------------------------------------------ #
    # Test 2: Secure compose — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_compose_no_findings(self, plugin, tmp_path):
        """A hardened docker-compose.yml produces no results."""
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\n"
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    ports:\n"
            "      - '127.0.0.1:8080:8080'\n"
            "    volumes:\n"
            "      - ./data:/app/data\n"
            "    environment:\n"
            "      - APP_ENV=production\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No compose files — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_compose_files_returns_empty(self, plugin, tmp_path):
        """Directories without docker-compose files produce no results."""
        (tmp_path / "app.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
