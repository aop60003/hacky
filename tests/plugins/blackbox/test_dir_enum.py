# tests/plugins/blackbox/test_dir_enum.py
"""Tests for directory/file enumeration plugin (P2-1)."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.dir_enum import DirEnumPlugin
from vibee_hacker.core.models import Target, Severity


class TestDirEnum:
    @pytest.fixture
    def plugin(self):
        return DirEnumPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_git_config_found(self, plugin, target, httpx_mock):
        """/.git/config returning 200 with substantial content should be CRITICAL."""
        from vibee_hacker.plugins.blackbox.dir_enum import SENSITIVE_PATHS
        # Default all paths to 404
        for path in SENSITIVE_PATHS:
            if path not in ("/.git/config", "/.git/HEAD"):
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=404,
                    text="Not Found",
                )
        # /.git/config returns 200 with real content
        httpx_mock.add_response(
            url="https://example.com/.git/config",
            status_code=200,
            text="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:org/repo.git\n",
        )
        httpx_mock.add_response(
            url="https://example.com/.git/HEAD",
            status_code=404,
            text="Not Found",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL
        assert results[0].rule_id == "dir_enum_sensitive_file"
        assert results[0].cwe_id == "CWE-538"

    @pytest.mark.asyncio
    async def test_all_return_404(self, plugin, target, httpx_mock):
        """All paths returning 404 should produce no results."""
        from vibee_hacker.plugins.blackbox.dir_enum import SENSITIVE_PATHS
        for path in SENSITIVE_PATHS:
            httpx_mock.add_response(
                url=f"https://example.com{path}",
                status_code=404,
                text="Not Found",
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError on first request returns empty list."""
        target = Target(url="https://down.example.com")
        httpx_mock.add_exception(
            httpx.ConnectError("connection refused"), is_reusable=True
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin):
        """Plugin without URL returns empty list."""
        target = Target(path="/some/path", mode="whitebox")
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_small_body_not_reported(self, plugin, target, httpx_mock):
        """200 response with <= 50 bytes should not be reported."""
        from vibee_hacker.plugins.blackbox.dir_enum import SENSITIVE_PATHS
        for path in SENSITIVE_PATHS:
            if path == "/.env":
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=200,
                    text="short",  # well under 50 bytes
                )
            else:
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=404,
                    text="Not Found",
                )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_env_file_severity_is_critical(self, plugin, target, httpx_mock):
        """/.env file found should be CRITICAL severity."""
        from vibee_hacker.plugins.blackbox.dir_enum import SENSITIVE_PATHS
        for path in SENSITIVE_PATHS:
            if path == "/.env":
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=200,
                    text="DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecret123\nAPP_KEY=abcdefghijklmnopqrst\n",
                )
            else:
                httpx_mock.add_response(
                    url=f"https://example.com{path}",
                    status_code=404,
                    text="Not Found",
                )
        results = await plugin.run(target)
        assert len(results) >= 1
        env_result = next(r for r in results if "/.env" in r.endpoint)
        assert env_result.base_severity == Severity.CRITICAL
