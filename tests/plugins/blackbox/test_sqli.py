# tests/plugins/blackbox/test_sqli.py
import pytest
from vibee_hacker.plugins.blackbox.sqli import SqliPlugin
from vibee_hacker.core.models import Target, Severity


class TestSqli:
    @pytest.fixture
    def plugin(self):
        return SqliPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/search?q=test")

    @pytest.mark.asyncio
    async def test_error_based_detection(self, plugin, target, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/search?q=test",
            text="<html>Normal page</html>",
        )
        httpx_mock.add_response(
            url="https://example.com/search?q=test%27",
            text="You have an error in your SQL syntax near",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_sqli(self, plugin, target, httpx_mock):
        # Return normal page for any payload URL (no SQL errors)
        httpx_mock.add_response(text="<html>Normal page</html>")
        httpx_mock.add_response(text="<html>Normal page</html>")
        httpx_mock.add_response(text="<html>Normal page</html>")
        httpx_mock.add_response(text="<html>Normal page</html>")
        httpx_mock.add_response(text="<html>Normal page</html>")
        httpx_mock.add_response(text="<html>Normal page</html>")
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_params_skip(self, plugin, httpx_mock):
        target = Target(url="https://example.com/")
        results = await plugin.run(target)
        assert len(results) == 0
