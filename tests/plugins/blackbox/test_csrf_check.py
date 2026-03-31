# tests/plugins/blackbox/test_csrf_check.py
"""Tests for CSRF token check plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.csrf_check import CsrfCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestCsrfCheck:
    @pytest.fixture
    def plugin(self):
        return CsrfCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com")

    @pytest.mark.asyncio
    async def test_form_without_csrf_token_reported(self, plugin, target, httpx_mock):
        """Form with no CSRF token hidden input triggers csrf_token_missing finding."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="""<html><body>
                <form method="post" action="/transfer">
                    <input type="text" name="amount" />
                    <input type="submit" value="Transfer" />
                </form>
            </body></html>""",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "csrf_token_missing"
        assert results[0].base_severity == Severity.MEDIUM
        assert results[0].cwe_id == "CWE-352"

    @pytest.mark.asyncio
    async def test_form_with_csrf_token_no_finding(self, plugin, target, httpx_mock):
        """Form containing a CSRF hidden input yields no findings."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="""<html><body>
                <form method="post" action="/transfer">
                    <input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz" />
                    <input type="text" name="amount" />
                    <input type="submit" value="Transfer" />
                </form>
            </body></html>""",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_forms_found_no_finding(self, plugin, target, httpx_mock):
        """Page with no forms yields no results."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="<html><body><p>No forms here</p></body></html>",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_url_returns_empty(self, plugin, httpx_mock):
        """No URL returns empty."""
        target = Target(url=None)
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, target, httpx_mock):
        """Transport error returns empty results gracefully."""
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_form_with_csrf_named_token_no_finding(self, plugin, target, httpx_mock):
        """Form with _token hidden input (Laravel style) yields no findings."""
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            text="""<html><body>
                <form method="post" action="/submit">
                    <input type="hidden" name="_token" value="secret123" />
                    <input type="submit" value="Submit" />
                </form>
            </body></html>""",
        )
        results = await plugin.run(target)
        assert results == []
