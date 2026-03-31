# tests/plugins/blackbox/test_content_type_confusion.py
"""Tests for content-type confusion / validation bypass detection plugin."""
import pytest
import httpx
from vibee_hacker.plugins.blackbox.content_type_confusion import ContentTypeConfusionPlugin
from vibee_hacker.core.models import Target, Severity


class TestContentTypeConfusion:
    @pytest.fixture
    def plugin(self):
        return ContentTypeConfusionPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/data")

    @pytest.mark.asyncio
    async def test_server_accepts_wrong_content_type(self, plugin, target, httpx_mock):
        """Server returns 200 for wrong content-type request — reported as HIGH."""
        # Baseline POST with correct content-type
        httpx_mock.add_response(
            url="https://example.com/api/data",
            status_code=200,
            text='{"result": "ok"}',
        )
        # application/xml content-type accepted
        httpx_mock.add_response(
            url="https://example.com/api/data",
            status_code=200,
            text='{"result": "ok"}',
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].base_severity == Severity.HIGH
        assert results[0].rule_id == "content_type_not_validated"
        assert results[0].cwe_id == "CWE-436"

    @pytest.mark.asyncio
    async def test_server_rejects_wrong_content_type(self, plugin, target, httpx_mock):
        """Server rejects all wrong content-type requests (415) — no results."""
        # Baseline POST
        httpx_mock.add_response(
            url="https://example.com/api/data",
            status_code=200,
            text='{"result": "ok"}',
        )
        # All wrong content-type requests get 415
        for _ in range(3):
            httpx_mock.add_response(
                url="https://example.com/api/data",
                status_code=415,
                text="Unsupported Media Type",
            )
        results = await plugin.run(target)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError returns empty list."""
        target = Target(url="https://down.example.com/api/data")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []
