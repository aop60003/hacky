"""Integration tests for crawler→plugin context passing in the ScanEngine."""
from __future__ import annotations

import pytest
from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


class MockCrawlerReader(PluginBase):
    """Plugin that reads crawled URLs from context and returns findings."""
    name = "mock_crawler_reader"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target, context=None):
        results = []
        if context and context.crawl_urls:
            for url in context.crawl_urls:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Found via crawl: {url}",
                    description="Crawled URL processed",
                    endpoint=url,
                ))
        return results


class MockContextInspector(PluginBase):
    """Plugin that stores the context it received for later inspection."""
    name = "mock_context_inspector"
    category = "blackbox"
    phase = 3
    base_severity = Severity.LOW
    received_context: InterPhaseContext | None = None

    async def run(self, target, context=None):
        MockContextInspector.received_context = context
        return []


class TestEngineCrawlerIntegration:
    @pytest.mark.asyncio
    async def test_engine_handles_crawler_failure_gracefully(self):
        """Engine should not raise even when crawler cannot reach the target."""
        engine = ScanEngine(timeout_per_plugin=10, safe_mode=False)
        engine.register_plugin(MockCrawlerReader())

        # Port 19999 is unlikely to have anything listening
        target = Target(url="http://127.0.0.1:19999/nonexistent", mode="blackbox")
        results = await engine.scan(target)
        # Engine must return a list (may be empty or contain plugin errors)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_context_is_populated_and_passed_to_phase3_plugins(self):
        """Plugins in phase 3 must receive an InterPhaseContext object."""
        MockContextInspector.received_context = None

        engine = ScanEngine(timeout_per_plugin=5, safe_mode=False)
        engine.register_plugin(MockContextInspector())

        target = Target(url="http://127.0.0.1:19999/page?id=1", mode="blackbox")
        await engine.scan(target)

        # Context object is always created and passed, even when crawling fails
        assert MockContextInspector.received_context is not None
        assert isinstance(MockContextInspector.received_context, InterPhaseContext)

    @pytest.mark.asyncio
    async def test_whitebox_target_skips_auto_crawl(self):
        """Auto-crawl must NOT run for whitebox targets."""
        MockContextInspector.received_context = None

        engine = ScanEngine(timeout_per_plugin=5, safe_mode=False)
        engine.register_plugin(MockContextInspector())

        # whitebox target: mode is not "blackbox"
        target = Target(path="/some/local/path", mode="whitebox")
        await engine.scan(target)

        # Context should be empty (no crawl_urls populated)
        ctx = MockContextInspector.received_context
        if ctx is not None:
            assert ctx.crawl_urls == []
            assert ctx.crawl_forms == []
            assert ctx.crawl_parameters == {}

    @pytest.mark.asyncio
    async def test_crawl_urls_in_context_come_from_auto_crawl(self, httpx_mock):
        """When crawling succeeds, crawl_urls must be populated in context."""
        base = "https://testsite.example.com"
        # Allow any extra requests the engine or plugins might make
        httpx_mock.add_response(
            url=f"{base}/",
            headers={"content-type": "text/html"},
            text=f'<html><body><a href="{base}/page?q=1">link</a></body></html>',
        )
        httpx_mock.add_response(
            url=f"{base}/page?q=1",
            headers={"content-type": "text/html"},
            text="<html><body>page</body></html>",
        )

        MockContextInspector.received_context = None
        engine = ScanEngine(timeout_per_plugin=15, safe_mode=False)
        engine.register_plugin(MockContextInspector())

        target = Target(url=f"{base}/", mode="blackbox", verify_ssl=False)
        await engine.scan(target)

        ctx = MockContextInspector.received_context
        assert ctx is not None
        assert len(ctx.crawl_urls) >= 1

    @pytest.mark.asyncio
    async def test_injection_plugin_receives_crawled_urls(self, httpx_mock):
        """Injection plugins must be able to see crawled URLs through the context."""
        base = "https://crawltest.example.com"
        httpx_mock.add_response(
            url=f"{base}/",
            headers={"content-type": "text/html"},
            text=f'<html><body><a href="{base}/search?q=test">search</a></body></html>',
        )
        httpx_mock.add_response(
            url=f"{base}/search?q=test",
            headers={"content-type": "text/html"},
            text="<html><body>results</body></html>",
        )

        engine = ScanEngine(timeout_per_plugin=15, safe_mode=False)
        reader = MockCrawlerReader()
        engine.register_plugin(reader)

        target = Target(url=f"{base}/", mode="blackbox", verify_ssl=False)
        results = await engine.scan(target)

        # MockCrawlerReader creates a result for each crawled URL
        crawler_results = [r for r in results if r.plugin_name == "mock_crawler_reader"]
        assert len(crawler_results) >= 1
