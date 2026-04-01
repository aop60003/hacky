"""Tests for headless browser crawler (Playwright-based)."""
import asyncio
import pytest
from vibee_hacker.core.headless_crawler import HeadlessCrawler
from vibee_hacker.core.crawler import CrawlResult


class TestHeadlessCrawler:
    def test_init_defaults(self):
        c = HeadlessCrawler()
        assert c.max_pages == 30
        assert c.max_depth == 2
        assert c.timeout == 10000

    def test_init_custom(self):
        c = HeadlessCrawler(
            max_pages=10,
            max_depth=1,
            auth_headers={"Authorization": "Bearer tok"},
        )
        assert c.max_pages == 10
        assert c.max_depth == 1
        assert c.auth_headers["Authorization"] == "Bearer tok"

    def test_init_timeout_custom(self):
        c = HeadlessCrawler(timeout=5000)
        assert c.timeout == 5000

    def test_auth_headers_default_empty(self):
        c = HeadlessCrawler()
        assert c.auth_headers == {}

    def test_crawl_result_type(self):
        """crawl() must return CrawlResult even on connection failure."""
        c = HeadlessCrawler(timeout=1000)
        result = asyncio.run(c.crawl("http://127.0.0.1:19998/nonexistent"))
        assert isinstance(result, CrawlResult)

    def test_crawl_returns_empty_on_failure(self):
        """crawl() should return empty lists on failure, not raise."""
        c = HeadlessCrawler(timeout=1000)
        result = asyncio.run(c.crawl("http://127.0.0.1:19998/nonexistent"))
        # Should not crash — all list fields present
        assert hasattr(result, "urls")
        assert hasattr(result, "forms")
        assert hasattr(result, "api_endpoints")

    def test_crawl_result_has_all_fields(self):
        """CrawlResult has urls, forms, api_endpoints fields."""
        result = CrawlResult()
        assert isinstance(result.urls, list)
        assert isinstance(result.forms, list)
        assert isinstance(result.api_endpoints, list)
