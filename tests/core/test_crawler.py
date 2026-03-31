import pytest
import httpx
from vibee_hacker.core.crawler import Crawler, CrawlResult, FormInfo


class TestCrawler:
    @pytest.fixture
    def crawler(self):
        return Crawler(max_depth=2, max_pages=10)

    @pytest.mark.asyncio
    async def test_crawl_discovers_links(self, crawler, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            headers={"content-type": "text/html"},
            text='<html><body><a href="/about">About</a><a href="/contact">Contact</a></body></html>',
        )
        httpx_mock.add_response(
            url="https://example.com/about",
            headers={"content-type": "text/html"},
            text='<html><body>About page</body></html>',
        )
        httpx_mock.add_response(
            url="https://example.com/contact",
            headers={"content-type": "text/html"},
            text='<html><body>Contact page</body></html>',
        )
        result = await crawler.crawl("https://example.com/")
        assert len(result.urls) == 3

    @pytest.mark.asyncio
    async def test_crawl_discovers_forms(self, crawler, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            headers={"content-type": "text/html"},
            text='<html><form action="/login" method="POST"><input name="username"><input name="password"></form></html>',
        )
        result = await crawler.crawl("https://example.com/")
        assert len(result.forms) == 1
        assert result.forms[0].action == "https://example.com/login"
        assert result.forms[0].method == "POST"
        assert "username" in result.forms[0].fields

    @pytest.mark.asyncio
    async def test_crawl_discovers_api_from_js(self, crawler, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            headers={"content-type": "text/html"},
            text='<html><script>fetch("/api/users")</script></html>',
        )
        result = await crawler.crawl("https://example.com/")
        assert "https://example.com/api/users" in result.api_endpoints

    @pytest.mark.asyncio
    async def test_crawl_collects_parameters(self, crawler, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/search?q=test&page=1",
            headers={"content-type": "text/html"},
            text='<html><body>Results</body></html>',
        )
        result = await crawler.crawl("https://example.com/search?q=test&page=1")
        assert "q" in result.parameters["https://example.com/search?q=test&page=1"]

    @pytest.mark.asyncio
    async def test_crawl_respects_max_depth(self, httpx_mock):
        crawler = Crawler(max_depth=0, max_pages=10)
        httpx_mock.add_response(
            url="https://example.com/",
            headers={"content-type": "text/html"},
            text='<html><a href="/deep">Deep</a></html>',
        )
        result = await crawler.crawl("https://example.com/")
        assert len(result.urls) == 1  # Only start URL

    @pytest.mark.asyncio
    async def test_crawl_same_domain_only(self, crawler, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com/",
            headers={"content-type": "text/html"},
            text='<html><a href="https://evil.com/steal">Evil</a></html>',
        )
        result = await crawler.crawl("https://example.com/")
        assert all("example.com" in u for u in result.urls)

    @pytest.mark.asyncio
    async def test_crawl_transport_error(self, crawler, httpx_mock):
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        result = await crawler.crawl("https://down.example.com/")
        assert result.urls == []

    @pytest.mark.asyncio
    async def test_empty_crawl_result(self):
        result = CrawlResult()
        assert result.urls == []
        assert result.forms == []
        assert result.parameters == {}
        assert result.api_endpoints == []
