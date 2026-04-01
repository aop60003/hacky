"""Headless browser crawler using Playwright for SPA support."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from vibee_hacker.core.crawler import CrawlResult, FormInfo


class HeadlessCrawler:
    """Crawls SPAs using Playwright's headless Chromium."""

    def __init__(
        self,
        max_pages: int = 30,
        max_depth: int = 2,
        timeout: int = 10000,  # ms
        auth_headers: dict[str, str] | None = None,
        verify_ssl: bool = True,
    ):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.auth_headers = auth_headers or {}
        self.verify_ssl = verify_ssl

    async def crawl(self, start_url: str) -> CrawlResult:
        """Crawl using headless Chromium. Returns CrawlResult."""
        from playwright.async_api import async_playwright

        result = CrawlResult()
        visited: set[str] = set()
        base_domain = urlparse(start_url).netloc
        queue: list[tuple[str, int]] = [(start_url, 0)]

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    extra_http_headers=self.auth_headers,
                    ignore_https_errors=not self.verify_ssl,
                )
                page = await context.new_page()

                # Intercept XHR/fetch to capture API endpoints
                api_endpoints: list[str] = []
                page.on(
                    "request",
                    lambda req: api_endpoints.append(req.url)
                    if req.resource_type in ("xhr", "fetch")
                    else None,
                )

                while queue and len(visited) < self.max_pages:
                    url, depth = queue.pop(0)
                    if url in visited or depth > self.max_depth:
                        continue
                    visited.add(url)

                    try:
                        await page.goto(
                            url, wait_until="networkidle", timeout=self.timeout
                        )
                        await page.wait_for_timeout(1000)  # Extra wait for JS
                    except Exception:
                        continue

                    result.urls.append(url)

                    # Extract rendered links
                    links = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )

                    # Extract forms
                    forms_data = await page.eval_on_selector_all(
                        "form",
                        """forms => forms.map(f => ({
                            action: f.action,
                            method: (f.method || 'GET').toUpperCase(),
                            fields: [...f.querySelectorAll('input,textarea,select')]
                                .map(i => i.name).filter(n => n)
                        }))""",
                    )
                    for fd in forms_data:
                        result.forms.append(
                            FormInfo(
                                action=fd["action"],
                                method=fd["method"],
                                fields=fd["fields"],
                            )
                        )

                    # Follow same-domain links
                    if depth < self.max_depth:
                        for link in links:
                            link_domain = urlparse(link).netloc
                            if link_domain == base_domain and link not in visited:
                                queue.append((link, depth + 1))

                # Add intercepted API endpoints
                for api_url in api_endpoints:
                    api_domain = urlparse(api_url).netloc
                    if api_domain == base_domain and api_url not in result.api_endpoints:
                        result.api_endpoints.append(api_url)

                await browser.close()

        except Exception:
            # Playwright not available or browser launch failed — return empty result
            pass

        return result
