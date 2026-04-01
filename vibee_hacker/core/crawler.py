"""Web crawler for endpoint discovery."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs

import httpx


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[str]


@dataclass
class CrawlResult:
    urls: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    api_endpoints: list[str] = field(default_factory=list)


class _LinkParser(HTMLParser):
    """Extract links, forms, and scripts from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[FormInfo] = []
        self.scripts: list[str] = []
        self._current_form: dict | None = None
        self._current_fields: list[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
            }
            self._current_fields = []
        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_fields.append(name)
        elif tag == "script" and "src" in attr_dict:
            self.scripts.append(attr_dict["src"])

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(FormInfo(
                action=self._current_form["action"],
                method=self._current_form["method"],
                fields=self._current_fields,
            ))
            self._current_form = None


# Regex for API endpoints in JavaScript
JS_API_PATTERN = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|delete)|\.ajax)\s*\(\s*['"](/[a-zA-Z0-9/_-]+)['"]''',
    re.I,
)


class Crawler:
    """Async web crawler for endpoint discovery."""

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: int = 10,
        verify_ssl: bool = True,
        auth_headers: dict[str, str] | None = None,
    ):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auth_headers = auth_headers

    async def crawl(self, start_url: str, auth_headers: dict[str, str] | None = None) -> CrawlResult:
        result = CrawlResult()
        visited: set[str] = set()
        base_domain = urlparse(start_url).netloc
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])

        # Merge instance-level auth_headers with any passed per-call headers
        effective_headers: dict[str, str] = {}
        if self.auth_headers:
            effective_headers.update(self.auth_headers)
        if auth_headers:
            effective_headers.update(auth_headers)

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
            while queue and len(visited) < self.max_pages:
                url, depth = queue.popleft()

                if url in visited or depth > self.max_depth:
                    continue
                visited.add(url)

                try:
                    headers = effective_headers or {}
                    resp = await client.get(url, headers=headers)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(resp.text) > 2_000_000:
                    continue

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                result.urls.append(url)

                # Collect query parameters
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if params:
                    result.parameters[url] = list(params.keys())

                # Parse HTML
                parser = _LinkParser()
                try:
                    parser.feed(resp.text)
                except Exception:
                    continue

                # Collect forms
                for form in parser.forms:
                    abs_action = urljoin(url, form.action) if form.action else url
                    result.forms.append(FormInfo(
                        action=abs_action,
                        method=form.method,
                        fields=form.fields,
                    ))

                # Extract API endpoints from inline JS
                for match in JS_API_PATTERN.finditer(resp.text):
                    api_path = match.group(1)
                    abs_api = urljoin(url, api_path)
                    if abs_api not in result.api_endpoints:
                        result.api_endpoints.append(abs_api)

                # Follow links (same domain only)
                if depth < self.max_depth:
                    for link in parser.links:
                        abs_link = urljoin(url, link)
                        link_domain = urlparse(abs_link).netloc
                        if link_domain == base_domain and abs_link not in visited:
                            queue.append((abs_link, depth + 1))

        return result
