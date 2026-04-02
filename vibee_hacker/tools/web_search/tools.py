"""Web search tool for security research.

Searches the internet for CVEs, PoCs, exploit techniques, and
security documentation. Uses DuckDuckGo (no API key needed) as
default, with optional Perplexity API for richer results.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)


@register_tool(
    description="Search the web for CVEs, exploits, security techniques, "
    "and documentation. Returns top results with snippets.",
    requires_network=True,
)
async def web_search(
    query: str,
    max_results: int = 5,
) -> Dict[str, Any]:
    """Search the web for security-relevant information.

    Args:
        query: Search query (e.g., "CVE-2024-1234 PoC", "nginx SSRF bypass").
        max_results: Number of results to return.

    Returns:
        Dict with results list containing title, url, snippet.
    """
    if not query.strip():
        return {"error": "Empty query"}

    # Try Perplexity API first if configured
    from vibee_hacker.config import Config
    perplexity_key = Config.get("vibee_perplexity_api_key")

    if perplexity_key:
        return await _search_perplexity(query, max_results, perplexity_key)

    # Fallback to DuckDuckGo (no API key needed)
    return await _search_duckduckgo(query, max_results)


async def _search_perplexity(
    query: str, max_results: int, api_key: str
) -> Dict[str, Any]:
    """Search using Perplexity API (better quality, security-focused)."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.perplexity.ai/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "sonar",
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity research assistant. "
                                "Provide technical, actionable information about "
                                "vulnerabilities, exploits, and security tools. "
                                "Include CVE IDs, CVSS scores, and PoC references."
                            ),
                        },
                        {"role": "user", "content": query},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return {
                "source": "perplexity",
                "query": query,
                "answer": content[:5000],
                "citations": data.get("citations", []),
            }
    except Exception as e:
        logger.warning("Perplexity search failed, falling back to DuckDuckGo: %s", e)
        return await _search_duckduckgo(query, max_results)


async def _search_duckduckgo(
    query: str, max_results: int
) -> Dict[str, Any]:
    """Search using DuckDuckGo HTML (no API key needed)."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0"},
            )
            resp.raise_for_status()

            # Parse results from HTML
            results = _parse_ddg_html(resp.text, max_results)
            return {
                "source": "duckduckgo",
                "query": query,
                "results": results,
                "count": len(results),
            }
    except Exception as e:
        return {"error": f"Search failed: {e}"}


def _parse_ddg_html(html: str, max_results: int) -> List[Dict[str, str]]:
    """Parse DuckDuckGo HTML results page."""
    import re

    results = []
    # Find result blocks
    for match in re.finditer(
        r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?'
        r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
        html,
        re.DOTALL,
    ):
        if len(results) >= max_results:
            break
        url = match.group(1)
        title = re.sub(r'<[^>]+>', '', match.group(2)).strip()
        snippet = re.sub(r'<[^>]+>', '', match.group(3)).strip()

        # DuckDuckGo wraps URLs in a redirect
        if "uddg=" in url:
            from urllib.parse import unquote, parse_qs, urlparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            url = unquote(qs.get("uddg", [url])[0])

        if title and url:
            results.append({"title": title, "url": url, "snippet": snippet})

    return results
