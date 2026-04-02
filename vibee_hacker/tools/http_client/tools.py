"""HTTP client tool: send arbitrary HTTP requests.

Enables the agent to craft custom HTTP requests for:
- Manual parameter testing with custom payloads
- Header manipulation (Host header injection, CORS testing)
- Authentication flow testing (token replay, session fixation)
- API endpoint probing with specific methods/bodies
- Response analysis (headers, body, timing)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from vibee_hacker.tools.registry import register_tool

logger = logging.getLogger(__name__)

MAX_RESPONSE_BODY = 20_000  # chars


@register_tool(
    description="Send an HTTP request with full control over method, headers, "
    "body, and params. Returns status, headers, body, and timing.",
    requires_network=True,
)
async def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """Send an HTTP request and return full response details.

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
        headers: Custom headers dict.
        body: Request body string (for POST/PUT/PATCH).
        params: URL query parameters dict.
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow redirects.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Dict with status_code, headers, body, elapsed_ms, final_url.
    """
    import httpx

    logger.info("HTTP %s %s", method, url[:200])

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout,
        ) as client:
            resp = await client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                content=body,
                params=params,
            )

        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        resp_headers = dict(resp.headers)
        resp_body = resp.text[:MAX_RESPONSE_BODY]

        return {
            "status_code": resp.status_code,
            "headers": resp_headers,
            "body": resp_body,
            "body_length": len(resp.text),
            "elapsed_ms": elapsed_ms,
            "final_url": str(resp.url),
        }

    except httpx.TimeoutException:
        return {"error": f"Request timed out after {timeout}s", "elapsed_ms": timeout * 1000}
    except Exception as e:
        return {"error": str(e)}


@register_tool(
    description="Send multiple HTTP requests in sequence and compare responses. "
    "Useful for A/B testing payloads, timing attacks, and race conditions.",
    requires_network=True,
)
async def http_request_batch(
    requests: List[Dict[str, Any]],
    delay_ms: int = 0,
) -> List[Dict[str, Any]]:
    """Send multiple HTTP requests and return all responses.

    Args:
        requests: List of request dicts, each with url, method, headers, body, params.
        delay_ms: Delay between requests in milliseconds.

    Returns:
        List of response dicts in same order.
    """
    import asyncio

    results = []
    for i, req in enumerate(requests):
        if i > 0 and delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000)

        result = await http_request(
            url=req.get("url", ""),
            method=req.get("method", "GET"),
            headers=req.get("headers"),
            body=req.get("body"),
            params=req.get("params"),
            timeout=req.get("timeout", 30),
            follow_redirects=req.get("follow_redirects", True),
            verify_ssl=req.get("verify_ssl", True),
        )
        results.append(result)

    return results
