"""Request Repeater: send custom HTTP requests and inspect responses."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


@dataclass
class RepeaterRequest:
    """A repeater request definition."""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class RepeaterResponse:
    """A repeater response capture."""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    content_length: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RepeaterHistoryEntry:
    """A single request-response pair in history."""
    request: RepeaterRequest
    response: RepeaterResponse
    label: str = ""


class Repeater:
    """Send custom HTTP requests and track history."""

    def __init__(self, verify_ssl: bool = True, proxy: str | None = None, timeout: int = 10):
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.timeout = timeout
        self.history: list[RepeaterHistoryEntry] = []

    async def send(self, request: RepeaterRequest, label: str = "") -> RepeaterResponse:
        """Send a request and return the response."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            proxy=self.proxy,
            timeout=self.timeout,
            follow_redirects=False,
        ) as client:
            try:
                resp = await client.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    content=request.body if request.body else None,
                    cookies=request.cookies,
                )

                response = RepeaterResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text[:100000],  # Limit to 100KB
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    content_length=len(resp.content),
                )
            except httpx.TransportError as e:
                response = RepeaterResponse(body=f"Error: {e}")

        entry = RepeaterHistoryEntry(request=request, response=response, label=label)
        self.history.append(entry)
        return response

    def get_history(self, limit: int = 50) -> list[RepeaterHistoryEntry]:
        """Get recent history entries."""
        return self.history[-limit:]

    def clear_history(self):
        """Clear all history."""
        self.history.clear()

    def diff_responses(self, idx1: int, idx2: int) -> dict:
        """Compare two responses from history."""
        if idx1 >= len(self.history) or idx2 >= len(self.history):
            return {"error": "Index out of range"}

        r1 = self.history[idx1].response
        r2 = self.history[idx2].response

        return {
            "status_diff": r1.status_code != r2.status_code,
            "status": (r1.status_code, r2.status_code),
            "length_diff": abs(r1.content_length - r2.content_length),
            "lengths": (r1.content_length, r2.content_length),
            "time_diff_ms": abs(r1.elapsed_ms - r2.elapsed_ms),
            "header_diff": {
                k: (r1.headers.get(k), r2.headers.get(k))
                for k in set(r1.headers) | set(r2.headers)
                if r1.headers.get(k) != r2.headers.get(k)
            },
        }
