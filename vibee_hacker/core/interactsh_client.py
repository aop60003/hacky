"""Interactsh client for external out-of-band detection."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)


@dataclass
class InteractshEvent:
    """A callback event received from Interactsh server."""
    unique_id: str
    full_id: str
    raw_request: str
    remote_address: str
    timestamp: datetime
    protocol: str  # http, dns, smtp, etc.


class InteractshClient:
    """Client for the Interactsh OOB callback service."""

    DEFAULT_SERVER = "oast.pro"

    def __init__(self, server: str | None = None, token: str | None = None):
        self.server = server or self.DEFAULT_SERVER
        self.token = token
        self._correlation_id = secrets.token_hex(10)
        self._registered = False
        self._interactions: list[InteractshEvent] = []

    @property
    def base_domain(self) -> str:
        """Get the base OOB domain for payloads."""
        return f"{self._correlation_id}.{self.server}"

    def generate_payload(self, tag: str = "") -> str:
        """Generate a unique subdomain payload for blind detection."""
        unique = secrets.token_hex(4)
        if tag:
            return f"{unique}-{tag}.{self.base_domain}"
        return f"{unique}.{self.base_domain}"

    def generate_url(self, tag: str = "", protocol: str = "https") -> str:
        """Generate a full URL payload."""
        subdomain = self.generate_payload(tag)
        return f"{protocol}://{subdomain}"

    async def register(self) -> bool:
        """Register with the Interactsh server."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://{self.server}/register",
                    params={"correlationId": self._correlation_id},
                )
                if resp.status_code == 200:
                    self._registered = True
                    return True
        except Exception as e:
            logger.warning("Interactsh registration failed: %s", e)
        return False

    async def poll(self) -> list[InteractshEvent]:
        """Poll for new interactions."""
        if not self._registered:
            return []

        events = []
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://{self.server}/poll",
                    params={"correlationId": self._correlation_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        event = InteractshEvent(
                            unique_id=item.get("unique-id", ""),
                            full_id=item.get("full-id", ""),
                            raw_request=item.get("raw-request", ""),
                            remote_address=item.get("remote-address", ""),
                            timestamp=datetime.now(timezone.utc),
                            protocol=item.get("protocol", ""),
                        )
                        events.append(event)
                        self._interactions.append(event)
        except Exception as e:
            logger.debug("Interactsh poll failed: %s", e)

        return events

    async def deregister(self) -> bool:
        """Deregister from the Interactsh server."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"https://{self.server}/deregister",
                    params={"correlationId": self._correlation_id},
                )
                self._registered = False
                return resp.status_code == 200
        except Exception:
            return False

    @property
    def has_interactions(self) -> bool:
        return len(self._interactions) > 0

    def find_by_tag(self, tag: str) -> list[InteractshEvent]:
        """Find interactions matching a specific tag."""
        return [e for e in self._interactions if tag in (e.unique_id or "") or tag in (e.full_id or "")]
