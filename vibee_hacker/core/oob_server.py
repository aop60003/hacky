"""Out-of-Band callback server for blind vulnerability detection."""

from __future__ import annotations

import asyncio
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class OOBCallback:
    """Represents a received OOB callback."""
    token: str
    source_ip: str
    path: str
    method: str
    headers: dict[str, str]
    body: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class OOBServer:
    """Simple HTTP server that captures out-of-band callbacks."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.callbacks: list[OOBCallback] = []
        self._tokens: dict[str, dict] = {}  # token -> {plugin, payload_info}
        self._server = None
        self._running = False

    def generate_token(self, plugin_name: str, payload_info: str = "") -> str:
        """Generate unique token for a blind payload."""
        token = uuid.uuid4().hex[:16]
        self._tokens[token] = {"plugin": plugin_name, "info": payload_info}
        return token

    def get_callback_url(self, token: str) -> str:
        """Get the URL to embed in blind payloads."""
        return f"http://{self.host}:{self.port}/cb/{token}"

    def check_token(self, token: str) -> OOBCallback | None:
        """Check if a token has received a callback."""
        for cb in self.callbacks:
            if token in cb.path:
                return cb
        return None

    async def start(self):
        """Start the OOB HTTP server."""
        self._running = True
        server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        self._server = server
        logger.info("OOB server listening on %s:%d", self.host, self.port)
        return server

    async def stop(self):
        """Stop the OOB server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader, writer):
        """Handle incoming HTTP connections."""
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=5)
            text = data.decode("utf-8", errors="ignore")

            # Parse basic HTTP request
            lines = text.split("\r\n")
            if not lines:
                return

            request_line = lines[0]
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse headers
            headers = {}
            body = ""
            header_done = False
            for line in lines[1:]:
                if line == "":
                    header_done = True
                    continue
                if header_done:
                    body += line
                elif ": " in line:
                    key, val = line.split(": ", 1)
                    headers[key] = val

            # Get client IP
            peername = writer.get_extra_info("peername")
            source_ip = peername[0] if peername else "unknown"

            # Store callback
            callback = OOBCallback(
                token=path.split("/")[-1] if "/" in path else "",
                source_ip=source_ip,
                path=path,
                method=method,
                headers=headers,
                body=body,
            )
            self.callbacks.append(callback)
            logger.info(
                "OOB callback received: %s %s from %s", method, path, source_ip
            )

            # Send response
            response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            writer.write(response.encode())
            await writer.drain()

        except Exception as e:
            logger.debug("OOB handler error: %s", e)
        finally:
            writer.close()

    @property
    def has_callbacks(self) -> bool:
        return len(self.callbacks) > 0
