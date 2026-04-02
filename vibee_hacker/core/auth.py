"""Authentication framework for authenticated scanning."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration."""
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    success_pattern: str = ""  # regex to verify login succeeded
    token_header: str = ""  # e.g., "Authorization"
    token_pattern: str = ""  # regex to extract token from login response
    cookie_names: list[str] = field(default_factory=list)  # cookies to preserve


class AuthHandler:
    """Manages authentication for scans."""

    def __init__(self, config: AuthConfig):
        self.config = config
        self._cookies: dict[str, str] = {}
        self._headers: dict[str, str] = {}
        self._authenticated = False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def auth_headers(self) -> dict[str, str]:
        """Get headers to use for authenticated requests."""
        headers = dict(self._headers)
        if self._cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        return headers

    async def login(self, client: httpx.AsyncClient | None = None) -> bool:
        """Perform login and capture session tokens."""
        if not self.config.login_url:
            return False

        own_client = client is None
        if own_client:
            client = httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True)

        try:
            # POST login credentials
            data = {
                self.config.username_field: self.config.username,
                self.config.password_field: self.config.password,
            }
            resp = await client.post(self.config.login_url, data=data)

            # Check success
            if self.config.success_pattern:
                if not re.search(self.config.success_pattern, resp.text, re.IGNORECASE):
                    logger.warning("Login failed: success pattern not found")
                    return False

            # Extract cookies
            for cookie_name, cookie_value in resp.cookies.items():
                if not self.config.cookie_names or cookie_name in self.config.cookie_names:
                    self._cookies[cookie_name] = cookie_value

            # Extract token from response
            if self.config.token_pattern and self.config.token_header:
                match = re.search(self.config.token_pattern, resp.text)
                if match:
                    self._headers[self.config.token_header] = match.group(1)

            self._authenticated = bool(self._cookies or self._headers)
            return self._authenticated

        except Exception as e:
            logger.warning("Login failed: %s", e)
            return False
        finally:
            if own_client:
                await client.aclose()

    async def refresh_if_needed(self, client: httpx.AsyncClient) -> bool:
        """Re-login if session expired (check by hitting a protected page)."""
        if not self._authenticated:
            return await self.login(client)
        return True

    def reset(self):
        """Clear all auth state."""
        self._cookies.clear()
        self._headers.clear()
        self._authenticated = False
