# vibee_hacker/plugins/blackbox/auth_check.py
"""Session management / authentication check plugin."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Cookie names commonly used for session tracking
SESSION_COOKIE_NAMES = re.compile(
    r"(sessionid|session|sess|sid|auth|token|jsessionid|phpsessid|asp\.net_sessionid)",
    re.IGNORECASE,
)


def _extract_session_value(set_cookie_header: str) -> str | None:
    """Return the value of a recognised session cookie from a Set-Cookie header."""
    for part in set_cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            if SESSION_COOKIE_NAMES.fullmatch(name.strip()):
                return value.strip()
    return None


class AuthCheckPlugin(PluginBase):
    name = "auth_check"
    description = "Detect session fixation: check whether session token rotates between logins"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Session cookie does not change between two successive login requests"
    expected_evidence = "Identical session token returned on first and second login"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        credentials = {"username": "testuser", "password": "testpass"}
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp1 = await client.post(target.url, data=credentials)
                resp2 = await client.post(target.url, data=credentials)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        cookie1_header = resp1.headers.get("set-cookie", "")
        cookie2_header = resp2.headers.get("set-cookie", "")

        if not cookie1_header:
            return []

        token1 = _extract_session_value(cookie1_header)
        token2 = _extract_session_value(cookie2_header)

        if token1 is None:
            return []

        if token1 == token2:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="Session fixation: session token does not rotate on re-authentication",
                description=(
                    f"Two successive POST requests to {target.url} returned the identical "
                    f"session cookie value. An attacker who can set a victim's session cookie "
                    f"before authentication will inherit the authenticated session."
                ),
                evidence=f"Token1='{token1}' | Token2='{token2}'",
                recommendation=(
                    "Regenerate the session identifier after every successful authentication. "
                    "Use framework-provided session management that rotates tokens automatically."
                ),
                cwe_id="CWE-384",
                endpoint=target.url,
                rule_id="session_fixation",
            ))

        return results
