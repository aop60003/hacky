# vibee_hacker/plugins/blackbox/user_enum.py
"""User enumeration detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

LOGIN_PATHS = [
    "/login",
    "/signin",
    "/auth",
    "/api/login",
    "/api/auth",
    "/api/signin",
    "/user/login",
    "/account/login",
]

KNOWN_USER = "admin"
UNKNOWN_USER = "nonexistent_user_xyz_abc_12345"


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class UserEnumPlugin(PluginBase):
    name = "user_enum"
    description = "Detect user enumeration via differing login responses"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "Login endpoint returns different response body for known vs unknown username"
    expected_evidence = "Response body length or content differs between admin and nonexistent user"
    destructive_level = 1

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for path in LOGIN_PATHS:
                endpoint = base + path
                try:
                    resp_known = await client.post(
                        endpoint,
                        json={"username": KNOWN_USER, "password": "wrong_password_xyz"},
                        headers={"Content-Type": "application/json"},
                    )
                    resp_unknown = await client.post(
                        endpoint,
                        json={"username": UNKNOWN_USER, "password": "wrong_password_xyz"},
                        headers={"Content-Type": "application/json"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Skip if endpoint doesn't exist
                if resp_known.status_code == 404 and resp_unknown.status_code == 404:
                    continue

                # Skip if no meaningful response at all
                if resp_known.status_code == 404:
                    continue

                # Compare status codes
                status_differs = resp_known.status_code != resp_unknown.status_code

                # Compare body content
                body_known = resp_known.text.strip() if len(resp_known.text) < 100_000 else ""
                body_unknown = resp_unknown.text.strip() if len(resp_unknown.text) < 100_000 else ""
                body_length_diff = abs(len(body_known) - len(body_unknown))
                body_content_differs = body_known != body_unknown

                if status_differs or body_content_differs:
                    evidence_parts = []
                    if status_differs:
                        evidence_parts.append(
                            f"Status codes differ: known={resp_known.status_code}, unknown={resp_unknown.status_code}"
                        )
                    if body_content_differs:
                        evidence_parts.append(
                            f"Body length differs by {body_length_diff} chars"
                        )

                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="User enumeration possible via login endpoint",
                        description=(
                            f"The login endpoint at {endpoint} returns different responses for "
                            f"existing vs non-existing usernames. This allows attackers to enumerate "
                            f"valid user accounts via targeted credential attacks."
                        ),
                        evidence=" | ".join(evidence_parts),
                        recommendation=(
                            "Return identical generic error messages for all failed login attempts "
                            "regardless of whether the username exists. Use constant-time comparison "
                            "and ensure response bodies, status codes, and timing are identical."
                        ),
                        cwe_id="CWE-204",
                        endpoint=endpoint,
                        curl_command=(
                            f"curl -s -X POST {shlex.quote(endpoint)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"username\":\"admin\",\"password\":\"wrong\"}}'"
                        ),
                        rule_id="user_enumeration",
                    ))
                    return results  # Stop on first finding

        return results
