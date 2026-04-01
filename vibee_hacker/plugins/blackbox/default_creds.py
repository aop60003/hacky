# vibee_hacker/plugins/blackbox/default_creds.py
"""Default credentials check plugin (P2-2)."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

DEFAULT_CREDS = [
    {"url_pattern": "/manager/html", "username": "tomcat", "password": "tomcat"},
    {"url_pattern": "/phpmyadmin/", "username": "root", "password": ""},
    {"url_pattern": "/admin/", "username": "admin", "password": "admin"},
    {"url_pattern": "/jenkins/", "username": "admin", "password": "admin"},
    {"url_pattern": "/grafana/", "username": "admin", "password": "admin"},
]

# Response body fragments that indicate a failed login
_FAILURE_MARKERS = (
    "invalid",
    "incorrect",
    "wrong password",
    "authentication failed",
    "login failed",
    "bad credentials",
    "unauthorized",
    "access denied",
)


def _login_succeeded(resp: httpx.Response) -> bool:
    """Return True if the response looks like a successful login."""
    body_lower = resp.text.lower()
    if any(marker in body_lower for marker in _FAILURE_MARKERS):
        return False
    return True


class DefaultCredsPlugin(PluginBase):
    name = "default_creds"
    description = "Check common admin interfaces for default credentials"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Default credentials accepted by an admin interface"
    expected_evidence = "HTTP 200 login response without failure indicators"
    destructive_level = 2

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = target.url.rstrip("/")
        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=True,
        ) as client:
            for cred in DEFAULT_CREDS:
                url_pattern = cred["url_pattern"]
                url = base + url_pattern

                # Step 1: Check if the endpoint is reachable
                try:
                    probe = await client.get(url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if probe.status_code != 200:
                    continue

                # Step 2: Attempt login with default credentials
                try:
                    login_resp = await client.post(
                        url,
                        data={
                            "username": cred["username"],
                            "password": cred["password"],
                        },
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if login_resp.status_code == 200 and _login_succeeded(login_resp):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title=f"Default credentials work on {url_pattern}",
                        description=(
                            f"The admin interface at {url} accepted default credentials "
                            f"({cred['username']}:{cred['password']}). "
                            "An attacker can take over this interface immediately."
                        ),
                        recommendation=(
                            f"Change the default credentials for the service at {url_pattern} immediately. "
                            "Enforce strong, unique passwords and restrict administrative access by IP."
                        ),
                        cwe_id="CWE-798",
                        evidence=(
                            f"POST {url} with username={cred['username']}, "
                            f"password={cred['password']} -> HTTP {login_resp.status_code}"
                        ),
                        endpoint=url,
                        rule_id="default_credentials",
                    ))

        return results
