# vibee_hacker/plugins/blackbox/oauth_check.py
"""OAuth misconfiguration detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

OAUTH_PATH_PATTERN = re.compile(r"/oauth|/authorize|/auth|/login", re.I)
EVIL_REDIRECT = "https://evil.com/callback"


class OauthCheckPlugin(PluginBase):
    name = "oauth_check"
    description = "Detect OAuth redirect_uri bypass and missing state parameter"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "redirect_uri=evil.com accepted (302 to evil.com) or missing state param accepted"
    expected_evidence = "302 redirect Location header pointing to evil.com"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        if not OAUTH_PATH_PATTERN.search(parsed.path):
            return []

        results: list[Result] = []

        # Test redirect_uri validation bypass
        probe_params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": EVIL_REDIRECT,
        }
        probe_url = urlunparse(parsed._replace(query=urlencode(probe_params)))

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            try:
                resp = await client.get(probe_url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="OAuth redirect_uri validation bypass",
                        description=(
                            f"The OAuth endpoint accepted redirect_uri='{EVIL_REDIRECT}' "
                            f"and redirected to '{location}'. "
                            f"An attacker can steal authorization codes by controlling the redirect URI."
                        ),
                        evidence=f"Status: {resp.status_code} | Location: {location}",
                        recommendation=(
                            "Validate redirect_uri strictly against a pre-registered allowlist. "
                            "Do not allow dynamic or unregistered redirect URIs."
                        ),
                        cwe_id="CWE-601",
                        endpoint=probe_url,
                        curl_command=f"curl -v {shlex.quote(probe_url)}",
                        rule_id="oauth_redirect_bypass",
                    ))

            # Test missing state parameter acceptance
            no_state_params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": target.url,
            }
            no_state_url = urlunparse(parsed._replace(query=urlencode(no_state_params)))

            try:
                state_resp = await client.get(no_state_url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return results

            # If server responds 200 or redirect without complaining about missing state, flag it
            if state_resp.status_code in (200, 301, 302, 303, 307, 308):
                state_location = state_resp.headers.get("location", "")
                # Only flag if the redirect doesn't include a state parameter warning
                if "state" not in state_location.lower() and "error" not in state_location.lower():
                    # Check body for error about state
                    if "state" not in state_resp.text.lower()[:1000]:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title="OAuth missing state parameter accepted",
                            description=(
                                f"The OAuth endpoint accepted an authorization request without "
                                f"a 'state' parameter. This may allow CSRF attacks against the OAuth flow."
                            ),
                            evidence=f"Status: {state_resp.status_code} | No state parameter required",
                            recommendation=(
                                "Require and validate the 'state' parameter in OAuth authorization requests "
                                "to prevent CSRF attacks."
                            ),
                            cwe_id="CWE-352",
                            endpoint=no_state_url,
                            curl_command=f"curl -v {shlex.quote(no_state_url)}",
                            rule_id="oauth_missing_state",
                        ))

        return results
