"""Plugin: OAuth PKCE Downgrade Attack Detection (blackbox)."""
from __future__ import annotations

from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

OAUTH_PATHS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/oauth",
    "/authorize",
    "/connect/authorize",
    "/.well-known/openid-configuration",
]

PKCE_INDICATORS = [
    "code_challenge",
    "pkce",
    "S256",
    "code_verifier",
]


class OauthPkceDowngradePlugin(PluginBase):
    name = "oauth_pkce_downgrade"
    description = "Check OAuth endpoints for missing PKCE enforcement (code_challenge not required)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=False) as client:
            for path in OAUTH_PATHS:
                endpoint = base + path

                # Step 1: Check if endpoint exists
                try:
                    probe = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Skip clearly non-existent endpoints
                if probe.status_code == 404:
                    continue

                # Step 2: Try authorization request WITHOUT code_challenge
                params = {
                    "response_type": "code",
                    "client_id": "test_client",
                    "redirect_uri": "https://attacker.example.com/callback",
                    "scope": "openid",
                    "state": "vibee_pkce_test",
                }
                try:
                    resp = await client.get(endpoint, params=params)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                body = resp.text[:3000]
                body_lower = body.lower()

                # If the server proceeds (redirect, login page, or 200) without requiring code_challenge
                # that's the vulnerability. If it returns an error about missing code_challenge, that's safe.
                requires_pkce = any(kw in body_lower for kw in [
                    "code_challenge_required",
                    "pkce required",
                    "code_challenge missing",
                    "invalid_request",
                ])
                mentions_pkce = any(kw in body_lower for kw in PKCE_INDICATORS)

                # If server accepts request without PKCE (no error about PKCE required)
                if resp.status_code in (200, 302, 303) and not requires_pkce:
                    location = resp.headers.get("location", "")
                    # Check if it's a redirect to our redirect_uri with a code (actual auth)
                    if "code=" in location or "code=" in body_lower:
                        severity = Severity.HIGH
                        detail = "Authorization code returned without PKCE validation."
                    else:
                        severity = Severity.MEDIUM
                        detail = "OAuth endpoint accepted request without code_challenge parameter."

                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=severity,
                            title="OAuth PKCE Not Enforced",
                            description=(
                                f"OAuth endpoint at {endpoint} accepted an authorization request without "
                                f"code_challenge (PKCE). {detail} "
                                "This enables authorization code interception attacks."
                            ),
                            evidence=f"GET {endpoint}?{urlencode(params)} → {resp.status_code}: {body[:200]}",
                            recommendation=(
                                "Require PKCE (code_challenge and code_verifier) for all public clients. "
                                "Reject authorization requests that omit code_challenge with error: "
                                "invalid_request / code_challenge_required."
                            ),
                            cwe_id="CWE-287",
                            rule_id="oauth_pkce_missing",
                            endpoint=endpoint,
                        )
                    )
                    return results

        return results
