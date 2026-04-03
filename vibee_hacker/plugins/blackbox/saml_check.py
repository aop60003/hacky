"""Plugin: SAML Endpoint Detection and Signature Validation Check (blackbox)."""
from __future__ import annotations

import base64
import re
from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SAML_PATHS = [
    "/saml/sso",
    "/saml/acs",
    "/saml/metadata",
    "/auth/saml",
    "/sso/saml",
    "/saml2/sso",
    "/api/saml/sso",
    "/saml/login",
]

# A minimal, unsigned SAML Response (will fail signature validation if implemented correctly)
UNSIGNED_SAML_RESPONSE = base64.b64encode(b"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_vibee_test_response"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z"
    Status="urn:oasis:names:tc:SAML:2.0:status:Success">
  <saml:Issuer>https://attacker.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="_vibee_assertion" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://attacker.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>""").decode()

SIGNATURE_ERROR_INDICATORS = [
    "signature",
    "invalid",
    "verification",
    "mismatch",
    "bad request",
    "unauthorized",
    "forbidden",
]


class SamlCheckPlugin(PluginBase):
    name = "saml_check"
    description = "Probe SAML endpoints and check for signature validation enforcement"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=False) as client:
            for path in SAML_PATHS:
                endpoint = base + path

                # Step 1: Probe endpoint
                try:
                    probe = await client.get(endpoint)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Skip non-existent endpoints
                if probe.status_code == 404:
                    continue

                body_lower = probe.text.lower()
                is_saml_endpoint = any(
                    kw in body_lower
                    for kw in ["saml", "sso", "assertion", "identity provider", "idp"]
                )

                # Step 2: Submit unsigned SAML response
                try:
                    resp = await client.post(
                        endpoint,
                        data={"SAMLResponse": UNSIGNED_SAML_RESPONSE, "RelayState": "vibee_test"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                resp_body = resp.text[:3000].lower()

                # If server accepted the unsigned response (2xx or redirect without error)
                signature_rejected = any(kw in resp_body for kw in SIGNATURE_ERROR_INDICATORS)

                if resp.status_code in (200, 302, 303) and not signature_rejected:
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title="SAML Signature Validation May Not Be Enforced",
                            description=(
                                f"SAML endpoint at {endpoint} accepted an unsigned SAML Response "
                                f"(HTTP {resp.status_code}) without rejecting it. "
                                "If signature validation is not enforced, attackers can forge SAML assertions "
                                "to authenticate as any user."
                            ),
                            evidence=f"POST {endpoint} with unsigned SAMLResponse → {resp.status_code}: {resp.text[:200]}",
                            recommendation=(
                                "Enforce XML signature validation on all SAML responses and assertions. "
                                "Use a well-tested SAML library and verify the issuer and signature certificate."
                            ),
                            cwe_id="CWE-347",
                            rule_id="saml_signature_bypass",
                            endpoint=endpoint,
                        )
                    )
                    return results

                # If endpoint was found but properly rejected
                elif probe.status_code not in (404, 405) and (is_saml_endpoint or resp.status_code != 404):
                    # Report the endpoint presence as informational
                    if not results:
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.INFO,
                                title="SAML Endpoint Discovered",
                                description=(
                                    f"A SAML endpoint was found at {endpoint} (HTTP {probe.status_code}). "
                                    "The endpoint appears to reject unsigned responses correctly."
                                ),
                                evidence=f"GET {endpoint} → {probe.status_code}",
                                recommendation=(
                                    "Ensure SAML signature validation remains enforced and all SAML libraries are up to date."
                                ),
                                cwe_id="CWE-347",
                                rule_id="saml_endpoint_found",
                                endpoint=endpoint,
                            )
                        )

        return results
