# vibee_hacker/plugins/blackbox/jwt_check.py
"""JWT Token Analysis plugin — detects weak/insecure JWT configurations."""

from __future__ import annotations

import base64
import json
import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Regex to find JWT tokens: three base64url segments separated by dots
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Simple PII patterns inside JWT payload
PII_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),  # email
    re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),                   # US phone
]


def _b64_decode(segment: str) -> dict | None:
    """Decode a base64url JWT segment into a dict, padding as needed."""
    # Add padding
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(segment))
    except Exception:
        return None


def _extract_jwts(text: str, headers: dict) -> list[str]:
    """Find JWT strings in response headers and body."""
    tokens: list[str] = []
    # Check Authorization and Set-Cookie headers
    for header_name in ("authorization", "set-cookie"):
        value = headers.get(header_name, "")
        for match in JWT_PATTERN.finditer(value):
            tokens.append(match.group())
    # Check response body
    for match in JWT_PATTERN.finditer(text):
        tokens.append(match.group())
    return list(dict.fromkeys(tokens))  # deduplicate while preserving order


class JwtCheckPlugin(PluginBase):
    name = "jwt_check"
    description = "JWT Token Analysis — detects alg:none, missing exp, PII in payload"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "JWT found in response with weak algorithm, missing expiry, or PII"
    expected_evidence = "Decoded JWT header/payload revealing security weakness"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

        # Normalise header names to lowercase for lookup
        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        tokens = _extract_jwts(resp.text, lower_headers)
        if not tokens:
            return []

        results: list[Result] = []

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            header_data = _b64_decode(parts[0])
            payload_data = _b64_decode(parts[1])

            if header_data is None or payload_data is None:
                continue

            # Check 1: alg = none (CRITICAL)
            alg = str(header_data.get("alg", "")).lower()
            if alg in ("none", ""):
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.CRITICAL,
                    title="JWT uses 'alg: none' (signature bypass)",
                    description=(
                        "A JWT token was found with algorithm set to 'none', "
                        "meaning the signature is not verified by the server."
                    ),
                    evidence=f"JWT header: {json.dumps(header_data)}",
                    cwe_id="CWE-347",
                    endpoint=target.url,
                    rule_id="jwt_weak_alg_none",
                ))

            # Check 2: missing exp claim
            if "exp" not in payload_data:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.HIGH,
                    title="JWT missing expiration claim (exp)",
                    description=(
                        "A JWT token was found without an 'exp' (expiration) claim. "
                        "This token does not expire and can be replayed indefinitely."
                    ),
                    evidence=f"JWT payload keys: {list(payload_data.keys())}",
                    cwe_id="CWE-347",
                    endpoint=target.url,
                    rule_id="jwt_weak_no_expiry",
                ))

            # Check 3: PII in payload
            payload_str = json.dumps(payload_data)
            for pattern in PII_PATTERNS:
                match = pattern.search(payload_str)
                if match:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title="PII found in JWT payload",
                        description=(
                            "The JWT payload contains what appears to be Personally "
                            "Identifiable Information (PII). JWT payloads are only "
                            "base64-encoded (not encrypted) and can be read by anyone."
                        ),
                        evidence=f"PII pattern matched in JWT payload: {match.group()!r}",
                        cwe_id="CWE-347",
                        endpoint=target.url,
                        rule_id="jwt_weak_pii_in_payload",
                    ))
                    break  # One PII finding per token is enough

        return results
