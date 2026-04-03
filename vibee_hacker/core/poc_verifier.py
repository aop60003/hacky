"""PoC auto-verifier: executes generated PoCs to confirm vulnerabilities."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx

from vibee_hacker.core.poc_generator import PoC

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of PoC verification."""
    poc_title: str
    verified: bool
    confidence: str  # "confirmed", "likely", "unconfirmed", "false_positive"
    evidence: str = ""
    response_status: int = 0
    response_body_snippet: str = ""
    response_time_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "poc_title": self.poc_title,
            "verified": self.verified,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "response_status": self.response_status,
            "response_body_snippet": self.response_body_snippet,
            "response_time_ms": self.response_time_ms,
            "error": self.error,
        }


# Verification signatures per vuln type
VERIFICATION_SIGNATURES: dict[str, dict] = {
    "sqli": {
        "check": "pattern",
        "success_patterns": [
            r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL",
            r"sqlite3\.OperationalError", r"SQLSTATE", r"syntax error",
            r"Unclosed quotation mark", r"unterminated",
        ],
        "method": "GET",
        "payload_param": True,
    },
    "xss": {
        "success_patterns": [
            r"<script>alert\(", r"<img\s+src=x\s+onerror=",
            r"javascript:", r"on\w+=",
        ],
        "check": "reflection",  # payload must be reflected in response
        "method": "GET",
        "payload_param": True,
    },
    "cmdi": {
        "check": "pattern",
        "success_patterns": [
            r"uid=\d+", r"root:", r"www-data", r"bin/bash",
            r"Windows NT", r"SYSTEM",
        ],
        "method": "GET",
        "payload_param": True,
    },
    "ssrf": {
        "check": "pattern",
        "success_patterns": [
            r"ami-id", r"instance-id", r"iam/security-credentials",
            r"metadata", r"169\.254\.169\.254",
        ],
        "method": "GET",
        "payload_param": True,
    },
    "cors": {
        "check": "header",
        "header_name": "Access-Control-Allow-Origin",
        "expected_value": "https://evil.com",
        "method": "GET",
        "extra_headers": {"Origin": "https://evil.com"},
    },
    "open_redirect": {
        "check": "redirect",
        "expected_location": "evil.com",
        "method": "GET",
        "payload_param": True,
    },
    "default_creds": {
        "check": "pattern",
        "success_patterns": [
            r"dashboard", r"welcome", r"logout", r"admin panel",
        ],
        "method": "POST",
        "post_data": {"username": "admin", "password": "admin"},
    },
    "idor": {
        "check": "diff",  # different content for different IDs
        "method": "GET",
    },
}


class PoCVerifier:
    """Automatically verify PoCs by executing them safely."""

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def verify(self, poc: PoC) -> VerificationResult:
        """Verify a single PoC."""
        vuln_type = poc.vuln_type
        sigs = VERIFICATION_SIGNATURES.get(vuln_type)

        if not sigs:
            return VerificationResult(
                poc_title=poc.vuln_title,
                verified=False,
                confidence="unconfirmed",
                error=f"No verification signatures for type: {vuln_type}",
            )

        # Extract URL from curl command
        url = self._extract_url_from_curl(poc.curl_command)
        if not url:
            return VerificationResult(
                poc_title=poc.vuln_title,
                verified=False,
                confidence="unconfirmed",
                error="Could not extract URL from PoC",
            )

        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                method = sigs.get("method", "GET")
                headers = sigs.get("extra_headers", {})
                data = sigs.get("post_data")

                if method == "POST" and data:
                    resp = await client.post(url, data=data, headers=headers)
                else:
                    resp = await client.get(url, headers=headers)

                elapsed_ms = resp.elapsed.total_seconds() * 1000
                body = resp.text[:5000]

                # Check verification based on type — check_type takes priority
                check_type = sigs.get("check", "pattern")

                if check_type == "reflection":
                    # Check if payload is reflected in response
                    patterns = sigs.get("success_patterns", [])
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            return VerificationResult(
                                poc_title=poc.vuln_title,
                                verified=True,
                                confidence="confirmed",
                                evidence=f"XSS payload reflected: {pattern}",
                                response_status=resp.status_code,
                                response_body_snippet=body[:200],
                                response_time_ms=elapsed_ms,
                            )

                elif check_type == "pattern":
                    patterns = sigs.get("success_patterns", [])
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            return VerificationResult(
                                poc_title=poc.vuln_title,
                                verified=True,
                                confidence="confirmed",
                                evidence=f"Pattern matched: {pattern} -> {match.group()[:100]}",
                                response_status=resp.status_code,
                                response_body_snippet=body[:200],
                                response_time_ms=elapsed_ms,
                            )

                elif check_type == "header":
                    header_name = sigs.get("header_name", "")
                    expected = sigs.get("expected_value", "")
                    actual = resp.headers.get(header_name, "")
                    if expected.lower() in actual.lower():
                        return VerificationResult(
                            poc_title=poc.vuln_title,
                            verified=True,
                            confidence="confirmed",
                            evidence=f"{header_name}: {actual}",
                            response_status=resp.status_code,
                            response_time_ms=elapsed_ms,
                        )

                elif check_type == "redirect":
                    location = resp.headers.get("Location", "")
                    expected = sigs.get("expected_location", "")
                    if expected in location:
                        return VerificationResult(
                            poc_title=poc.vuln_title,
                            verified=True,
                            confidence="confirmed",
                            evidence=f"Redirect to: {location}",
                            response_status=resp.status_code,
                            response_time_ms=elapsed_ms,
                        )

                # Not confirmed
                return VerificationResult(
                    poc_title=poc.vuln_title,
                    verified=False,
                    confidence="unconfirmed",
                    evidence="No verification signatures matched",
                    response_status=resp.status_code,
                    response_body_snippet=body[:200],
                    response_time_ms=elapsed_ms,
                )

        except httpx.TransportError as e:
            return VerificationResult(
                poc_title=poc.vuln_title,
                verified=False,
                confidence="unconfirmed",
                error=f"Connection error: {e}",
            )
        except Exception as e:
            return VerificationResult(
                poc_title=poc.vuln_title,
                verified=False,
                confidence="unconfirmed",
                error=str(e),
            )

    async def verify_all(self, pocs: list[PoC]) -> list[VerificationResult]:
        """Verify all PoCs."""
        results = []
        for poc in pocs:
            result = await self.verify(poc)
            results.append(result)
        return results

    def _extract_url_from_curl(self, curl_cmd: str) -> str:
        """Extract URL from a curl command string."""
        # Match curl -s 'URL' or curl 'URL'
        match = re.search(r"curl\s+(?:-[sIvX]\s+)*'([^']+)'", curl_cmd)
        if match:
            return match.group(1)
        # Try double quotes
        match = re.search(r'curl\s+(?:-[sIvX]\s+)*"([^"]+)"', curl_cmd)
        if match:
            return match.group(1)
        return ""

    def summary(self, results: list[VerificationResult]) -> dict:
        """Get summary of verification results."""
        confirmed = sum(1 for r in results if r.confidence == "confirmed")
        likely = sum(1 for r in results if r.confidence == "likely")
        unconfirmed = sum(1 for r in results if r.confidence == "unconfirmed")
        fp = sum(1 for r in results if r.confidence == "false_positive")
        return {
            "total": len(results),
            "confirmed": confirmed,
            "likely": likely,
            "unconfirmed": unconfirmed,
            "false_positive": fp,
            "verification_rate": f"{confirmed}/{len(results)}" if results else "0/0",
        }
