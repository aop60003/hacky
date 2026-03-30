# vibee_hacker/plugins/blackbox/sensitive_data_exposure.py
"""Sensitive data exposure detection plugin."""

from __future__ import annotations

import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SENSITIVE_PATTERNS = [
    (
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),
        "credit_card",
        "Credit card number",
    ),
    (
        re.compile(r"\b\d{6}-[1-4]\d{6}\b"),
        "korean_ssn",
        "Korean resident registration number (주민번호)",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_key",
        "AWS access key",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
        "private_key",
        "Private key material",
    ),
]


class SensitiveDataPlugin(PluginBase):
    name = "sensitive_data_exposure"
    description = "Detect sensitive data leaked in HTTP response bodies"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Sensitive data patterns (credit cards, SSN, keys) in response"
    expected_evidence = "Matched sensitive data pattern in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            for pattern, pattern_id, label in SENSITIVE_PATTERNS:
                match = pattern.search(resp.text)
                if match:
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Sensitive data exposed: {label}",
                        description=(
                            f"{label} pattern detected in HTTP response body at {target.url}."
                        ),
                        evidence=f"Pattern '{pattern.pattern}' matched at position {match.start()}",
                        cwe_id="CWE-200",
                        endpoint=target.url,
                        curl_command=f"curl {shlex.quote(target.url)}",
                        rule_id=f"sensitive_data_{pattern_id}",
                    ))

        return results
