# vibee_hacker/plugins/blackbox/cloud_storage_exposure.py
"""Cloud storage public exposure detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Patterns to find cloud storage URLs in response body
CLOUD_URL_PATTERNS = [
    # AWS S3: s3.amazonaws.com, s3-region.amazonaws.com, bucket.s3.amazonaws.com
    re.compile(
        r"https?://[a-zA-Z0-9._-]*\.?s3(?:-[a-z0-9-]+)?\.amazonaws\.com(?:/[^\s\"'<>]*)?",
        re.I,
    ),
    # GCS: storage.googleapis.com/bucket/...
    re.compile(
        r"https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+(?:/[^\s\"'<>]*)?",
        re.I,
    ),
    # Azure Blob: account.blob.core.windows.net
    re.compile(
        r"https?://[a-zA-Z0-9-]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?",
        re.I,
    ),
]

PUBLIC_INDICATORS = [
    "ListBucketResult",
    "ListBucketResponse",
    "<Contents>",
    "<Key>",
    "<?xml",
]


def _extract_bucket_root(url: str) -> str | None:
    """Extract the bucket root URL from a cloud storage URL."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


class CloudStorageExposurePlugin(PluginBase):
    name = "cloud_storage_exposure"
    description = "Detect publicly accessible S3/GCS/Azure Blob storage by scanning response for cloud URLs"
    category = "blackbox"
    phase = 2
    base_severity = Severity.CRITICAL
    detection_criteria = "Cloud storage URL found in response body and bucket root returns public listing"
    expected_evidence = "ListBucketResult XML or data in response from cloud storage URL"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        seen_buckets: set[str] = set()

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch main page to look for cloud storage URLs
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            # Find all cloud storage URLs in the response
            cloud_urls: list[str] = []
            for pattern in CLOUD_URL_PATTERNS:
                cloud_urls.extend(pattern.findall(resp.text))

            # Probe each unique bucket root
            for cloud_url in cloud_urls:
                bucket_root = _extract_bucket_root(cloud_url)
                if not bucket_root or bucket_root in seen_buckets:
                    continue
                seen_buckets.add(bucket_root)

                try:
                    bucket_resp = await client.get(bucket_root)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if bucket_resp.status_code == 200:
                    body = bucket_resp.text
                    is_public = any(indicator in body for indicator in PUBLIC_INDICATORS)

                    if is_public or len(body) > 100:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Publicly accessible cloud storage: {bucket_root}",
                            description=(
                                f"A cloud storage bucket at '{bucket_root}' was found referenced "
                                f"in the response body of '{target.url}' and is publicly accessible. "
                                f"This may expose sensitive files or allow unauthorized data access."
                            ),
                            evidence=(
                                f"Bucket URL: {bucket_root} | "
                                f"Status: {bucket_resp.status_code} | "
                                f"Response length: {len(body)} bytes"
                            ),
                            recommendation=(
                                "Remove public access from cloud storage buckets. "
                                "Enable bucket-level access control policies. "
                                "Use pre-signed URLs for legitimate public file access."
                            ),
                            cwe_id="CWE-284",
                            endpoint=bucket_root,
                            curl_command=f"curl -v {shlex.quote(bucket_root)}",
                            rule_id="cloud_storage_public",
                        ))

        return results
