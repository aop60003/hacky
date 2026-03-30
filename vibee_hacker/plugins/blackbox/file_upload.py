# vibee_hacker/plugins/blackbox/file_upload.py
"""File Upload Vulnerability detection plugin (extension bypass)."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urljoin

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Character class matching single or double quotes in HTML attribute values
_Q = chr(34) + chr(39)


def _pat(pattern):
    return re.compile(pattern, re.I)


UPLOAD_FORM_PATTERNS = [
    _pat("<input[^>]+type=[" + _Q + "]?file[" + _Q + "]?"),
    _pat("<form[^>]+enctype=[" + _Q + "]multipart/form-data[" + _Q + "]"),
]

UPLOAD_SUCCESS_PATTERNS = [
    _pat("/uploads?/"),
    _pat(r"\.php"),
    _pat(chr(34) + "url" + chr(34) + r"\s*:"),
    _pat(chr(34) + "path" + chr(34) + r"\s*:"),
    _pat(chr(34) + "file" + chr(34) + r"\s*:"),
    _pat(chr(34) + "filename" + chr(34) + r"\s*:"),
    _pat(chr(34) + "location" + chr(34) + r"\s*:"),
]

UPLOAD_FILENAME = "shell.php.jpg"
UPLOAD_CONTENT = b"GIF89a" + bytes(20)
UPLOAD_CONTENT_TYPE = "image/jpeg"
DEFAULT_FIELD_NAME = "file"


def _find_upload_field(html):
    match = re.search(
        "<input[^>]+type=[" + _Q + "]?file[" + _Q + "]?[^>]*>",
        html, re.I,
    )
    if match:
        nm = re.search(
            r"name=[" + _Q + "]?([^" + _Q + r">\s]+)",
            match.group(), re.I,
        )
        if nm:
            return nm.group(1)
    return DEFAULT_FIELD_NAME


def _find_form_action(html, base_url):
    match = re.search(
        "<form[^>]+action=[" + _Q + "]?([^" + _Q + r">\s]+)",
        html, re.I,
    )
    if match:
        return urljoin(base_url, match.group(1))
    return base_url


class FileUploadPlugin(PluginBase):
    name = "file_upload"
    description = "File Upload Vulnerability detection (extension bypass)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Upload of .php.jpg double-extension file returns 200 with stored path"
    expected_evidence = "Server accepts and stores double-extension file, returns path in response"
    destructive_level = 1

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                page_resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(page_resp.text) > 1_000_000:
                return []

            html = page_resp.text
            has_upload = any(p.search(html) for p in UPLOAD_FORM_PATTERNS)
            if not has_upload:
                return []

            field_name = _find_upload_field(html)
            action_url = _find_form_action(html, target.url)
            files = {field_name: (UPLOAD_FILENAME, UPLOAD_CONTENT, UPLOAD_CONTENT_TYPE)}

            try:
                upload_resp = await client.post(action_url, files=files)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if upload_resp.status_code not in (200, 201):
                return []

            if len(upload_resp.text) > 1_000_000:
                return []

            for pattern in UPLOAD_SUCCESS_PATTERNS:
                if pattern.search(upload_resp.text):
                    curl_cmd = (
                        f"curl -X POST {shlex.quote(action_url)} "
                        f"-F {shlex.quote(field_name + '=@' + UPLOAD_FILENAME + ';type=' + UPLOAD_CONTENT_TYPE)}"
                    )
                    return [Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="File Upload Extension Bypass (Unrestricted File Upload)",
                        description=(
                            f"The application accepted upload of '{UPLOAD_FILENAME}' "
                            "(a double-extension PHP file disguised as JPEG). "
                            "The server response indicates the file was stored, "
                            "which may allow remote code execution."
                        ),
                        evidence=(
                            f"Upload response ({upload_resp.status_code}): "
                            f"{upload_resp.text[:200]}"
                        ),
                        cwe_id="CWE-434",
                        endpoint=target.url,
                        curl_command=curl_cmd,
                        rule_id="file_upload_extension_bypass",
                    )]

        return []
