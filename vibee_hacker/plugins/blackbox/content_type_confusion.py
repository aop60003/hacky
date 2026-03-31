# vibee_hacker/plugins/blackbox/content_type_confusion.py
"""Content-type confusion / validation bypass detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# JSON body to send in all cases
JSON_BODY = '{"test": "probe"}'

# (content_type_header, description)
# None means no Content-Type header is sent
WRONG_CONTENT_TYPES: list[tuple[str | None, str]] = [
    ("application/xml", "XML content-type with JSON body (potential XXE bypass)"),
    ("text/plain", "text/plain content-type with JSON body (CORS preflight bypass)"),
    (None, "no Content-Type header with JSON body"),
]

# Status codes that indicate the server processed the request successfully
SUCCESS_CODES = {200, 201, 202, 204}

# Status codes that indicate the server correctly rejected wrong content-type
REJECTION_CODES = {400, 415, 422}


class ContentTypeConfusionPlugin(PluginBase):
    name = "content_type_confusion"
    description = "Detect content-type validation bypass — server accepts wrong content-type"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = (
        "Server returns 2xx for POST with wrong Content-Type while baseline JSON POST also returns 2xx"
    )
    expected_evidence = "HTTP 2xx response for wrong Content-Type request matching baseline success response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Establish baseline with correct JSON content-type
            try:
                baseline_resp = await client.post(
                    target.url,
                    content=JSON_BODY,
                    headers={"Content-Type": "application/json"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if baseline_resp.status_code not in SUCCESS_CODES:
                # Endpoint doesn't accept JSON either — skip
                return []

            # Now test with wrong content-types
            for ct, ct_description in WRONG_CONTENT_TYPES:
                headers: dict[str, str] = {}
                if ct is not None:
                    headers["Content-Type"] = ct

                try:
                    resp = await client.post(
                        target.url,
                        content=JSON_BODY,
                        headers=headers,
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if len(resp.text) > 1_000_000:
                    continue

                if resp.status_code in SUCCESS_CODES:
                    ct_display = ct if ct else "(none)"
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Content-type not validated: accepted '{ct_display}'",
                        description=(
                            f"The endpoint {target.url} accepted a POST request with Content-Type "
                            f"'{ct_display}' ({ct_description}), returning HTTP {resp.status_code}. "
                            f"Missing content-type validation can enable XXE attacks, CORS preflight "
                            f"bypass, or type confusion leading to unexpected server behavior."
                        ),
                        evidence=(
                            f"Content-Type: '{ct_display}' accepted | "
                            f"Status: {resp.status_code} | Baseline status: {baseline_resp.status_code}"
                        ),
                        cwe_id="CWE-436",
                        endpoint=target.url,
                        curl_command=(
                            f"curl -X POST {shlex.quote(target.url)} "
                            + (f"-H 'Content-Type: {ct}' " if ct else "")
                            + f"-d {shlex.quote(JSON_BODY)}"
                        ),
                        rule_id="content_type_not_validated",
                    ))
                    return results  # Stop on first confirmed finding

        return results
