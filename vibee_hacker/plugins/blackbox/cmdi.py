# vibee_hacker/plugins/blackbox/cmdi.py
"""OS Command Injection detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

MARKER = "VIBEE_CMD_MARKER"
PAYLOADS = [
    f";echo {MARKER}",
    f"|echo {MARKER}",
    f"`echo {MARKER}`",
    f"$(echo {MARKER})",
    f"&&echo {MARKER}",
    f"& echo {MARKER}",        # Windows cmd
]

MAX_PARAMS = 10


class CmdiPlugin(PluginBase):
    name = "cmdi"
    description = "OS Command Injection detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Command output marker found in response after injecting shell commands"
    expected_evidence = "VIBEE_CMD_MARKER string in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch baseline response and abort if MARKER already present
            try:
                baseline_resp = await client.get(target.url)
                if MARKER in baseline_resp.text:
                    return []
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            # --- GET parameter fuzzing ---
            if params:
                capped_params = dict(list(params.items())[:MAX_PARAMS])
                for param_name, values in capped_params.items():
                    original = values[0] if values else ""
                    for payload in PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
                        test_params[param_name] = original + payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        try:
                            resp = await client.get(test_url)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:  # 1MB max response
                            continue

                        if MARKER in resp.text:
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"Command Injection in parameter '{param_name}'",
                                description=f"Output-based CMDi with payload: {payload}",
                                evidence=MARKER,
                                cwe_id="CWE-78",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url)}",
                                rule_id="cmdi_output_based",
                            ))
                            return results

            # --- POST body fuzzing ---
            # Try POST injection when no GET params exist or GET scan found nothing
            if not results:
                post_fields = ["q", "search", "username", "email", "name", "query", "input"]
                form_fields: list[str] = []
                post_urls: list[str] = [target.url]
                if context and context.crawl_forms:
                    for form in context.crawl_forms:
                        if form.get("method", "get").lower() == "post":
                            form_action = form.get("action", target.url)
                            if form_action not in post_urls:
                                post_urls.append(form_action)
                            for field in form.get("fields", []):
                                fname = field.get("name", "")
                                if fname and fname not in form_fields:
                                    form_fields.append(fname)

                fields_to_fuzz = form_fields if form_fields else post_fields

                for post_url in post_urls[:5]:
                    for field in fields_to_fuzz[:MAX_PARAMS]:
                        for payload in PAYLOADS:
                            data = {field: payload}
                            try:
                                resp = await client.post(post_url, data=data, timeout=10)
                            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                                continue

                            if len(resp.text) > 1_000_000:
                                continue

                            if MARKER in resp.text:
                                results.append(Result(
                                    plugin_name=self.name,
                                    base_severity=self.base_severity,
                                    title=f"Command Injection via POST field '{field}'",
                                    description=f"Output-based CMDi via POST with payload: {payload}",
                                    evidence=MARKER,
                                    cwe_id="CWE-78",
                                    endpoint=post_url,
                                    param_name=field,
                                    rule_id="cmdi_output_based",
                                ))
                                return results

        return results
