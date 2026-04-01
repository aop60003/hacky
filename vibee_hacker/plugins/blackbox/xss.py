# vibee_hacker/plugins/blackbox/xss.py
"""Reflected XSS detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

XSS_PAYLOADS = [
    "<script>alert('vbh')</script>",
    "<img src=x onerror=alert('vbh')>",
    "'\"><svg/onload=alert('vbh')>",
]

MAX_PARAMS = 10


class XssPlugin(PluginBase):
    name = "xss"
    description = "Reflected XSS detection"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Injected XSS payload reflected unescaped in response body"
    expected_evidence = "XSS payload string found verbatim in response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # --- GET parameter fuzzing ---
            if params:
                capped_params = dict(list(params.items())[:MAX_PARAMS])
                for param_name in capped_params:
                    for payload in XSS_PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        try:
                            resp = await client.get(test_url)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:  # 1MB max response
                            continue

                        content_type = resp.headers.get("content-type", "")
                        if "text/html" not in content_type:
                            continue

                        if payload in resp.text:
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"Reflected XSS in parameter '{param_name}'",
                                description=f"Payload reflected unescaped: {payload[:50]}",
                                evidence=payload,
                                cwe_id="CWE-79",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url)}",
                                rule_id="xss_reflected",
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
                        for payload in XSS_PAYLOADS:
                            data = {field: payload}
                            try:
                                resp = await client.post(post_url, data=data, timeout=10)
                            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                                continue

                            if len(resp.text) > 1_000_000:
                                continue

                            content_type = resp.headers.get("content-type", "")
                            if "text/html" not in content_type:
                                continue

                            if payload in resp.text:
                                results.append(Result(
                                    plugin_name=self.name,
                                    base_severity=self.base_severity,
                                    title=f"Reflected XSS via POST field '{field}'",
                                    description=f"Payload reflected unescaped in POST response: {payload[:50]}",
                                    evidence=payload,
                                    cwe_id="CWE-79",
                                    endpoint=post_url,
                                    param_name=field,
                                    rule_id="xss_reflected",
                                ))
                                return results

        return results
