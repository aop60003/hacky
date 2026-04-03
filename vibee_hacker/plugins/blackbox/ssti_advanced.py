# vibee_hacker/plugins/blackbox/ssti_advanced.py
"""Advanced SSTI detection plugin — engine-specific payloads for Jinja2, Twig, Freemarker."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Engine-specific payloads and their expected outputs
# Each tuple: (engine_name, payload, expected_result, rule_id_suffix)
ENGINE_PAYLOADS: list[tuple[str, str, str, str]] = [
    # Jinja2 / Flask: {{7*7}} → 49
    ("jinja2", "{{7*7}}", "49", "jinja2"),
    # Twig (PHP): {{7*'7'}} → 7777777 (string repetition)
    ("twig", "{{7*'7'}}", "7777777", "twig"),
    # Freemarker (Java): ${7*7} → 49
    ("freemarker", "${7*7}", "49", "freemarker"),
    # Smarty (PHP): {7*7} → 49
    ("smarty", "{7*7}", "49", "smarty"),
    # Mako / Cheetah: ${7*7} → 49 (same as freemarker)
    ("mako", "${7*7}", "49", "mako"),
]

MAX_PARAMS = 10


class SstiAdvancedPlugin(PluginBase):
    name = "ssti_advanced"
    description = (
        "Advanced SSTI — engine-specific payloads for Jinja2, Twig, Freemarker, "
        "Smarty, and Mako; detects by matching computed output (49 or 7777777)"
    )
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    destructive_level = 1
    detection_criteria = (
        "Engine-specific template expression evaluated and computed result "
        "(49 or 7777777) appears in response where it was not present in baseline"
    )
    expected_evidence = "Payload result '49' or '7777777' reflected after template injection"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_url in urls_to_test:
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                capped = dict(list(params.items())[:MAX_PARAMS])

                # Baseline to avoid false positives
                try:
                    baseline_resp = await client.get(test_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                baseline_text = baseline_resp.text

                for param_name, values in capped.items():
                    original_value = values[0] if values else ""

                    for engine_name, payload, expected, rule_suffix in ENGINE_PAYLOADS:
                        # Build test URL preserving other params
                        test_params = {k: v[0] for k, v in capped.items()}
                        test_params[param_name] = original_value + payload
                        test_url_injected = urlunparse(
                            parsed._replace(query=urlencode(test_params))
                        )

                        try:
                            resp = await client.get(test_url_injected)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if len(resp.text) > 1_000_000:
                            continue

                        if expected in resp.text and expected not in baseline_text:
                            return [Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=(
                                    f"Server-Side Template Injection ({engine_name.capitalize()}) "
                                    f"in parameter '{param_name}'"
                                ),
                                description=(
                                    f"SSTI detected using a {engine_name.capitalize()}-specific "
                                    f"payload. The expression '{payload}' was evaluated server-side "
                                    f"and the computed result '{expected}' appeared in the response. "
                                    f"This allows arbitrary code execution in the template context."
                                ),
                                evidence=(
                                    f"Engine: {engine_name} | "
                                    f"Payload: {payload!r} → result: '{expected}' | "
                                    f"Param: {param_name}"
                                ),
                                cwe_id="CWE-94",
                                endpoint=test_url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url_injected)}",
                                rule_id=f"ssti_{rule_suffix}",
                            )]

        return []
