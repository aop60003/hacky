# vibee_hacker/plugins/blackbox/xpath_injection.py
"""XPath injection detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

PAYLOADS = [
    "' or '1'='1",
    "1 or 1=1",
    "'] | //*/text()[",
    "' or ''='",
    "x' or name()='username' or 'x'='y",
]

XPATH_ERROR_PATTERNS = [
    re.compile(r"XPath", re.I),
    re.compile(r"XPATH", re.I),
    re.compile(r"SimpleXMLElement", re.I),
    re.compile(r"xmlXPathEval", re.I),
    re.compile(r"XPathException", re.I),
    re.compile(r"xpath.*error", re.I),
    re.compile(r"Invalid XPath"),
]


class XpathInjectionPlugin(PluginBase):
    name = "xpath_injection"
    description = "Detect XPath injection vulnerabilities via URL parameter fuzzing"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Response contains XPath error indicators after injection payload"
    expected_evidence = "XPath error string (xmlXPathEval, XPathException, etc.) in response body"
    destructive_level = 1

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for param_name in list(params.keys()):
                for payload in PAYLOADS:
                    # Replace only the target param with payload
                    injected_params = dict(params)
                    injected_params[param_name] = [payload]
                    new_query = urlencode(injected_params, doseq=True)
                    injected_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        resp = await client.get(injected_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    for error_pattern in XPATH_ERROR_PATTERNS:
                        if error_pattern.search(resp.text):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title="XPath injection vulnerability detected",
                                description=(
                                    f"The parameter '{param_name}' at {target.url} is vulnerable to "
                                    f"XPath injection. The application returned an XPath error message "
                                    f"when injected with a malicious payload."
                                ),
                                evidence=(
                                    f"Parameter: {param_name} | "
                                    f"Payload: {payload} | "
                                    f"Pattern: {error_pattern.pattern} | "
                                    f"Status: {resp.status_code} | "
                                    f"Snippet: {resp.text[:200]}"
                                ),
                                recommendation=(
                                    "Use parameterized XPath queries or an XPath library that supports "
                                    "variable binding. Never concatenate user input into XPath expressions."
                                ),
                                cwe_id="CWE-643",
                                endpoint=injected_url,
                                param_name=param_name,
                                curl_command=f"curl -s {shlex.quote(injected_url)}",
                                rule_id="xpath_injection",
                            ))
                            return results  # Stop on first finding

        return results
