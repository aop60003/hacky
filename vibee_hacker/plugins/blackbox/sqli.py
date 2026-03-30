# vibee_hacker/plugins/blackbox/sqli.py
"""SQL Injection detection plugin (error-based)."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sql syntax.*error", re.I),
    re.compile(r"microsoft.*odbc.*driver", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"pg_query\(\).*failed", re.I),
]

PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND '1'='2", "1; SELECT 1--"]


class SqliPlugin(PluginBase):
    name = "sqli"
    description = "SQL Injection detection (error-based)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "SQL error patterns in response after injecting SQL payloads"
    expected_evidence = "SQL syntax error message in HTTP response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        MAX_PARAMS = 10
        if len(params) > MAX_PARAMS:
            params = dict(list(params.items())[:MAX_PARAMS])

        results = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch baseline response to compare against
            try:
                baseline_resp = await client.get(target.url)
            except httpx.TransportError:
                return []

            # Skip patterns that already fire on the baseline (pre-existing errors)
            baseline_matched_patterns = {p for p in SQL_ERROR_PATTERNS if p.search(baseline_resp.text)}

            for param_name, values in params.items():
                original_value = values[0] if values else ""
                for payload in PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except httpx.TransportError:
                        continue

                    if len(resp.text) > 1_000_000:  # 1MB max response
                        continue

                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern in baseline_matched_patterns:
                            continue
                        if pattern.search(resp.text):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"SQL Injection in parameter '{param_name}'",
                                description=f"Error-based SQLi detected with payload: {payload}",
                                evidence=pattern.pattern,
                                cwe_id="CWE-89",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url)}",
                                rule_id="sqli_error_based",
                            ))
                            return results  # Stop on first confirmed finding

        return results
