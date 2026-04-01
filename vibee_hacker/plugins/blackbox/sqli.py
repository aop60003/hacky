# vibee_hacker/plugins/blackbox/sqli.py
"""SQL Injection detection plugin (error-based and time-based blind)."""

from __future__ import annotations

import re
import shlex
import statistics
import time
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

TIME_BASED_PAYLOADS = [
    "' OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
]
TIME_BASED_EXTRA_MARGIN = 2.5  # flag if response is >2.5s slower than baseline median


class SqliPlugin(PluginBase):
    name = "sqli"
    description = "SQL Injection detection (error-based and time-based blind)"
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
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
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
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
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

            # --- Time-based blind SQLi detection ---
            # Measure baseline 3 times and use the median for a stable reference
            baseline_samples: list[float] = []
            for _ in range(3):
                try:
                    t0 = time.monotonic()
                    await client.get(target.url)
                    baseline_samples.append(time.monotonic() - t0)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    pass
            baseline_median = statistics.median(baseline_samples) if baseline_samples else 0.0

            for param_name, values in params.items():
                original_value = values[0] if values else ""
                for payload in TIME_BASED_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = original_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        t_start = time.monotonic()
                        resp = await client.get(test_url, timeout=15)
                        elapsed = time.monotonic() - t_start
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    delay = elapsed - baseline_median
                    if delay > TIME_BASED_EXTRA_MARGIN:
                        # Confirmation request: only report if second attempt is also slow
                        try:
                            t_confirm = time.monotonic()
                            await client.get(test_url, timeout=15)
                            confirm_elapsed = time.monotonic() - t_confirm
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        confirm_delay = confirm_elapsed - baseline_median
                        if confirm_delay <= TIME_BASED_EXTRA_MARGIN:
                            continue  # First hit was a fluke; skip

                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Time-Based Blind SQL Injection in parameter '{param_name}'",
                            description=(
                                f"Time-based blind SQLi detected with payload: {payload}. "
                                f"Response delayed {delay:.1f}s above baseline median {baseline_median:.2f}s "
                                f"(confirmed: {confirm_elapsed:.2f}s)."
                            ),
                            evidence=(
                                f"Response time: {elapsed:.2f}s, baseline median: {baseline_median:.2f}s, "
                                f"delay: {delay:.2f}s, confirmation delay: {confirm_delay:.2f}s"
                            ),
                            cwe_id="CWE-89",
                            endpoint=target.url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(test_url)}",
                            rule_id="sqli_time_based",
                        ))
                        return results  # Stop on first confirmed finding

        return results
