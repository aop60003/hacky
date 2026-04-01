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

MAX_PARAMS = 10


class SqliPlugin(PluginBase):
    name = "sqli"
    description = "SQL Injection detection (error-based and time-based blind)"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "SQL error patterns in response after injecting SQL payloads"
    expected_evidence = "SQL syntax error message in HTTP response body"

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Build list of URLs to test: start URL + crawled URLs that have query params
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:20]:
                if crawled_url != target.url and "?" in crawled_url:
                    urls_to_test.append(crawled_url)

        results: list[Result] = []
        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_target_url in urls_to_test:
                parsed = urlparse(test_target_url)
                params = parse_qs(parsed.query)

                if not params:
                    continue

                # Fetch baseline response to compare against
                try:
                    baseline_resp = await client.get(test_target_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Skip patterns that already fire on the baseline (pre-existing errors)
                baseline_matched_patterns = {p for p in SQL_ERROR_PATTERNS if p.search(baseline_resp.text)}

                capped_params = dict(list(params.items())[:MAX_PARAMS])

                # --- GET parameter fuzzing (error-based) ---
                for param_name, values in capped_params.items():
                    original_value = values[0] if values else ""
                    for payload in PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
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
                                    endpoint=test_target_url,
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
                        await client.get(test_target_url)
                        baseline_samples.append(time.monotonic() - t0)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        pass
                baseline_median = statistics.median(baseline_samples) if baseline_samples else 0.0

                for param_name, values in capped_params.items():
                    original_value = values[0] if values else ""
                    for payload in TIME_BASED_PAYLOADS:
                        test_params = {k: v[0] for k, v in capped_params.items()}
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
                                endpoint=test_target_url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url)}",
                                rule_id="sqli_time_based",
                            ))
                            return results  # Stop on first confirmed finding

            # --- POST body fuzzing ---
            # Try POST injection when no GET params exist or GET scan found nothing
            if not results:
                post_fields = ["q", "search", "username", "email", "name", "query", "input"]
                # Also inject into forms discovered by the crawler
                form_fields: list[str] = []
                post_urls: list[str] = [target.url]
                if context and context.crawl_forms:
                    for form in context.crawl_forms:
                        if form.get("method", "get").lower() == "post":
                            form_action = form.get("action", target.url)
                            if form_action not in post_urls:
                                post_urls.append(form_action)
                            for field in form.get("fields", []):
                                fname = field.get("name", "") if isinstance(field, dict) else field
                                if fname and fname not in form_fields:
                                    form_fields.append(fname)

                fields_to_fuzz = form_fields if form_fields else post_fields

                start_parsed = urlparse(target.url)
                start_baseline_matched: set = set()
                try:
                    start_baseline = await client.get(target.url)
                    start_baseline_matched = {p for p in SQL_ERROR_PATTERNS if p.search(start_baseline.text)}
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    pass

                for post_url in post_urls[:5]:
                    # Fetch a POST baseline for this URL to exclude pre-existing errors
                    try:
                        post_baseline = await client.post(post_url, data={})
                        post_baseline_text = post_baseline.text[:1_000_000]
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue
                    post_baseline_matched = {p for p in SQL_ERROR_PATTERNS if p.search(post_baseline_text)}

                    for field in fields_to_fuzz[:MAX_PARAMS]:
                        for payload in PAYLOADS:
                            data = {field: payload}
                            try:
                                resp = await client.post(post_url, data=data, timeout=10)
                            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                                continue

                            if len(resp.text) > 1_000_000:
                                continue

                            for pattern in SQL_ERROR_PATTERNS:
                                if pattern in start_baseline_matched:
                                    continue
                                if pattern in post_baseline_matched:
                                    continue
                                if pattern.search(resp.text):
                                    results.append(Result(
                                        plugin_name=self.name,
                                        base_severity=self.base_severity,
                                        title=f"SQL Injection via POST field '{field}'",
                                        description=f"Error-based SQLi detected with POST payload: {payload}",
                                        evidence=pattern.pattern,
                                        cwe_id="CWE-89",
                                        endpoint=post_url,
                                        param_name=field,
                                        rule_id="sqli_error_based",
                                    ))
                                    return results

        return results
