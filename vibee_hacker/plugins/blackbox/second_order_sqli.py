"""Plugin: Second-Order SQL Injection Detection (blackbox)."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Payloads to store in first-stage forms
SQLI_PAYLOADS = [
    "vibee'--",
    "vibee' OR '1'='1",
    "vibee'; SELECT SLEEP(0)--",
    "vibee\"; SELECT 1--",
]

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "unclosed quotation",
    "you have an error in your sql",
    "ora-",
    "pg::syntaxerror",
    "unterminated string",
    "syntax error",
    "mysql_fetch",
    "odbc driver",
    "microsoft ole db",
    "jdbc",
    "sqlstate",
]

REGISTRATION_PATHS = [
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/user/register",
    "/account/register",
    "/api/users",
]

RETRIEVAL_PATHS = [
    "/profile",
    "/admin",
    "/admin/users",
    "/search",
    "/api/users",
    "/api/profile",
    "/user/profile",
    "/account",
]


class SecondOrderSqliPlugin(PluginBase):
    name = "second_order_sqli"
    description = "Detect second-order SQL injection by submitting payloads in registration then retrieving in admin/search"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=True) as client:
            # Phase 1: Submit payloads via registration/profile forms
            for reg_path in REGISTRATION_PATHS:
                reg_endpoint = base + reg_path

                for payload in SQLI_PAYLOADS:
                    # Try to store payload in various field types
                    for field_combo in [
                        {"username": payload, "password": "Vibee@123!", "email": "vibee@test.com"},
                        {"name": payload, "email": "vibee@test.com"},
                        {"user": payload, "pass": "Vibee@123!"},
                    ]:
                        try:
                            store_resp = await client.post(reg_endpoint, data=field_combo, timeout=8)
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            continue

                        if store_resp.status_code == 404:
                            break  # endpoint doesn't exist, try next

                        # Phase 2: Check retrieval endpoints for SQL errors
                        for ret_path in RETRIEVAL_PATHS:
                            ret_endpoint = base + ret_path

                            try:
                                ret_resp = await client.get(ret_endpoint, timeout=8)
                            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                                continue

                            if ret_resp.status_code == 404:
                                continue

                            body_lower = ret_resp.text[:5000].lower()

                            for error in SQL_ERROR_PATTERNS:
                                if error in body_lower:
                                    results.append(
                                        Result(
                                            plugin_name=self.name,
                                            base_severity=Severity.CRITICAL,
                                            title="Second-Order SQL Injection",
                                            description=(
                                                f"SQL injection payload stored via {reg_endpoint} "
                                                f"triggered a SQL error when retrieved from {ret_endpoint}. "
                                                "The application stores user input without sanitization and "
                                                "later uses it in SQL queries without parameterization."
                                            ),
                                            evidence=(
                                                f"1. POST {reg_endpoint} payload={payload[:40]!r} → {store_resp.status_code}\n"
                                                f"2. GET {ret_endpoint} → {ret_resp.status_code}: SQL error '{error}' in response"
                                            ),
                                            recommendation=(
                                                "Use parameterized queries (prepared statements) whenever stored user data "
                                                "is used in SQL queries. Never concatenate user-controlled data into SQL strings, "
                                                "even if it was previously sanitized on input."
                                            ),
                                            cwe_id="CWE-89",
                                            rule_id="second_order_sqli",
                                            endpoint=reg_endpoint,
                                        )
                                    )
                                    return results

        return results
