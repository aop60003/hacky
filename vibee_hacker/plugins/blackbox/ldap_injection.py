# vibee_hacker/plugins/blackbox/ldap_injection.py
"""LDAP injection detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

PAYLOADS = [
    ")(cn=*)",
    "*)(uid=*))(|(uid=*",
    "*()|&'",
]

LDAP_ERROR_PATTERNS = [
    re.compile(r"LDAP", re.I),
    re.compile(r"InvalidDN", re.I),
    re.compile(r"Bad search filter", re.I),
    re.compile(r"ldap_search", re.I),
    re.compile(r"javax\.naming", re.I),
]


class LdapInjectionPlugin(PluginBase):
    name = "ldap_injection"
    description = "Detect LDAP injection via filter payload injection in URL parameters"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "LDAP error strings in response after injecting LDAP filter payloads"
    expected_evidence = "LDAP error message (LDAP, InvalidDN, Bad search filter, ldap_search, javax.naming) in HTTP response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
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

                    if len(resp.text) > 1_000_000:
                        continue

                    for pattern in LDAP_ERROR_PATTERNS:
                        if pattern.search(resp.text):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=self.base_severity,
                                title=f"LDAP Injection in parameter '{param_name}'",
                                description=(
                                    f"LDAP error detected after injecting payload '{payload}' "
                                    f"into parameter '{param_name}'. The server may be vulnerable "
                                    f"to LDAP injection attacks."
                                ),
                                evidence=f"Pattern '{pattern.pattern}' matched in response | Payload: {payload}",
                                recommendation=(
                                    "Validate and escape all user input before using in LDAP queries. "
                                    "Use parameterized LDAP queries or a safe LDAP API."
                                ),
                                cwe_id="CWE-90",
                                endpoint=target.url,
                                param_name=param_name,
                                curl_command=f"curl {shlex.quote(test_url)}",
                                rule_id="ldap_injection",
                            ))
                            return results

        return results
