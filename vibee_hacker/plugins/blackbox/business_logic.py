# vibee_hacker/plugins/blackbox/business_logic.py
"""Business logic flaw detection plugin via negative/zero value manipulation."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

NUMERIC_VALUE_RE = re.compile(r"^\d+(\.\d+)?$")

# Manipulation payloads: (label, value)
MANIPULATION_PAYLOADS = [
    ("negative", -1),
    ("negative_large", -100),
    ("zero", 0),
]

# Also test JSON POST body field names
COMMON_NUMERIC_FIELDS = ["price", "quantity", "amount", "total", "count", "fee"]


class BusinessLogicPlugin(PluginBase):
    name = "business_logic"
    description = "Detect business logic flaws via negative and zero value manipulation in numeric parameters"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Server returns 200 OK when negative or zero values are supplied for numeric parameters"
    expected_evidence = "200 OK response after submitting price=-1 or quantity=0"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)

        # Find numeric parameters
        numeric_params = {
            k: v[0] for k, v in params.items()
            if v and NUMERIC_VALUE_RE.match(v[0])
        }

        if not numeric_params:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for param_name, original_value in numeric_params.items():
                for label, evil_value in MANIPULATION_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = str(evil_value)
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    try:
                        resp = await client.get(test_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code == 200:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Business logic flaw: {label} value accepted for '{param_name}'",
                            description=(
                                f"The server accepted a {label} value ({evil_value}) for parameter "
                                f"'{param_name}' (original: {original_value}) and returned HTTP 200. "
                                f"This may allow price manipulation, free orders, or account credit abuse."
                            ),
                            evidence=(
                                f"Parameter '{param_name}' = {evil_value} | "
                                f"Status: {resp.status_code} | Original: {original_value}"
                            ),
                            recommendation=(
                                "Validate all numeric inputs server-side. "
                                "Reject negative values and zero for price, quantity, and amount fields. "
                                "Implement business rule validation beyond basic type checking."
                            ),
                            cwe_id="CWE-840",
                            endpoint=test_url,
                            param_name=param_name,
                            curl_command=f"curl {shlex.quote(test_url)}",
                            rule_id="business_logic_flaw",
                        ))
                        return results  # Stop at first confirmed finding

        return results
