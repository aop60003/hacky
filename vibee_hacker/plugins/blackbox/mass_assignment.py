# vibee_hacker/plugins/blackbox/mass_assignment.py
"""Mass assignment vulnerability detection plugin."""

from __future__ import annotations

import json
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

BASELINE_PAYLOAD = {"name": "test", "email": "test@example.com"}

MASS_ASSIGN_EXTRA_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "price": 0,
    "admin": True,
    "superuser": True,
}

# Fields we look for in the response that indicate mass assignment
SENSITIVE_FIELDS = ["role", "is_admin", "admin", "superuser", "price"]


class MassAssignmentPlugin(PluginBase):
    name = "mass_assignment"
    description = "Detect mass assignment vulnerabilities by checking if extra fields are reflected in responses"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Extra privilege-escalating fields sent in POST body appear in response JSON"
    expected_evidence = "Sensitive fields like role=admin or is_admin=true reflected in API response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        mass_payload = {**BASELINE_PAYLOAD, **MASS_ASSIGN_EXTRA_FIELDS}

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Fetch baseline response
            try:
                baseline_resp = await client.post(
                    target.url,
                    json=BASELINE_PAYLOAD,
                    headers={"Content-Type": "application/json"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            # Try mass assignment payload
            try:
                resp = await client.post(
                    target.url,
                    json=mass_payload,
                    headers={"Content-Type": "application/json"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) > 1_000_000:
                return []

            baseline_body = baseline_resp.text
            mass_body = resp.text

            # Check if any sensitive field appears in mass response but not in baseline
            for field in SENSITIVE_FIELDS:
                field_in_baseline = f'"{field}"' in baseline_body
                field_in_mass = f'"{field}"' in mass_body

                if field_in_mass and not field_in_baseline:
                    payload_str = json.dumps(mass_payload)
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title="Mass assignment vulnerability detected",
                        description=(
                            f"The application appears to accept and reflect extra fields in POST requests. "
                            f"Field '{field}' was not present in the baseline response but appeared after "
                            f"sending a payload with privilege-escalating fields."
                        ),
                        evidence=f"Field '{field}' reflected in response after mass assignment payload",
                        cwe_id="CWE-915",
                        endpoint=target.url,
                        curl_command=(
                            f"curl -X POST {shlex.quote(target.url)} "
                            f"-H 'Content-Type: application/json' "
                            f"-d {shlex.quote(payload_str)}"
                        ),
                        rule_id="mass_assignment",
                    ))
                    return results  # Stop on first confirmed finding

        return results
