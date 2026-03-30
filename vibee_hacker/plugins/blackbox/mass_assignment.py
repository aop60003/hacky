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

            # Try to parse both responses as JSON for accurate value comparison
            try:
                baseline_json = json.loads(baseline_body)
            except (json.JSONDecodeError, ValueError):
                baseline_json = None

            try:
                mass_json = json.loads(mass_body)
            except (json.JSONDecodeError, ValueError):
                mass_json = None

            # Check if any injected sensitive field VALUE appears in mass response but not baseline
            for field in SENSITIVE_FIELDS:
                injected_value = MASS_ASSIGN_EXTRA_FIELDS.get(field)

                if baseline_json is not None and mass_json is not None:
                    # JSON comparison: field must be present with the injected value in mass response
                    # but either absent or with a different value in baseline
                    mass_field_value = mass_json.get(field) if isinstance(mass_json, dict) else None
                    baseline_field_value = baseline_json.get(field) if isinstance(baseline_json, dict) else None
                    field_reflected = (
                        mass_field_value == injected_value
                        and baseline_field_value != injected_value
                    )
                else:
                    # Fallback to text-based value search when JSON parsing fails
                    injected_value_str = (
                        json.dumps(injected_value) if not isinstance(injected_value, str)
                        else f'"{injected_value}"'
                    )
                    field_key = f'"{field}"'
                    field_reflected = (
                        field_key in mass_body and injected_value_str in mass_body
                        and not (field_key in baseline_body and injected_value_str in baseline_body)
                    )

                if field_reflected:
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
