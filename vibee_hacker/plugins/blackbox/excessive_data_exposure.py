# vibee_hacker/plugins/blackbox/excessive_data_exposure.py
"""Excessive data exposure detection plugin."""

from __future__ import annotations

import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Sensitive field names that should not appear in API responses
SENSITIVE_FIELDS = [
    "password",
    "passwd",
    "hash",
    "salt",
    "secret",
    "internal_id",
    "_id",
    "__v",
    "ssn",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "pin",
    "private_key",
    "api_key",
    "access_token",
    "refresh_token",
]


def _flatten_keys(obj: object, depth: int = 0) -> list[str]:
    """Recursively extract all keys from a JSON object."""
    if depth > 10:
        return []
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(str(k).lower())
            keys.extend(_flatten_keys(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj[:20]:  # Limit list iteration
            keys.extend(_flatten_keys(item, depth + 1))
    return keys


class ExcessiveDataExposurePlugin(PluginBase):
    name = "excessive_data_exposure"
    description = "Detect sensitive fields leaked in API JSON responses"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "JSON response contains sensitive field names (password, hash, secret, etc.)"
    expected_evidence = "Sensitive field name found in JSON response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if resp.status_code not in range(200, 300):
                return []

            content_type = resp.headers.get("content-type", "")
            if "application/json" not in content_type:
                return []

            if len(resp.text) > 1_000_000:
                return []

            try:
                data = resp.json()
            except Exception:
                return []

            all_keys = _flatten_keys(data)
            found_fields = [f for f in SENSITIVE_FIELDS if f in all_keys]

            if found_fields:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title="Sensitive fields exposed in API response",
                    description=(
                        f"The API endpoint {target.url} returns JSON responses containing "
                        f"sensitive field names: {', '.join(found_fields)}. "
                        f"This may expose credentials, internal identifiers, or private data."
                    ),
                    evidence=(
                        f"Sensitive fields found in response: {', '.join(found_fields)}"
                    ),
                    recommendation=(
                        "Apply response filtering to remove sensitive fields before returning data. "
                        "Use DTOs/serializers that explicitly whitelist allowed fields."
                    ),
                    cwe_id="CWE-213",
                    endpoint=target.url,
                    curl_command=f"curl -s {shlex.quote(target.url)}",
                    rule_id="excessive_data_exposure",
                ))

        return results
