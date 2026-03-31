# vibee_hacker/plugins/blackbox/cloud_service_misconfig.py
"""Cloud service misconfiguration detection plugin."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

FIREBASE_RE = re.compile(r"firebaseio\.com", re.I)


def _is_json_data(text: str) -> bool:
    """Return True if response body looks like real data (not an error)."""
    stripped = text.strip()
    if not stripped or stripped in ("null", "false", "[]", "{}"):
        return False
    if '"error"' in stripped.lower() or '"permission denied"' in stripped.lower():
        return False
    return stripped.startswith(("{", "[", '"'))


class CloudServiceMisconfigPlugin(PluginBase):
    name = "cloud_service_misconfig"
    description = (
        "Probe cloud-specific endpoints for misconfigurations: "
        "Firebase .json, Kubernetes dashboard"
    )
    category = "blackbox"
    phase = 1
    base_severity = Severity.CRITICAL
    detection_criteria = (
        "Firebase /.json returns data, "
        "or Kubernetes dashboard open without auth"
    )
    expected_evidence = "Cloud metadata/data returned without authentication"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:

            # --- Firebase: probe {host}/.json ---
            if FIREBASE_RE.search(target.url):
                firebase_url = base.rstrip("/") + "/.json"
                try:
                    resp = await client.get(firebase_url)
                    if resp.status_code == 200 and _is_json_data(resp.text):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="Firebase database publicly readable",
                            description=(
                                f"The Firebase Realtime Database at '{firebase_url}' "
                                f"returned data without authentication. "
                                f"This exposes all stored data to unauthorized users."
                            ),
                            evidence=(
                                f"GET {firebase_url} → {resp.status_code} | "
                                f"Body preview: {resp.text[:200]}"
                            ),
                            recommendation=(
                                "Set Firebase database rules to require authentication. "
                                'Change rules from `".read": true` to require auth.'
                            ),
                            cwe_id="CWE-16",
                            endpoint=firebase_url,
                            curl_command=f"curl -v {shlex.quote(firebase_url)}",
                            rule_id="cloud_misconfig_firebase",
                        ))
                        return results
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    return []

            # --- Kubernetes Dashboard: probe /api/v1/namespaces ---
            k8s_url = base.rstrip("/") + "/api/v1/namespaces"
            try:
                k8s_resp = await client.get(k8s_url)
                if k8s_resp.status_code == 200:
                    body = k8s_resp.text
                    if '"kind"' in body and '"Namespace"' in body:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="Kubernetes API server accessible without authentication",
                            description=(
                                f"The Kubernetes API endpoint '{k8s_url}' returned namespace "
                                f"data without authentication. This allows full cluster control."
                            ),
                            evidence=(
                                f"GET {k8s_url} → {k8s_resp.status_code} | "
                                f"Body preview: {body[:200]}"
                            ),
                            recommendation=(
                                "Enable Kubernetes RBAC and disable anonymous access. "
                                "Do not expose the Kubernetes API server to the internet. "
                                "Rotate all cluster credentials immediately."
                            ),
                            cwe_id="CWE-16",
                            endpoint=k8s_url,
                            curl_command=f"curl -v {shlex.quote(k8s_url)}",
                            rule_id="cloud_misconfig_k8s_dashboard",
                        ))
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                pass

        return results
