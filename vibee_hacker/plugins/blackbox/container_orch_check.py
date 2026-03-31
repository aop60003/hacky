# vibee_hacker/plugins/blackbox/container_orch_check.py
"""Container orchestration API exposure detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Container orchestration endpoints to probe
CONTAINER_ENDPOINTS = [
    {"name": "Docker API (2375)", "url": "http://{host}:2375/version", "service": "Docker"},
    {"name": "Docker API TLS (2376)", "url": "http://{host}:2376/version", "service": "Docker"},
    {"name": "kubelet (10250)", "url": "http://{host}:10250/pods", "service": "kubelet"},
    {"name": "etcd (2379)", "url": "http://{host}:2379/version", "service": "etcd"},
    {"name": "cAdvisor (8080)", "url": "http://{host}:8080/containers/", "service": "cAdvisor"},
]


def _host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""


class ContainerOrchCheckPlugin(PluginBase):
    name = "container_orch_check"
    description = "Probe container orchestration APIs (Docker, kubelet, etcd, cAdvisor) for unauthenticated access"
    category = "blackbox"
    phase = 1
    base_severity = Severity.CRITICAL
    detection_criteria = "Container orchestration API endpoint returns 200 with version/pod/container data"
    expected_evidence = "HTTP 200 response from Docker API, kubelet, etcd, or cAdvisor endpoint"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        host = _host(target.url)
        if not host:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            for endpoint_def in CONTAINER_ENDPOINTS:
                url = endpoint_def["url"].format(host=host)
                try:
                    resp = await client.get(url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if resp.status_code == 200:
                    service = endpoint_def["service"]
                    name = endpoint_def["name"]
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Container orchestration API exposed: {name}",
                        description=(
                            f"The {service} API at {url} is accessible without authentication. "
                            f"This allows full container management, including executing commands "
                            f"in containers and accessing secrets."
                        ),
                        evidence=(
                            f"Service: {name} | URL: {url} | "
                            f"Status: {resp.status_code} | "
                            f"Response: {resp.text[:200]}"
                        ),
                        cwe_id="CWE-284",
                        endpoint=url,
                        curl_command=f"curl -v {shlex.quote(url)}",
                        rule_id="container_api_exposed",
                    ))
                    return results  # Report first finding

        return results
