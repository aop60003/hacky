# vibee_hacker/plugins/blackbox/subdomain_takeover_poc.py
"""Subdomain takeover PoC confirmation plugin."""

from __future__ import annotations

import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Service-specific takeover confirmation patterns
TAKEOVER_CONFIRMATIONS = [
    (re.compile(r"NoSuchBucket", re.I), "AWS S3"),
    (re.compile(r"There isn't a GitHub Pages site here", re.I), "GitHub Pages"),
    (re.compile(r"Fastly error:\s*unknown domain", re.I), "Fastly CDN"),
    (re.compile(r"is not a registered IngressPoint", re.I), "AWS CloudFront"),
    (re.compile(r"herokucdn\.com/error-pages", re.I), "Heroku"),
    (re.compile(r"This UserVoice subdomain is either invalid", re.I), "UserVoice"),
    (re.compile(r"project not found", re.I), "GitLab Pages"),
    (re.compile(r"Branch not found", re.I), "Netlify"),
]


class SubdomainTakeoverPocPlugin(PluginBase):
    name = "subdomain_takeover_poc"
    description = "Confirm subdomain takeover by probing dangling CNAME targets for service-specific errors"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Dangling CNAME target returns service-specific unclaimed subdomain error"
    expected_evidence = "Takeover-confirming signature in CNAME target response"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if context is None or not context.dangling_cnames:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for cname in context.dangling_cnames:
                # Build probe URL for the CNAME target
                if not cname.startswith("http"):
                    probe_url = f"http://{cname}/"
                else:
                    probe_url = cname

                try:
                    resp = await client.get(probe_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                body = resp.text[:500_000]
                for pattern, service_name in TAKEOVER_CONFIRMATIONS:
                    if pattern.search(body):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Subdomain takeover confirmed: {service_name} ({cname})",
                            description=(
                                f"The dangling CNAME target {cname} returned a "
                                f"{service_name} unclaimed service error. "
                                f"An attacker can register this service name and serve "
                                f"malicious content under the original subdomain."
                            ),
                            evidence=(
                                f"CNAME target: {cname} | Service: {service_name} | "
                                f"Status: {resp.status_code} | "
                                f"Pattern: {pattern.pattern[:60]}"
                            ),
                            cwe_id="CWE-284",
                            endpoint=probe_url,
                            curl_command=f"curl -v {shlex.quote(probe_url)}",
                            rule_id="subdomain_takeover_confirmed",
                        ))
                        break

        return results
