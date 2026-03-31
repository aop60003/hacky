# vibee_hacker/plugins/blackbox/dangling_dns.py
"""Dangling DNS / subdomain takeover signature detection plugin."""

from __future__ import annotations

import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Known subdomain takeover service signatures
TAKEOVER_SIGNATURES = [
    (re.compile(r"There isn't a GitHub Pages site here", re.I), "GitHub Pages"),
    (re.compile(r"NoSuchBucket", re.I), "AWS S3"),
    (re.compile(r"Fastly error:\s*unknown domain", re.I), "Fastly CDN"),
    (re.compile(r"is not a registered IngressPoint", re.I), "AWS CloudFront"),
    (re.compile(r"herokucdn\.com/error-pages", re.I), "Heroku"),
    (re.compile(r"The requested URL was not found on this server.*Bitbucket", re.I), "Bitbucket"),
    (re.compile(r"This UserVoice subdomain is either invalid", re.I), "UserVoice"),
    (re.compile(r"project not found", re.I), "GitLab Pages"),
    (re.compile(r"Branch not found", re.I), "Netlify"),
    (re.compile(r"404 Not Found.*Pantheon", re.I), "Pantheon"),
]


class DanglingDnsPlugin(PluginBase):
    name = "dangling_dns"
    description = "Detect subdomain takeover indicators by checking for service-specific error signatures"
    category = "blackbox"
    phase = 2
    base_severity = Severity.HIGH
    detection_criteria = "Target response body contains known subdomain takeover service signature"
    expected_evidence = "Takeover signature pattern found in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            body = resp.text[:500_000]
            for pattern, service_name in TAKEOVER_SIGNATURES:
                if pattern.search(body):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Dangling DNS — potential {service_name} subdomain takeover",
                        description=(
                            f"The target {target.url} returned a response matching the "
                            f"{service_name} unclaimed subdomain error signature. "
                            f"An attacker may be able to register this service and take control "
                            f"of the subdomain."
                        ),
                        evidence=(
                            f"URL: {target.url} | Status: {resp.status_code} | "
                            f"Service: {service_name} | Pattern: {pattern.pattern[:60]}"
                        ),
                        cwe_id="CWE-284",
                        endpoint=target.url,
                        curl_command=f"curl -v {shlex.quote(target.url)}",
                        rule_id="dangling_dns_takeover",
                    ))
                    break  # One finding per target

        # Store any found dangling targets in context for subdomain_takeover_poc
        if results and context is not None:
            parsed_host = target.url.split("//")[-1].split("/")[0]
            if parsed_host not in context.dangling_cnames:
                context.dangling_cnames.append(parsed_host)

        return results
