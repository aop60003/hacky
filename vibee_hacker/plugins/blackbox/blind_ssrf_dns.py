# vibee_hacker/plugins/blackbox/blind_ssrf_dns.py
"""Blind SSRF via DNS callback detection plugin."""

from __future__ import annotations

import shlex
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# OOB callback domain — in production this would be a controlled burp collaborator / interactsh domain
OOB_DOMAIN = "oob.vibee-scanner.internal"

# Parameter names commonly used for URL/callback inputs
URL_PARAM_NAMES = [
    "url", "uri", "href", "src", "source", "dest", "destination",
    "redirect", "target", "host", "site", "callback", "webhook",
    "endpoint", "path", "next", "return", "returnUrl", "return_url",
    "fetch", "load", "proxy", "image", "img", "file",
]

MAX_PARAMS = 15

# Probe paths that commonly accept URL parameters
PROBE_PATHS = [
    "/api/fetch",
    "/api/proxy",
    "/api/preview",
    "/webhook",
    "/callback",
    "/redirect",
]


def _make_oob_url(unique_id: str) -> str:
    return f"http://{unique_id}.{OOB_DOMAIN}/"


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class BlindSsrfDnsPlugin(PluginBase):
    name = "blind_ssrf_dns"
    description = (
        "Blind SSRF via DNS — inject unique OOB subdomains into URL parameters "
        "to detect server-side request forgery via DNS callbacks"
    )
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    destructive_level = 1
    detection_criteria = (
        "Server returns 200 or makes an apparent fetch after receiving an OOB URL payload "
        "in a URL-type parameter (DNS callback verification is heuristic in passive mode)"
    )
    expected_evidence = "OOB URL injected into URL parameter; server responded with 200 to probe"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)
        results: list[Result] = []

        # Collect (url, param_name) test cases
        test_cases: list[tuple[str, str, bool]] = []  # (url, param_name, is_query_param)

        # From existing query params in target URL
        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        for param_name in list(params.keys())[:MAX_PARAMS]:
            if param_name.lower() in URL_PARAM_NAMES:
                test_cases.append((target.url, param_name, True))

        # From crawled URLs
        if context:
            for crawled_url in (context.crawl_urls or [])[:10]:
                c_parsed = urlparse(crawled_url)
                c_params = parse_qs(c_parsed.query)
                for param_name in list(c_params.keys())[:MAX_PARAMS]:
                    if param_name.lower() in URL_PARAM_NAMES:
                        test_cases.append((crawled_url, param_name, True))

        # Probe paths with common URL param names
        for probe_path in PROBE_PATHS:
            probe_url = base + probe_path
            for param_name in URL_PARAM_NAMES[:5]:
                test_cases.append((probe_url, param_name, True))

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for test_url, param_name, is_query in test_cases:
                unique_id = uuid.uuid4().hex[:12]
                oob_url = _make_oob_url(unique_id)

                if is_query:
                    t_parsed = urlparse(test_url)
                    t_params = {k: v[0] for k, v in parse_qs(t_parsed.query).items()}
                    t_params[param_name] = oob_url
                    injected_url = urlunparse(t_parsed._replace(query=urlencode(t_params)))
                else:
                    injected_url = test_url

                try:
                    resp = await client.get(injected_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                # Heuristic: if the server accepted the request (200) and the body
                # contains our OOB domain or the unique ID, that indicates the server
                # may have fetched the URL (or at minimum echoed it back).
                body = resp.text
                if resp.status_code == 200 and (unique_id in body or OOB_DOMAIN in body):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=self.base_severity,
                        title=f"Blind SSRF (DNS) candidate in parameter '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' accepted an external URL payload "
                            f"({oob_url}) and the server returned a 200 response with the OOB "
                            f"domain reflected in the body. In a real assessment, verify DNS "
                            f"callback using an Interactsh/Burp Collaborator server."
                        ),
                        evidence=(
                            f"OOB URL injected: {oob_url} | "
                            f"Response reflected unique ID '{unique_id}' | "
                            f"Status: {resp.status_code}"
                        ),
                        cwe_id="CWE-918",
                        endpoint=test_url,
                        param_name=param_name,
                        curl_command=f"curl {shlex.quote(injected_url)}",
                        rule_id="blind_ssrf_dns",
                    ))
                    return results

        return results
