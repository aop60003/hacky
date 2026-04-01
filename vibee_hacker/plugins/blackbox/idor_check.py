# vibee_hacker/plugins/blackbox/idor_check.py
"""BOLA/IDOR detection plugin — enumerates adjacent numeric IDs."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Match a numeric ID segment in the URL path, e.g. /api/users/123
PATH_ID_RE = re.compile(r"(.*/)(\d+)(/.*)?$")


def _substitute_path_id(url: str, new_id: int) -> str | None:
    """Return URL with the last numeric path segment replaced by new_id."""
    parsed = urlparse(url)
    match = PATH_ID_RE.match(parsed.path)
    if not match:
        return None
    prefix, _old_id, suffix = match.group(1), match.group(2), match.group(3) or ""
    new_path = f"{prefix}{new_id}{suffix}"
    return urlunparse(parsed._replace(path=new_path))


def _substitute_param_id(url: str, param: str, new_id: int) -> str:
    """Return URL with the given numeric query parameter replaced by new_id."""
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    params[param] = str(new_id)
    return urlunparse(parsed._replace(query=urlencode(params)))


def _has_numeric_id_in_path(url: str) -> bool:
    return bool(PATH_ID_RE.match(urlparse(url).path))


def _numeric_params(url: str) -> dict[str, int]:
    """Return query params whose values are integers."""
    parsed = urlparse(url)
    result = {}
    for k, v in parse_qs(parsed.query).items():
        try:
            result[k] = int(v[0])
        except (ValueError, IndexError):
            pass
    return result


class IdorCheckPlugin(PluginBase):
    name = "idor_check"
    description = "BOLA/IDOR detection — adjacent numeric ID enumeration"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    detection_criteria = "Adjacent ID returns 200 with different non-empty body"
    expected_evidence = "Different valid response for modified numeric ID in URL"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        # Collect all candidate URLs to check: start URL + crawled URLs with numeric IDs
        candidate_source_urls: list[str] = []

        # Always include target URL if it has a numeric ID
        has_path_id = _has_numeric_id_in_path(target.url)
        numeric_params = _numeric_params(target.url)
        if has_path_id or numeric_params:
            candidate_source_urls.append(target.url)

        # Also include crawled URLs that have numeric path IDs (not already covered)
        if context:
            for crawled_url in (context.crawl_urls or [])[:15]:
                if crawled_url != target.url and _has_numeric_id_in_path(crawled_url):
                    candidate_source_urls.append(crawled_url)

        if not candidate_source_urls:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            for source_url in candidate_source_urls:
                src_has_path_id = _has_numeric_id_in_path(source_url)
                src_numeric_params = _numeric_params(source_url)

                # Baseline: fetch original resource
                try:
                    baseline_resp = await client.get(source_url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                baseline_text = baseline_resp.text
                baseline_status = baseline_resp.status_code

                # Build list of (modified_url, label) candidates to probe
                candidates: list[tuple[str, str]] = []

                if src_has_path_id:
                    parsed_path = PATH_ID_RE.match(urlparse(source_url).path)
                    if parsed_path:
                        orig_id = int(parsed_path.group(2))
                        for delta in (1, -1):
                            new_id = orig_id + delta
                            if new_id < 0:
                                continue
                            new_url = _substitute_path_id(source_url, new_id)
                            if new_url:
                                candidates.append((new_url, f"path id {orig_id}+({delta:+d})={new_id}"))

                for param, orig_id in src_numeric_params.items():
                    for delta in (1, -1):
                        new_id = orig_id + delta
                        if new_id < 0:
                            continue
                        new_url = _substitute_param_id(source_url, param, new_id)
                        candidates.append((new_url, f"param {param!r}: {orig_id}+({delta:+d})={new_id}"))

                for probe_url, label in candidates:
                    try:
                        resp = await client.get(probe_url)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    # Detection: 200 response with non-empty body different from baseline
                    if (
                        resp.status_code == 200
                        and resp.text.strip()
                        and resp.text != baseline_text
                        and baseline_status == 200
                    ):
                        curl_cmd = f"curl {shlex.quote(probe_url)}"
                        return [Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="BOLA/IDOR — Insecure Direct Object Reference",
                            description=(
                                f"Modifying the numeric ID in the URL ({label}) returned a "
                                f"different valid 200 response. This indicates the server does "
                                f"not properly enforce access controls on object references. "
                                f"(Manual verification required - may be a public endpoint)"
                            ),
                            evidence=(
                                f"Original URL: {source_url} → status {baseline_status}\n"
                                f"Modified URL: {probe_url} → status 200, different body"
                            ),
                            cwe_id="CWE-639",
                            endpoint=source_url,
                            curl_command=curl_cmd,
                            rule_id="idor_id_enumeration",
                            confidence="low",
                            recommendation="Verify with authenticated session. Implement server-side access control. Verify user owns the requested resource.",
                        )]

        return []
