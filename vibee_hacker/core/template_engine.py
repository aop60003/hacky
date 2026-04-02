"""YAML template engine for custom vulnerability detection rules."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import yaml
import httpx

from vibee_hacker.core.models import Result, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class Template:
    """Parsed YAML template."""
    id: str
    name: str
    severity: Severity
    description: str
    cwe: str = ""
    tags: list[str] = field(default_factory=list)
    requests: list[dict] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, data: dict) -> Template:
        info = data.get("info", {})
        return cls(
            id=data.get("id", "unknown"),
            name=info.get("name", "Unknown"),
            severity=SEVERITY_MAP.get(info.get("severity", "info"), Severity.INFO),
            description=info.get("description", ""),
            cwe=info.get("cwe", ""),
            tags=info.get("tags", []),
            requests=data.get("requests", []),
        )


class TemplateEngine:
    """Loads and executes YAML-based vulnerability templates."""

    def __init__(self, template_dir: str | Path | None = None):
        self.templates: list[Template] = []
        if template_dir:
            self.load_directory(Path(template_dir))

    def load_directory(self, path: Path) -> int:
        """Load all YAML templates from a directory. Returns count loaded."""
        count = 0
        if not path.is_dir():
            return 0
        for f in sorted(path.glob("*.yaml")):
            try:
                self.load_file(f)
                count += 1
            except Exception as e:
                logger.warning("Failed to load template %s: %s", f, e)
        return count

    def load_file(self, path: Path) -> Template:
        """Load a single YAML template file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        template = Template.from_yaml(data)
        self.templates.append(template)
        return template

    def load_string(self, yaml_str: str) -> Template:
        """Load a template from a YAML string."""
        data = yaml.safe_load(yaml_str)
        template = Template.from_yaml(data)
        self.templates.append(template)
        return template

    async def execute(self, target_url: str, verify_ssl: bool = True, timeout: int = 10) -> list[Result]:
        """Execute all loaded templates against a target URL."""
        results = []
        async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
            for template in self.templates:
                try:
                    template_results = await self._execute_template(client, template, target_url)
                    results.extend(template_results)
                except Exception as e:
                    logger.warning("Template %s failed: %s", template.id, e)
        return results

    async def _execute_template(self, client: httpx.AsyncClient, template: Template, target_url: str) -> list[Result]:
        """Execute a single template against the target."""
        results = []

        for req_spec in template.requests:
            method = req_spec.get("method", "GET").upper()
            path = req_spec.get("path", "{{BaseURL}}")
            matchers = req_spec.get("matchers", [])
            payloads = req_spec.get("payloads", {})

            # Resolve URL
            url = path.replace("{{BaseURL}}", target_url)

            # Get payload lists
            param_values = payloads.get("param_values", [])

            if param_values:
                # Fuzz each parameter with each payload
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                if not params:
                    # No params in URL, try appending payloads as raw query
                    for payload in param_values:
                        test_url = f"{url}?test={payload}" if "?" not in url else f"{url}&test={payload}"
                        matched = await self._send_and_match(client, method, test_url, None, matchers)
                        if matched:
                            results.append(self._create_result(template, test_url, "test", payload))
                            return results
                else:
                    for param_name in params:
                        for payload in param_values:
                            new_params = dict(params)
                            new_params[param_name] = [payload]
                            new_query = urlencode(new_params, doseq=True)
                            test_url = parsed._replace(query=new_query).geturl()
                            matched = await self._send_and_match(client, method, test_url, None, matchers)
                            if matched:
                                results.append(self._create_result(template, test_url, param_name, payload))
                                return results
            else:
                # No payloads, just check the URL directly
                matched = await self._send_and_match(client, method, url, None, matchers)
                if matched:
                    results.append(self._create_result(template, url, "", ""))

        return results

    async def _send_and_match(self, client, method, url, body, matchers) -> bool:
        """Send request and check all matchers."""
        try:
            if method == "GET":
                resp = await client.get(url)
            elif method == "POST":
                resp = await client.post(url, data=body)
            else:
                resp = await client.request(method, url)
        except (httpx.TransportError, httpx.InvalidURL):
            return False

        for matcher in matchers:
            if not self._check_matcher(resp, matcher):
                return False
        return len(matchers) > 0

    def _check_matcher(self, resp: httpx.Response, matcher: dict) -> bool:
        """Check if a response matches a matcher definition."""
        matcher_type = matcher.get("type", "")
        condition = matcher.get("condition", "and")

        if matcher_type == "word":
            words = matcher.get("words", [])
            text = resp.text.lower()
            if condition == "or":
                return any(w.lower() in text for w in words)
            return all(w.lower() in text for w in words)

        elif matcher_type == "status":
            statuses = matcher.get("status", [])
            return resp.status_code in statuses

        elif matcher_type == "regex":
            patterns = matcher.get("regex", [])
            text = resp.text
            if condition == "or":
                return any(re.search(p, text) for p in patterns)
            return all(re.search(p, text) for p in patterns)

        elif matcher_type == "header":
            headers = matcher.get("headers", {})
            for key, value in headers.items():
                if key.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                    return False
                if value and value.lower() not in resp.headers.get(key, "").lower():
                    return False
            return True

        return False

    def _create_result(self, template: Template, url: str, param: str, payload: str) -> Result:
        """Create a Result from a matched template."""
        return Result(
            plugin_name=f"template:{template.id}",
            base_severity=template.severity,
            title=template.name,
            description=template.description,
            evidence=f"Payload: {payload}" if payload else "Matched",
            cwe_id=template.cwe,
            endpoint=url,
            param_name=param if param else None,
            rule_id=template.id,
            recommendation="Review and fix the identified vulnerability.",
        )
