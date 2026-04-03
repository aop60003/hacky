"""Business logic vulnerability detection."""

from __future__ import annotations

import re
import json
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from vibee_hacker.core.plugin_base import PluginBase
from vibee_hacker.core.models import Result, Severity, Target

# Patterns indicating price/quantity/amount fields
NUMERIC_PARAMS = ["price", "amount", "total", "quantity", "qty", "count", "discount", "cost", "fee", "rate", "credits", "points", "balance"]
ROLE_PARAMS = ["role", "admin", "is_admin", "user_type", "privilege", "level", "group", "permission"]
STATE_PARAMS = ["status", "state", "step", "stage", "phase", "approved", "verified", "confirmed"]


class BusinessLogicPlugin(PluginBase):
    name = "business_logic"
    description = "Detect business logic vulnerabilities: price tampering, privilege escalation, workflow bypass"
    category = "blackbox"
    phase = 3
    destructive_level = 1

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context=None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        urls_to_test = [target.url]

        if context:
            for url in (getattr(context, "crawl_urls", None) or [])[:10]:
                if url not in urls_to_test and "?" in url:
                    urls_to_test.append(url)
            for form in (getattr(context, "crawl_forms", None) or [])[:10]:
                fields = form.get("fields", [])
                action = form.get("action", "")
                if action and any(self._is_sensitive_param(f) for f in fields):
                    urls_to_test.append(action)

        async with httpx.AsyncClient(
            verify=getattr(target, "verify_ssl", True),
            timeout=10,
            follow_redirects=True,
        ) as client:
            for url in urls_to_test:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)

                for param_name, values in params.items():
                    # 1. Price/amount tampering
                    if self._is_numeric_param(param_name):
                        result = await self._test_numeric_tampering(client, url, param_name, values[0])
                        if result:
                            results.append(result)

                    # 2. Role/privilege escalation
                    if self._is_role_param(param_name):
                        result = await self._test_privilege_escalation(client, url, param_name, values[0])
                        if result:
                            results.append(result)

                    # 3. State/workflow bypass
                    if self._is_state_param(param_name):
                        result = await self._test_workflow_bypass(client, url, param_name, values[0])
                        if result:
                            results.append(result)

                if len(results) >= 10:
                    break

        return results

    def _is_numeric_param(self, name: str) -> bool:
        return any(p in name.lower() for p in NUMERIC_PARAMS)

    def _is_role_param(self, name: str) -> bool:
        return any(p in name.lower() for p in ROLE_PARAMS)

    def _is_state_param(self, name: str) -> bool:
        return any(p in name.lower() for p in STATE_PARAMS)

    def _is_sensitive_param(self, name: str) -> bool:
        return self._is_numeric_param(name) or self._is_role_param(name) or self._is_state_param(name)

    async def _test_numeric_tampering(self, client: httpx.AsyncClient, url: str, param: str, original_value: str) -> Result | None:
        """Test if numeric params (price, qty) can be tampered."""
        tampered_values = ["0", "-1", "0.01", "99999"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for tampered in tampered_values:
            try:
                new_params = dict(params)
                new_params[param] = [tampered]
                new_query = urlencode(new_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                resp = await client.get(test_url)
                if resp.status_code == 200 and tampered in resp.text:
                    return Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title=f"Price/amount tampering: {param}={tampered} accepted",
                        description=(
                            f"Server accepted tampered value '{tampered}' for parameter '{param}'. "
                            f"Original value was '{original_value}'."
                        ),
                        endpoint=test_url,
                        param_name=param,
                        rule_id="biz_numeric_tampering",
                        cwe_id="CWE-20",
                        recommendation="Validate all numeric parameters server-side. Never trust client-supplied prices/amounts.",
                    )
            except (httpx.TransportError, httpx.InvalidURL):
                continue
        return None

    async def _test_privilege_escalation(self, client: httpx.AsyncClient, url: str, param: str, original_value: str) -> Result | None:
        """Test if role/privilege params can be escalated."""
        escalation_values = ["admin", "1", "true", "root", "superadmin"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for escalated in escalation_values:
            if escalated == original_value:
                continue
            try:
                new_params = dict(params)
                new_params[param] = [escalated]
                new_query = urlencode(new_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                resp = await client.get(test_url)
                if resp.status_code == 200:
                    return Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title=f"Privilege escalation: {param}={escalated} accepted",
                        description=f"Server accepted privilege escalation value '{escalated}' for '{param}'.",
                        endpoint=test_url,
                        param_name=param,
                        rule_id="biz_privilege_escalation",
                        cwe_id="CWE-269",
                        confidence="low",
                        recommendation="Enforce authorization server-side. Never derive privileges from client parameters.",
                    )
            except (httpx.TransportError, httpx.InvalidURL):
                continue
        return None

    async def _test_workflow_bypass(self, client: httpx.AsyncClient, url: str, param: str, original_value: str) -> Result | None:
        """Test if workflow state can be bypassed."""
        bypass_values = ["completed", "approved", "verified", "1", "true", "done"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for bypassed in bypass_values:
            if bypassed == original_value:
                continue
            try:
                new_params = dict(params)
                new_params[param] = [bypassed]
                new_query = urlencode(new_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                resp = await client.get(test_url)
                if resp.status_code == 200:
                    return Result(
                        plugin_name=self.name,
                        base_severity=Severity.HIGH,
                        title=f"Workflow bypass: {param}={bypassed} accepted",
                        description=f"Server accepted workflow state bypass for '{param}'.",
                        endpoint=test_url,
                        param_name=param,
                        rule_id="biz_workflow_bypass",
                        cwe_id="CWE-841",
                        confidence="low",
                        recommendation="Enforce workflow state transitions server-side.",
                    )
            except (httpx.TransportError, httpx.InvalidURL):
                continue
        return None
