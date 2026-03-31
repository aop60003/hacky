# vibee_hacker/plugins/blackbox/cookie_security.py
"""Cookie security flags check plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase


def _parse_cookie_attrs(cookie_header: str) -> dict[str, str | bool]:
    """Parse a Set-Cookie header string into a dict of attribute -> value."""
    parts = [p.strip() for p in cookie_header.split(";")]
    attrs: dict[str, str | bool] = {}
    for i, part in enumerate(parts):
        if i == 0:
            # Cookie name=value
            if "=" in part:
                name, _, val = part.partition("=")
                attrs["_name"] = name.strip()
                attrs["_value"] = val.strip()
            else:
                attrs["_name"] = part
                attrs["_value"] = ""
        else:
            if "=" in part:
                k, _, v = part.partition("=")
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.lower()] = True
    return attrs


class CookieSecurityPlugin(PluginBase):
    name = "cookie_security"
    description = "Check Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags"
    category = "blackbox"
    phase = 2
    base_severity = Severity.MEDIUM
    detection_criteria = "Set-Cookie header missing HttpOnly, Secure, or SameSite flag"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        # httpx stores multiple Set-Cookie headers; access via raw headers
        set_cookie_headers = [
            v for k, v in resp.headers.multi_items()
            if k.lower() == "set-cookie"
        ]

        if not set_cookie_headers:
            return []

        results: list[Result] = []

        for raw_cookie in set_cookie_headers:
            attrs = _parse_cookie_attrs(raw_cookie)
            cookie_name = str(attrs.get("_name", "<unknown>"))

            # Check HttpOnly
            if "httponly" not in attrs:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    description=(
                        f"The cookie '{cookie_name}' does not have the HttpOnly flag set. "
                        "This allows client-side scripts to access the cookie, enabling theft via XSS."
                    ),
                    recommendation=f"Add the HttpOnly attribute to the '{cookie_name}' cookie.",
                    evidence=f"Set-Cookie: {raw_cookie}",
                    cwe_id="CWE-614",
                    endpoint=target.url,
                    rule_id="cookie_missing_httponly",
                ))

            # Check Secure flag
            if "secure" not in attrs:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=self.base_severity,
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    description=(
                        f"The cookie '{cookie_name}' does not have the Secure flag set. "
                        "This allows the cookie to be transmitted over unencrypted HTTP connections."
                    ),
                    recommendation=f"Add the Secure attribute to the '{cookie_name}' cookie.",
                    evidence=f"Set-Cookie: {raw_cookie}",
                    cwe_id="CWE-614",
                    endpoint=target.url,
                    rule_id="cookie_missing_secure",
                ))

            # Check SameSite
            samesite_val = str(attrs.get("samesite", "")).lower()
            if not samesite_val:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.LOW,
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    description=(
                        f"The cookie '{cookie_name}' does not have a SameSite attribute. "
                        "Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks."
                    ),
                    recommendation=f"Add SameSite=Lax or SameSite=Strict to the '{cookie_name}' cookie.",
                    evidence=f"Set-Cookie: {raw_cookie}",
                    cwe_id="CWE-614",
                    endpoint=target.url,
                    rule_id="cookie_missing_samesite",
                ))
            elif samesite_val == "none" and "secure" not in attrs:
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.HIGH,
                    title=f"Cookie '{cookie_name}' has SameSite=None without Secure",
                    description=(
                        f"The cookie '{cookie_name}' uses SameSite=None but lacks the Secure flag. "
                        "Per RFC 6265bis, SameSite=None cookies must also be Secure; otherwise they may be "
                        "transmitted insecurely and be subject to CSRF."
                    ),
                    recommendation=(
                        f"Add the Secure flag to the '{cookie_name}' cookie when using SameSite=None, "
                        "or switch to SameSite=Lax or SameSite=Strict."
                    ),
                    evidence=f"Set-Cookie: {raw_cookie}",
                    cwe_id="CWE-614",
                    endpoint=target.url,
                    rule_id="cookie_samesite_none_without_secure",
                ))

        return results
