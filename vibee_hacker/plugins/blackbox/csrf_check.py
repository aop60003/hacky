# vibee_hacker/plugins/blackbox/csrf_check.py
"""CSRF token presence check plugin."""

from __future__ import annotations

import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Regex to find <form> tags
FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)

# Hidden input names that indicate a CSRF token
CSRF_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?hidden["\']?[^>]*\bname\s*=\s*["\']?'
    r'(csrf|_csrf|csrftoken|csrfmiddlewaretoken|_token|authenticity_token|'
    r'xsrf_token|__requestverificationtoken)',
    re.IGNORECASE | re.DOTALL,
)

# Also accept: name attribute before type attribute
CSRF_INPUT_RE2 = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\']?'
    r'(csrf|_csrf|csrftoken|csrfmiddlewaretoken|_token|authenticity_token|'
    r'xsrf_token|__requestverificationtoken)["\']?[^>]*\btype\s*=\s*["\']?hidden',
    re.IGNORECASE | re.DOTALL,
)


def _form_has_csrf_token(form_html: str) -> bool:
    return bool(CSRF_INPUT_RE.search(form_html) or CSRF_INPUT_RE2.search(form_html))


class CsrfCheckPlugin(PluginBase):
    name = "csrf_check"
    description = "Detect forms that lack CSRF tokens, leaving state-changing operations unprotected"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "HTML form with POST method has no recognisable CSRF hidden input"
    expected_evidence = "Form found without csrf/csrfmiddlewaretoken/_token hidden field"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=True) as client:
            try:
                resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

        # Only analyse HTML responses
        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type.lower() and not resp.text.strip().lower().startswith("<"):
            return []

        body = resp.text
        forms = FORM_RE.findall(body)

        if not forms:
            return []

        results: list[Result] = []
        for idx, form_html in enumerate(forms, start=1):
            if not _form_has_csrf_token(form_html):
                results.append(Result(
                    plugin_name=self.name,
                    base_severity=Severity.MEDIUM,
                    title=f"CSRF token missing in form #{idx}",
                    description=(
                        f"Form #{idx} at {target.url} does not contain a recognisable CSRF token "
                        f"hidden input field. State-changing requests from this form may be "
                        f"forgeable by a cross-site attacker."
                    ),
                    evidence=f"Form HTML (first 200 chars): {form_html[:200]}",
                    recommendation=(
                        "Add a CSRF token as a hidden input to every state-changing form. "
                        "Use your framework's built-in CSRF protection (e.g. Django CSRF middleware, "
                        "Rails authenticity_token, Laravel _token)."
                    ),
                    cwe_id="CWE-352",
                    endpoint=target.url,
                    rule_id="csrf_token_missing",
                ))

        return results
