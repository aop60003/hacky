# vibee_hacker/plugins/blackbox/password_policy_check.py
"""Password policy weakness detection plugin."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

SIGNUP_PATHS = [
    "/register",
    "/signup",
    "/password/reset",
    "/change-password",
]

WEAK_PASSWORDS = [
    "123456",
    "password",
    "a",
]


class PasswordPolicyCheckPlugin(PluginBase):
    name = "password_policy_check"
    description = "Detect weak password policy by submitting weak passwords to registration endpoints"
    category = "blackbox"
    phase = 3
    base_severity = Severity.MEDIUM
    detection_criteria = "Signup/registration endpoint accepts a known-weak password (HTTP 200/201)"
    expected_evidence = "Weak password accepted with HTTP 200 or 201"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []
        seen: set[str] = set()

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10, follow_redirects=True) as client:
            for path in SIGNUP_PATHS:
                base = target.url.rstrip("/")
                endpoint = f"{base}{path}"
                for weak_pw in WEAK_PASSWORDS:
                    payload = {
                        "username": "testuser",
                        "email": "test@example.com",
                        "password": weak_pw,
                        "password_confirm": weak_pw,
                    }
                    try:
                        resp = await client.post(endpoint, data=payload)
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if resp.status_code in (200, 201) and endpoint not in seen:
                        seen.add(endpoint)
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title=f"Weak password policy: {path}",
                            description=(
                                f"The endpoint {endpoint} accepted the weak password '{weak_pw}' "
                                f"(HTTP {resp.status_code}). The application does not enforce "
                                f"sufficient password complexity requirements."
                            ),
                            evidence=f"POST {endpoint} with password='{weak_pw}' -> HTTP {resp.status_code}",
                            recommendation=(
                                "Enforce strong password policy: minimum 8 characters, "
                                "require mixed case, numbers, and special characters. "
                                "Reject commonly used passwords."
                            ),
                            cwe_id="CWE-521",
                            endpoint=endpoint,
                            rule_id="password_policy_weak",
                        ))
                        break  # one finding per endpoint is enough

        return results
