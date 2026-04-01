# vibee_hacker/plugins/blackbox/default_creds.py
"""Default credentials check plugin (P2-2)."""

from __future__ import annotations

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

DEFAULT_CREDS = [
    {"url_pattern": "/manager/html", "username": "tomcat", "password": "tomcat"},
    {"url_pattern": "/phpmyadmin/", "username": "root", "password": ""},
    {"url_pattern": "/admin/", "username": "admin", "password": "admin"},
    {"url_pattern": "/jenkins/", "username": "admin", "password": "admin"},
    {"url_pattern": "/grafana/", "username": "admin", "password": "admin"},
    {"url_pattern": "/login", "username": "admin", "password": "admin"},
    {"url_pattern": "/login", "username": "admin", "password": "password"},
    {"url_pattern": "/login", "username": "admin", "password": "123456"},
    {"url_pattern": "/signin", "username": "admin", "password": "admin"},
    {"url_pattern": "/signin", "username": "admin", "password": "password"},
]

# Field name guesses for login form username and password
USERNAME_FIELDS = ["username", "user", "email", "login", "name"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd"]

SUCCESS_MARKERS = [
    "dashboard",
    "welcome",
    "logout",
    "admin panel",
    "control panel",
    "successfully",
]


def _login_succeeded(resp: httpx.Response) -> bool:
    """Return True if the response contains positive success markers."""
    text = resp.text.lower()
    return any(marker in text for marker in SUCCESS_MARKERS)


class DefaultCredsPlugin(PluginBase):
    name = "default_creds"
    description = "Check common admin interfaces for default credentials"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Default credentials accepted by an admin interface"
    expected_evidence = "HTTP 200 login response without failure indicators"
    destructive_level = 2

    def is_applicable(self, target: Target) -> bool:
        return bool(target.url)

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        base = target.url.rstrip("/")
        results: list[Result] = []

        async with httpx.AsyncClient(
            verify=target.verify_ssl,
            timeout=10,
            follow_redirects=True,
        ) as client:
            for cred in DEFAULT_CREDS:
                url_pattern = cred["url_pattern"]
                url = base + url_pattern

                # Step 1: Check if the endpoint is reachable
                try:
                    probe = await client.get(url)
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if probe.status_code != 200:
                    continue

                # Step 2: Attempt login with default credentials
                try:
                    login_resp = await client.post(
                        url,
                        data={
                            "username": cred["username"],
                            "password": cred["password"],
                        },
                    )
                except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                    continue

                if login_resp.status_code == 200 and _login_succeeded(login_resp):
                    results.append(Result(
                        plugin_name=self.name,
                        base_severity=Severity.CRITICAL,
                        title=f"Default credentials work on {url_pattern}",
                        description=(
                            f"The admin interface at {url} accepted default credentials "
                            f"({cred['username']}:{cred['password']}). "
                            "An attacker can take over this interface immediately."
                        ),
                        recommendation=(
                            f"Change the default credentials for the service at {url_pattern} immediately. "
                            "Enforce strong, unique passwords and restrict administrative access by IP."
                        ),
                        cwe_id="CWE-798",
                        evidence=(
                            f"POST {url} with username={cred['username']}, "
                            f"password={cred['password']} -> HTTP {login_resp.status_code}"
                        ),
                        endpoint=url,
                        rule_id="default_credentials",
                    ))
                    # Found a working credential pair — no need to continue
                    return results

            # Also check crawled login forms for default credentials
            if context and context.crawl_forms:
                tried_actions: set[str] = set()
                for form in context.crawl_forms:
                    fields = [f.lower() for f in form.get("fields", [])]
                    has_user_field = any(
                        any(uf in f for uf in USERNAME_FIELDS) for f in fields
                    )
                    has_pass_field = any(
                        any(pf in f for pf in PASSWORD_FIELDS) for f in fields
                    )
                    if not (has_user_field and has_pass_field):
                        continue

                    action = form.get("action", "")
                    if not action or action in tried_actions:
                        continue
                    tried_actions.add(action)

                    # Resolve action URL relative to target
                    from urllib.parse import urljoin
                    form_url = urljoin(target.url, action)

                    for cred_pair in (
                        ("admin", "admin"),
                        ("admin", "password"),
                        ("admin", "123456"),
                    ):
                        # Determine field names from the form's fields list
                        user_field = next(
                            (f for f in form.get("fields", [])
                             if any(uf in f.lower() for uf in USERNAME_FIELDS)),
                            "username",
                        )
                        pass_field = next(
                            (f for f in form.get("fields", [])
                             if any(pf in f.lower() for pf in PASSWORD_FIELDS)),
                            "password",
                        )
                        try:
                            login_resp = await client.post(
                                form_url,
                                data={user_field: cred_pair[0], pass_field: cred_pair[1]},
                            )
                        except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                            break

                        if login_resp.status_code == 200 and _login_succeeded(login_resp):
                            results.append(Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Default credentials work on form at {action}",
                                description=(
                                    f"A login form at {form_url} accepted default credentials "
                                    f"({cred_pair[0]}:{cred_pair[1]}). "
                                    "An attacker can take over this account immediately."
                                ),
                                recommendation=(
                                    "Change the default credentials immediately. "
                                    "Enforce strong, unique passwords."
                                ),
                                cwe_id="CWE-798",
                                evidence=(
                                    f"POST {form_url} with {user_field}={cred_pair[0]}, "
                                    f"{pass_field}={cred_pair[1]} -> HTTP {login_resp.status_code}"
                                ),
                                endpoint=form_url,
                                rule_id="default_credentials",
                            ))
                            return results

        return results
