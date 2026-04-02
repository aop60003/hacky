"""Autofix suggestions for detected vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FixSuggestion:
    """A code fix suggestion for a vulnerability."""

    rule_id: str
    language: str
    description: str
    before: str   # vulnerable code pattern
    after: str    # fixed code pattern
    reference: str = ""


# Built-in fix database
FIX_DATABASE: dict[str, list[FixSuggestion]] = {
    "sqli": [
        FixSuggestion(
            rule_id="sqli",
            language="python",
            description="Use parameterized queries instead of string formatting",
            before='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            after='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ),
        FixSuggestion(
            rule_id="sqli",
            language="javascript",
            description="Use parameterized queries with placeholders",
            before='db.query(`SELECT * FROM users WHERE id = ${userId}`)',
            after='db.query("SELECT * FROM users WHERE id = ?", [userId])',
        ),
    ],
    "xss": [
        FixSuggestion(
            rule_id="xss",
            language="python",
            description="Use HTML escaping for user input",
            before='return f"<p>{user_input}</p>"',
            after='from markupsafe import escape\nreturn f"<p>{escape(user_input)}</p>"',
        ),
        FixSuggestion(
            rule_id="xss",
            language="javascript",
            description="Use textContent instead of innerHTML",
            before='element.innerHTML = userInput',
            after='element.textContent = userInput',
        ),
    ],
    "cmdi": [
        FixSuggestion(
            rule_id="cmdi",
            language="python",
            description="Use subprocess with list arguments instead of shell=True",
            before='os.system(f"ping {host}")',
            after='import subprocess\nsubprocess.run(["ping", host], shell=False)',
        ),
    ],
    "ssrf": [
        FixSuggestion(
            rule_id="ssrf",
            language="python",
            description="Validate URL against allowlist before making requests",
            before='requests.get(user_url)',
            after=(
                'from urllib.parse import urlparse\n'
                'parsed = urlparse(user_url)\n'
                'if parsed.hostname not in ALLOWED_HOSTS:\n'
                '    raise ValueError("URL not allowed")\n'
                'requests.get(user_url)'
            ),
        ),
    ],
    "header_missing_csp": [
        FixSuggestion(
            rule_id="header_missing_csp",
            language="python",
            description="Add Content-Security-Policy header",
            before='return response',
            after=(
                'response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
                'return response'
            ),
        ),
    ],
    "hardcoded_secret": [
        FixSuggestion(
            rule_id="hardcoded_secret",
            language="python",
            description="Use environment variables for secrets",
            before='API_KEY = "sk-abc123..."',
            after='import os\nAPI_KEY = os.environ["API_KEY"]',
        ),
    ],
    "cors_wildcard_with_credentials": [
        FixSuggestion(
            rule_id="cors_wildcard_with_credentials",
            language="python",
            description="Specify allowed origins instead of wildcard",
            before='response.headers["Access-Control-Allow-Origin"] = "*"',
            after=(
                'ALLOWED_ORIGINS = ["https://app.example.com"]\n'
                'origin = request.headers.get("Origin")\n'
                'if origin in ALLOWED_ORIGINS:\n'
                '    response.headers["Access-Control-Allow-Origin"] = origin'
            ),
        ),
    ],
}


class AutofixEngine:
    """Provides fix suggestions for detected vulnerabilities."""

    def __init__(self):
        self._database: dict[str, list[FixSuggestion]] = dict(FIX_DATABASE)

    def get_fixes(self, rule_id: str, language: str | None = None) -> list[FixSuggestion]:
        """Get fix suggestions for a rule_id, optionally filtered by language."""
        # Try exact match first
        fixes = self._database.get(rule_id, [])
        # Try prefix match (e.g., "header_missing" for "header_missing_csp")
        if not fixes:
            for key, value in self._database.items():
                if rule_id.startswith(key) or key.startswith(rule_id):
                    fixes = value
                    break
        if language:
            fixes = [f for f in fixes if f.language == language]
        return fixes

    def add_fix(self, fix: FixSuggestion) -> None:
        """Add a custom fix suggestion."""
        if fix.rule_id not in self._database:
            self._database[fix.rule_id] = []
        self._database[fix.rule_id].append(fix)

    @property
    def supported_rules(self) -> list[str]:
        """List all rule_ids with fix suggestions."""
        return list(self._database.keys())

    def has_fix(self, rule_id: str) -> bool:
        """Check if a fix exists for a rule_id."""
        if rule_id in self._database:
            return True
        return any(
            rule_id.startswith(k) or k.startswith(rule_id)
            for k in self._database
        )
