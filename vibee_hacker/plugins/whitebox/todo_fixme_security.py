"""Plugin 11: Security-related TODO/FIXME/HACK Comment Detector (Phase 2, INFO)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# Matches TODO/FIXME/HACK/XXX followed by security-related terms (case-insensitive)
SECURITY_TODO_PATTERN = re.compile(
    r'(?i)\b(TODO|FIXME|HACK|XXX)\b.*?\b('
    r'security|secure|secur|auth|authori|authenticat|authn|authz|'
    r'password|passwd|token|secret|credential|cred|'
    r'vuln|vulnerable|inject|xss|sqli|sql\s*inject|csrf|'
    r'encrypt|decrypt|crypto|hash|sanitiz|escap|'
    r'privilege|permission|access\s*control|acl|rbac|'
    r'firewall|rate.?limit|brute.?force|dos|ddos|'
    r'hardcode|hard.?code|plaintext|plain.?text'
    r')\b'
)


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class TodoFixmeSecurityPlugin(PluginBase):
    name = "todo_fixme_security"
    description = "Find security-related TODO/FIXME/HACK/XXX comments indicating unfinished security work"
    category = "whitebox"
    phase = 2
    base_severity = Severity.INFO

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            if src_file.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".ico", ".bin", ".exe", ".pyc"):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                if SECURITY_TODO_PATTERN.search(line):
                    results.append(
                        Result(
                            plugin_name=self.name,
                            base_severity=Severity.INFO,
                            title="Security-related TODO/FIXME Comment Found",
                            description=(
                                f"A comment flagging unresolved security work was found in "
                                f"'{src_file.relative_to(root)}' at line {lineno}."
                            ),
                            evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                            recommendation=(
                                "Review and resolve all security-related TODO/FIXME items before deployment. "
                                "Track them in your issue tracker."
                            ),
                            rule_id="security_todo",
                            endpoint=str(src_file),
                        )
                    )

        return results
