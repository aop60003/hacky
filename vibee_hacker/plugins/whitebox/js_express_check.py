"""Plugin: Express.js Security Checker (Phase 2, MEDIUM)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs"}

EXPRESS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "Session cookie secure: false",
        re.compile(r'\bsecure\s*:\s*false\b'),
        "js_express_insecure_cookie",
    ),
    (
        "res.redirect with variable",
        re.compile(r'\bres\.redirect\s*\(\s*(?!["\'])'),
        "js_express_open_redirect",
    ),
    (
        "bodyParser without size limit",
        re.compile(r'\bbodyParser\s*\.\s*(?:json|urlencoded)\s*\(\s*\)'),
        "js_express_no_body_limit",
    ),
    (
        "trust proxy not configured",
        re.compile(r'\bapp\.set\s*\(\s*["\']trust proxy["\']'),
        "js_express_trust_proxy",
    ),
]


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class JsExpressCheckPlugin(PluginBase):
    name = "js_express_check"
    description = "Detect Express.js security misconfigurations (insecure cookies, open redirect, etc.)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.MEDIUM

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*"):
            if not src_file.is_file() or src_file.suffix.lower() not in JS_EXTENSIONS:
                continue
            if _should_skip(src_file):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat, rule_id in EXPRESS_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.MEDIUM,
                                title=f"Express.js Security Issue: {label}",
                                description=(
                                    f"Express.js security misconfiguration '{label}' detected in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    f"Fix the Express.js configuration issue: {label}. "
                                    "Set secure:true for cookies, validate redirects, and set body size limits."
                                ),
                                cwe_id="CWE-16",
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break

        return results
