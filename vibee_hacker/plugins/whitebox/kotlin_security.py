"""Plugin: Kotlin/Android Security Checks (whitebox)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import iter_files, safe_read
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

KOTLIN_PATTERNS: list[tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r'\.setJavaScriptEnabled\s*\(\s*true\s*\)'),
        "WebView JavaScript enabled",
        "WebView has JavaScript enabled, which increases XSS attack surface.",
        "Disable JavaScript unless strictly necessary. If needed, validate all data passed to WebView.",
        "CWE-749",
        "kotlin_webview_js_enabled",
    ),
    (
        re.compile(r'\.addJavascriptInterface\s*\('),
        "WebView addJavascriptInterface usage",
        "addJavascriptInterface exposes Java objects to JavaScript, enabling remote code execution.",
        "Avoid addJavascriptInterface or restrict to API level >= 17 and annotate with @JavascriptInterface.",
        "CWE-749",
        "kotlin_webview_js_interface",
    ),
    (
        re.compile(r'\bIntent\s*\([^)]*\)\s*$|\bIntent\s*\(\s*\)', re.MULTILINE),
        "Implicit Intent usage",
        "Implicit Intent without exported=false can be intercepted by malicious apps.",
        "Use explicit Intents with component name, or set exported=false in manifest.",
        "CWE-927",
        "kotlin_implicit_intent",
    ),
    (
        re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
        "SharedPreferences world-readable/writeable",
        "SharedPreferences created with MODE_WORLD_READABLE/WRITEABLE allows other apps to read data.",
        "Use MODE_PRIVATE for SharedPreferences. Use EncryptedSharedPreferences for sensitive data.",
        "CWE-927",
        "kotlin_shared_prefs_world_readable",
    ),
]


class KotlinSecurityPlugin(PluginBase):
    name = "kotlin_security"
    description = "Detect Android/Kotlin security issues (WebView JS, implicit intents, world-readable prefs)"
    category = "whitebox"
    phase = 2
    base_severity = Severity.HIGH

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in iter_files(root, {".kt", ".java", ".xml"}):
            content = safe_read(src_file)
            if content is None:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for pattern, title, description, recommendation, cwe_id, rule_id in KOTLIN_PATTERNS:
                    if pattern.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=title,
                                description=(
                                    f"{description} Found in '{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=recommendation,
                                cwe_id=cwe_id,
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                        break  # one finding per line

        return results
