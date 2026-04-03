"""Plugin: Swift Security Checks (whitebox)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import iter_files, safe_read
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Line-by-line patterns (single line matching)
LINE_PATTERNS: list[tuple[re.Pattern, str, str, str, str, str]] = [
    (
        re.compile(r'\bUIWebView\b'),
        "Deprecated UIWebView usage",
        "UIWebView is deprecated and lacks modern security features. Use WKWebView instead.",
        "Replace UIWebView with WKWebView which has improved security isolation.",
        "CWE-295",
        "swift_uiwebview",
    ),
    (
        re.compile(r'SecItemAdd|SecItemUpdate|kSecValueData', re.IGNORECASE),
        "Keychain usage without kSecAttrAccessible",
        "Keychain item added without specifying kSecAttrAccessible accessibility constraint.",
        "Always specify kSecAttrAccessible (e.g., kSecAttrAccessibleWhenUnlocked) when storing Keychain items.",
        "CWE-311",
        "swift_keychain_no_accessible",
    ),
    (
        re.compile(r'URLSession\.shared|NSURLSession\.sharedSession', re.IGNORECASE),
        "No certificate pinning detected",
        "URLSession used without certificate pinning delegate. MITM attacks may be possible.",
        "Implement certificate pinning via URLSessionDelegate.urlSession(_:didReceive:completionHandler:).",
        "CWE-295",
        "swift_no_cert_pinning",
    ),
]

# Whole-file patterns (multi-line, using DOTALL)
FILE_PATTERNS: list[tuple[re.Pattern, str, str, str, str, str]] = [
    (
        # Matches plist `<key>NSAllowsArbitraryLoads</key>...<true/>` and
        # Swift/ObjC `NSAllowsArbitraryLoads = true`
        re.compile(
            r'NSAllowsArbitraryLoads(?:\s*=\s*true|.*?<true\s*/>)',
            re.IGNORECASE | re.DOTALL,
        ),
        "NSAllowsArbitraryLoads enabled",
        "ATS is disabled, allowing insecure HTTP connections.",
        "Disable NSAllowsArbitraryLoads and use HTTPS for all connections.",
        "CWE-295",
        "swift_arbitrary_loads",
    ),
]

# For keychain check we need to ensure kSecAttrAccessible is NOT near the call
KEYCHAIN_ACCESSIBLE_RE = re.compile(r'kSecAttrAccessible', re.IGNORECASE)


class SwiftSecurityPlugin(PluginBase):
    name = "swift_security"
    description = "Detect iOS/Swift security misconfigurations (ATS, UIWebView, Keychain, cert pinning)"
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
        seen: set[tuple[str, str]] = set()  # (file, rule_id) dedup

        for src_file in iter_files(root, {".swift", ".plist", ".xml"}):
            content = safe_read(src_file)
            if content is None:
                continue

            rel = str(src_file.relative_to(root))
            lines = content.splitlines()

            # Whole-file multi-line patterns
            for pattern, title, description, recommendation, cwe_id, rule_id in FILE_PATTERNS:
                m = pattern.search(content)
                if m:
                    # Find line number from match position
                    lineno = content[:m.start()].count("\n") + 1
                    key = (rel, rule_id)
                    if key not in seen:
                        seen.add(key)
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=title,
                                description=(
                                    f"{description} Found in '{rel}' at line {lineno}."
                                ),
                                evidence=f"{rel}:{lineno}: {lines[lineno - 1].strip()[:120] if lineno <= len(lines) else m.group()[:80]}",
                                recommendation=recommendation,
                                cwe_id=cwe_id,
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )

            # Line-by-line patterns
            for lineno, line in enumerate(lines, start=1):
                stripped = line.lstrip()
                if stripped.startswith("//"):
                    continue

                for pattern, title, description, recommendation, cwe_id, rule_id in LINE_PATTERNS:
                    if not pattern.search(line):
                        continue

                    # Special handling: keychain without kSecAttrAccessible
                    if rule_id == "swift_keychain_no_accessible":
                        window_start = max(0, lineno - 5)
                        window_end = min(len(lines), lineno + 5)
                        window = "\n".join(lines[window_start:window_end])
                        if KEYCHAIN_ACCESSIBLE_RE.search(window):
                            continue

                    key = (rel, rule_id)
                    if key not in seen:
                        seen.add(key)
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title=title,
                                description=(
                                    f"{description} Found in '{rel}' at line {lineno}."
                                ),
                                evidence=f"{rel}:{lineno}: {line.strip()[:120]}",
                                recommendation=recommendation,
                                cwe_id=cwe_id,
                                rule_id=rule_id,
                                endpoint=str(src_file),
                            )
                        )
                    break  # one finding per line

        return results
