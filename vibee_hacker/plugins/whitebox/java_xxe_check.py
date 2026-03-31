"""Plugin: Java XXE (XML External Entity) Vulnerability Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import MAX_FILE_SIZE, should_skip
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Patterns that indicate unsafe XML parsing (factory instantiation without hardening)
UNSAFE_FACTORY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("DocumentBuilderFactory.newInstance()", re.compile(
        r'\bDocumentBuilderFactory\.newInstance\s*\(\s*\)'
    )),
    ("SAXParserFactory.newInstance()", re.compile(
        r'\bSAXParserFactory\.newInstance\s*\(\s*\)'
    )),
    ("XMLInputFactory.newInstance()", re.compile(
        r'\bXMLInputFactory\.(?:newInstance|newFactory)\s*\(\s*\)'
    )),
]

# These strings indicate secure processing has been configured
SECURE_MARKERS = (
    "FEATURE_SECURE_PROCESSING",
    "XMLConstants.FEATURE_SECURE_PROCESSING",
    "IS_SUPPORTING_EXTERNAL_ENTITIES",
    "XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES",
    "SUPPORT_DTD",
    "setExpandEntityReferences",
    "setFeature",
)


class JavaXxeCheckPlugin(PluginBase):
    name = "java_xxe_check"
    description = "Detect insecure XML parsing configurations that may allow XXE attacks"
    category = "whitebox"
    phase = 2
    base_severity = Severity.CRITICAL

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        for src_file in root.rglob("*.java"):
            if not src_file.is_file() or should_skip(src_file):
                continue
            try:
                if src_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # If file has any secure marker, skip it (secured factory)
            if any(marker in content for marker in SECURE_MARKERS):
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for label, pat in UNSAFE_FACTORY_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Unsafe XML Parser: {label}",
                                description=(
                                    f"Potentially unsafe XML parser '{label}' instantiated without "
                                    f"secure processing in '{src_file.relative_to(root)}' at line {lineno}. "
                                    "This may allow XXE (XML External Entity) injection attacks."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Set FEATURE_SECURE_PROCESSING to true and disable external entities: "
                                    "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); "
                                    "factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);"
                                ),
                                cwe_id="CWE-611",
                                rule_id="java_xxe_unsafe",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
