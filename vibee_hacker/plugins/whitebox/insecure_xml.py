"""Plugin 8: Insecure XML Parser Detector (Phase 2, CRITICAL)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

# Patterns that indicate potentially insecure XML parsing
INSECURE_XML_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "etree.parse() without defusedxml",
        re.compile(r'\betree\.parse\s*\(|ElementTree\.parse\s*\(|xml\.etree'),
        "Standard xml.etree parsers are vulnerable to XXE; use defusedxml instead.",
    ),
    (
        "lxml without entity protection",
        re.compile(r'lxml\.etree|from lxml import etree'),
        "lxml is vulnerable to XXE by default unless resolve_entities=False is set.",
    ),
    (
        "minidom parseString",
        re.compile(r'minidom\.parseString\s*\(|minidom\.parse\s*\('),
        "xml.dom.minidom is vulnerable to XXE attacks.",
    ),
    (
        "xml2js without safe options",
        re.compile(r'xml2js\.parseString\s*\(|xml2js\.Parser\s*\('),
        "xml2js should be used with explicitCharkey and entity handling configured.",
    ),
    (
        "PHP simplexml_load_string without protection",
        re.compile(r'simplexml_load_string\s*\(|simplexml_load_file\s*\('),
        "PHP simplexml functions are vulnerable to XXE unless LIBXML_NOENT is avoided.",
    ),
    (
        "xmlreader without entity disabling",
        re.compile(r'XMLReader\s*\(\)|xmlreader\.open\s*\('),
        "XMLReader can process external entities unless explicitly disabled.",
    ),
]

# Safe patterns that indicate protection is in place
SAFE_PATTERNS: list[re.Pattern] = [
    re.compile(r'defusedxml'),
    re.compile(r'resolve_entities\s*=\s*False'),
    re.compile(r'no_network\s*=\s*True'),
]


def _file_has_safe_pattern(content: str) -> bool:
    return any(pat.search(content) for pat in SAFE_PATTERNS)


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class InsecureXmlPlugin(PluginBase):
    name = "insecure_xml"
    description = "Detect XML parsers vulnerable to XXE (XML External Entity) attacks"
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

        for src_file in root.rglob("*"):
            if not src_file.is_file() or _should_skip(src_file):
                continue
            if src_file.suffix.lower() not in (".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb"):
                continue
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # If the file uses defusedxml or has protection, skip
            if _file_has_safe_pattern(content):
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for label, pat, rationale in INSECURE_XML_PATTERNS:
                    if pat.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.CRITICAL,
                                title=f"Insecure XML Parser: {label}",
                                description=(
                                    f"{rationale} Found in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use defusedxml for Python, set resolve_entities=False for lxml, "
                                    "or disable DTD processing in your XML parser."
                                ),
                                cwe_id="CWE-611",
                                rule_id="insecure_xml_parser",
                                endpoint=str(src_file),
                            )
                        )
                        break  # one result per line

        return results
