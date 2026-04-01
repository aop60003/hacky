"""Plugin 1: Language and Framework Detector (Phase 1, INFO)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = ["node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"]

LANG_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (JSX)",
    ".tsx": "TypeScript (TSX)",
    ".php": "PHP",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".cs": "C#",
}


def _should_skip(path: Path) -> bool:
    return any(skip in path.parts for skip in SKIP_DIRS)


class LangDetectorPlugin(PluginBase):
    name = "lang_detector"
    description = "Detect languages and frameworks used in the project"
    category = "whitebox"
    phase = 1
    base_severity = Severity.INFO

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []

        root = Path(target.path)
        if not root.exists():
            return []

        lang_counts: dict[str, int] = {}
        frameworks: list[str] = []

        # Count files by extension
        for f in root.rglob("*"):
            if f.is_file() and not _should_skip(f):
                ext = f.suffix.lower()
                if ext in LANG_EXTENSIONS:
                    lang = LANG_EXTENSIONS[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

        # Detect frameworks
        # Django
        if (root / "manage.py").exists() or (root / "settings.py").exists():
            frameworks.append("Django")
        # Flask
        for py_file in root.rglob("*.py"):
            if _should_skip(py_file):
                continue
            try:
                content = py_file.read_text(errors="ignore")
                if "from flask import" in content or "import flask" in content.lower():
                    if "Flask" not in frameworks:
                        frameworks.append("Flask")
                if "from fastapi import" in content or "import fastapi" in content.lower():
                    if "FastAPI" not in frameworks:
                        frameworks.append("FastAPI")
            except OSError:
                continue

        # package.json based frameworks
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                pkg_content = pkg_json.read_text(errors="ignore")
                if '"express"' in pkg_content:
                    frameworks.append("Express")
                if '"next"' in pkg_content:
                    frameworks.append("Next.js")
                if '"react"' in pkg_content and "Next.js" not in frameworks:
                    frameworks.append("React")
                if '"vue"' in pkg_content:
                    frameworks.append("Vue")
                if '"@angular/core"' in pkg_content:
                    frameworks.append("Angular")
            except OSError:
                pass

        # Spring (Java)
        pom_xml = root / "pom.xml"
        if pom_xml.exists():
            try:
                pom_content = pom_xml.read_text(errors="ignore")
                if "spring" in pom_content.lower():
                    frameworks.append("Spring")
            except OSError:
                pass

        # Laravel (PHP)
        artisan = root / "artisan"
        if artisan.exists():
            frameworks.append("Laravel")

        if not lang_counts and not frameworks:
            return []

        lang_summary = ", ".join(f"{lang} ({count} files)" for lang, count in lang_counts.items())
        fw_summary = ", ".join(frameworks) if frameworks else "none detected"

        return [
            Result(
                plugin_name=self.name,
                base_severity=Severity.INFO,
                title="Languages and Frameworks Detected",
                description=f"Languages: {lang_summary or 'none'}. Frameworks: {fw_summary}.",
                evidence=f"Languages: {lang_summary}; Frameworks: {fw_summary}",
                recommendation="Review detected stack for known vulnerabilities in dependencies.",
                rule_id="lang_detected",
                endpoint=str(root),
            )
        ]
