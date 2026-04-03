"""Nuclei template compatibility: import and convert Nuclei YAML templates."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vibee_hacker.core.template_engine import Template, TemplateEngine

logger = logging.getLogger(__name__)


@dataclass
class NucleiTemplate:
    """Parsed Nuclei template (subset of Nuclei format)."""
    id: str = ""
    name: str = ""
    severity: str = "info"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = ""
    reference: list[str] = field(default_factory=list)
    requests: list[dict] = field(default_factory=list)
    matchers: list[dict] = field(default_factory=list)


class NucleiImporter:
    """Import Nuclei templates and convert to VIBEE format."""

    SEVERITY_MAP = {
        "info": "info", "low": "low", "medium": "medium",
        "high": "high", "critical": "critical",
    }

    def parse_nuclei(self, yaml_str: str) -> NucleiTemplate | None:
        """Parse a Nuclei YAML template string."""
        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError:
            return None

        if not data or not isinstance(data, dict):
            return None

        info = data.get("info", {})

        # Parse requests (Nuclei format)
        requests = []
        http_section = data.get("http", data.get("requests", []))
        if isinstance(http_section, list):
            for req in http_section:
                parsed_req = {
                    "method": req.get("method", "GET"),
                    "path": req.get("path", ["{{BaseURL}}"])[0] if isinstance(req.get("path"), list) else req.get("path", "{{BaseURL}}"),
                    "headers": req.get("headers", {}),
                    "body": req.get("body", ""),
                    "matchers": req.get("matchers", []),
                    "matchers-condition": req.get("matchers-condition", "and"),
                }
                requests.append(parsed_req)

        return NucleiTemplate(
            id=data.get("id", ""),
            name=info.get("name", ""),
            severity=info.get("severity", "info"),
            description=info.get("description", ""),
            tags=self._parse_tags(info.get("tags", "")),
            author=info.get("author", ""),
            reference=info.get("reference", []),
            requests=requests,
        )

    def convert_to_vibee(self, nuclei: NucleiTemplate) -> Template:
        """Convert a Nuclei template to VIBEE Template format."""
        vibee_requests = []

        for req in nuclei.requests:
            vibee_matchers = []
            for matcher in req.get("matchers", []):
                vibee_matcher = self._convert_matcher(matcher)
                if vibee_matcher:
                    vibee_matchers.append(vibee_matcher)

            vibee_req = {
                "method": req.get("method", "GET"),
                "path": req.get("path", "{{BaseURL}}"),
                "matchers": vibee_matchers,
            }

            # Convert body to payloads if present
            body = req.get("body", "")
            if body:
                vibee_req["body"] = body

            vibee_requests.append(vibee_req)

        from vibee_hacker.core.models import Severity
        severity_map = {
            "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL,
        }

        return Template(
            id=nuclei.id,
            name=nuclei.name,
            severity=severity_map.get(nuclei.severity, Severity.INFO),
            description=nuclei.description,
            cwe="",
            tags=nuclei.tags,
            requests=vibee_requests,
        )

    def import_file(self, path: str | Path) -> Template | None:
        """Import a single Nuclei template file."""
        try:
            content = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        nuclei = self.parse_nuclei(content)
        if not nuclei:
            return None

        return self.convert_to_vibee(nuclei)

    def import_directory(self, path: str | Path) -> list[Template]:
        """Import all Nuclei templates from a directory."""
        templates = []
        dir_path = Path(path)
        if not dir_path.is_dir():
            return []

        for yaml_file in sorted(dir_path.rglob("*.yaml")):
            template = self.import_file(yaml_file)
            if template:
                templates.append(template)

        return templates

    def _convert_matcher(self, matcher: dict) -> dict | None:
        """Convert a Nuclei matcher to VIBEE matcher format."""
        matcher_type = matcher.get("type", "")

        if matcher_type == "word":
            return {
                "type": "word",
                "words": matcher.get("words", []),
                "condition": matcher.get("condition", "or"),
            }
        elif matcher_type == "status":
            return {
                "type": "status",
                "status": matcher.get("status", []),
            }
        elif matcher_type == "regex":
            return {
                "type": "regex",
                "regex": matcher.get("regex", []),
                "condition": matcher.get("condition", "or"),
            }
        elif matcher_type == "dsl":
            # DSL matchers are Nuclei-specific, convert to regex where possible
            logger.debug("DSL matcher not fully supported, skipping")
            return None

        return None

    def _parse_tags(self, tags) -> list[str]:
        """Parse tags from string or list."""
        if isinstance(tags, list):
            return tags
        if isinstance(tags, str):
            return [t.strip() for t in tags.split(",") if t.strip()]
        return []
