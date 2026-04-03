"""Plugin: Unsafe YAML Deserialization Detection (whitebox)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.file_utils import iter_files, safe_read
from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

# Python: yaml.load() without Loader=SafeLoader
PY_UNSAFE_YAML_RE = re.compile(
    r'\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)(?![^)]*SafeLoader)',
    re.DOTALL,
)
PY_SAFE_YAML_RE = re.compile(r'\byaml\.safe_load\s*\(')

# Ruby: YAML.load without safe_load
RB_UNSAFE_YAML_RE = re.compile(r'\bYAML\.load\s*\((?!.*safe_load)', re.IGNORECASE)
RB_SAFE_YAML_RE = re.compile(r'\bYAML\.safe_load\s*\(', re.IGNORECASE)


class YamlDeserializePlugin(PluginBase):
    name = "yaml_deserialize"
    description = "Detect unsafe YAML deserialization (yaml.load without SafeLoader) in Python and Ruby"
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

        for src_file in iter_files(root, {".py", ".rb"}):
            content = safe_read(src_file)
            if content is None:
                continue

            ext = src_file.suffix.lower()

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.lstrip()
                # Skip comments
                if ext == ".py" and stripped.startswith("#"):
                    continue
                if ext == ".rb" and stripped.startswith("#"):
                    continue

                if ext == ".py":
                    # Skip safe_load lines
                    if PY_SAFE_YAML_RE.search(line):
                        continue
                    if PY_UNSAFE_YAML_RE.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="Unsafe yaml.load() Without SafeLoader",
                                description=(
                                    f"yaml.load() called without Loader=yaml.SafeLoader in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "This allows arbitrary Python object construction from YAML input."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) "
                                    "to prevent arbitrary code execution via deserialization."
                                ),
                                cwe_id="CWE-502",
                                rule_id="yaml_unsafe_load",
                                endpoint=str(src_file),
                            )
                        )

                elif ext == ".rb":
                    # Skip YAML.safe_load lines
                    if RB_SAFE_YAML_RE.search(line):
                        continue
                    if RB_UNSAFE_YAML_RE.search(line):
                        results.append(
                            Result(
                                plugin_name=self.name,
                                base_severity=Severity.HIGH,
                                title="Unsafe YAML.load() in Ruby",
                                description=(
                                    f"YAML.load() called without safe_load in "
                                    f"'{src_file.relative_to(root)}' at line {lineno}. "
                                    "In Ruby, YAML.load can instantiate arbitrary objects leading to RCE."
                                ),
                                evidence=f"{src_file.relative_to(root)}:{lineno}: {line.strip()[:120]}",
                                recommendation=(
                                    "Use YAML.safe_load() in Ruby to prevent object deserialization attacks."
                                ),
                                cwe_id="CWE-502",
                                rule_id="yaml_unsafe_load",
                                endpoint=str(src_file),
                            )
                        )

        return results
