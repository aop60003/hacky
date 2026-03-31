"""Plugin: GraphQL Schema Security Check (Phase 5, HIGH)."""
from __future__ import annotations

import re
from pathlib import Path

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

SKIP_DIRS = {"node_modules", "venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor"}

# GraphQL file extensions
_GQL_EXTENSIONS = {".graphql", ".gql"}

# Type Mutation block parser
_MUTATION_BLOCK = re.compile(
    r'type\s+Mutation\s*\{([^}]*)\}',
    re.IGNORECASE | re.DOTALL,
)

# Field inside Mutation type: field_name(args): ReturnType [directives]
_FIELD_LINE = re.compile(
    r'^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*\S+(.*)$',
    re.MULTILINE,
)

# Auth directives (common patterns)
_AUTH_DIRECTIVE = re.compile(
    r'@(?:auth|authenticated|isAuthenticated|requireAuth|authorize|login_required|jwt|guard)\b',
    re.IGNORECASE,
)

# Introspection not disabled in JS/TS Apollo server config
_INTROSPECTION_ENABLED = re.compile(
    r'introspection\s*:\s*true\b',
    re.IGNORECASE,
)

# Deeply nested type detection (count type definitions: ≥5 types with nested references)
_TYPE_BLOCK = re.compile(r'type\s+\w+\s*\{[^}]*\}', re.DOTALL)
_FIELD_TYPE_REF = re.compile(r':\s*\[?\s*(\w+)\s*!?\]?', re.MULTILINE)

_DEPTH_THRESHOLD = 4


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def _count_type_depth(content: str) -> int:
    """Estimate max nesting depth by counting distinct type references in type blocks."""
    types_defined = set(re.findall(r'\btype\s+(\w+)\s*\{', content, re.IGNORECASE))
    types_defined.discard("Query")
    types_defined.discard("Mutation")
    types_defined.discard("Subscription")

    if len(types_defined) < _DEPTH_THRESHOLD:
        return 0

    # Count circular/cross-references between user-defined types
    refs = set()
    for block in _TYPE_BLOCK.finditer(content):
        block_text = block.group(0)
        for ref_match in _FIELD_TYPE_REF.finditer(block_text):
            ref_type = ref_match.group(1)
            if ref_type in types_defined:
                refs.add(ref_type)

    return len(refs)


class GraphQLSchemaCheckPlugin(PluginBase):
    name = "graphql_schema_check"
    description = "Scan GraphQL schema files for security issues like missing auth directives"
    category = "whitebox"
    phase = 5
    base_severity = Severity.HIGH

    def is_applicable(self, target: Target) -> bool:
        return target.path is not None

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.path:
            return []
        root = Path(target.path)
        if not root.exists():
            return []

        results: list[Result] = []

        # Scan .graphql / .gql files
        for gql_path in root.rglob("*"):
            if not gql_path.is_file() or _should_skip(gql_path):
                continue

            if gql_path.suffix.lower() in _GQL_EXTENSIONS:
                try:
                    content = gql_path.read_text(errors="ignore")
                except OSError:
                    continue

                rel = gql_path.relative_to(root)
                results.extend(_check_schema(content, gql_path, rel, self.name))

        # Scan .js/.ts for introspection not disabled
        for src_path in root.rglob("*.js"):
            if not src_path.is_file() or _should_skip(src_path):
                continue
            try:
                content = src_path.read_text(errors="ignore")
            except OSError:
                continue
            rel = src_path.relative_to(root)
            results.extend(_check_js_introspection(content, src_path, rel, self.name))

        for src_path in root.rglob("*.ts"):
            if not src_path.is_file() or _should_skip(src_path):
                continue
            try:
                content = src_path.read_text(errors="ignore")
            except OSError:
                continue
            rel = src_path.relative_to(root)
            results.extend(_check_js_introspection(content, src_path, rel, self.name))

        return results


def _check_schema(content: str, schema_path: Path, rel: Path, plugin_name: str) -> list[Result]:
    results: list[Result] = []

    # Check Mutation type for missing @auth directives
    for mutation_match in _MUTATION_BLOCK.finditer(content):
        mutation_body = mutation_match.group(1)
        for field_match in _FIELD_LINE.finditer(mutation_body):
            field_name = field_match.group(1)
            field_line = field_match.group(0)
            # Skip comment lines
            if field_line.strip().startswith("#"):
                continue
            if not _AUTH_DIRECTIVE.search(field_line):
                # Find absolute line number
                field_start = mutation_match.start(1) + field_match.start()
                line_num = content[:field_start].count("\n") + 1
                results.append(
                    Result(
                        plugin_name=plugin_name,
                        base_severity=Severity.HIGH,
                        title=f"Mutation '{field_name}' missing authorization directive",
                        description=(
                            f"The mutation '{field_name}' has no @auth or equivalent directive, "
                            f"allowing unauthenticated access. Found in '{rel}' at line ~{line_num}."
                        ),
                        evidence=f"{rel}:{line_num}: {field_line.strip()[:120]}",
                        recommendation=(
                            "Add @auth, @authenticated, or equivalent directive to all mutations, "
                            "or implement authorization at the resolver level."
                        ),
                        cwe_id="CWE-862",
                        rule_id="graphql_schema_unauth_mutation",
                        endpoint=str(schema_path),
                    )
                )

    # Check for deeply nested types (potential depth bomb)
    depth = _count_type_depth(content)
    if depth >= _DEPTH_THRESHOLD:
        results.append(
            Result(
                plugin_name=plugin_name,
                base_severity=Severity.MEDIUM,
                title="GraphQL schema has deeply nested types (potential depth bomb)",
                description=(
                    f"The schema has {depth} cross-referenced types which may enable "
                    f"deeply nested queries, leading to denial of service. In '{rel}'."
                ),
                evidence=f"{rel}: {depth} cross-referenced types detected",
                recommendation=(
                    "Implement query depth limiting (e.g. graphql-depth-limit) "
                    "and query complexity analysis."
                ),
                cwe_id="CWE-862",
                rule_id="graphql_schema_depth_bomb",
                endpoint=str(schema_path),
            )
        )

    return results


def _check_js_introspection(content: str, src_path: Path, rel: Path, plugin_name: str) -> list[Result]:
    results: list[Result] = []
    for match in _INTROSPECTION_ENABLED.finditer(content):
        line_num = content[: match.start()].count("\n") + 1
        line_text = content.splitlines()[line_num - 1].strip()
        results.append(
            Result(
                plugin_name=plugin_name,
                base_severity=Severity.MEDIUM,
                title="GraphQL introspection enabled in server config",
                description=(
                    "introspection: true allows attackers to enumerate the entire GraphQL schema. "
                    f"Found in '{rel}' at line {line_num}."
                ),
                evidence=f"{rel}:{line_num}: {line_text[:120]}",
                recommendation="Set `introspection: false` in production Apollo/GraphQL server config.",
                cwe_id="CWE-862",
                rule_id="graphql_schema_introspection_enabled",
                endpoint=str(src_path),
            )
        )
    return results
