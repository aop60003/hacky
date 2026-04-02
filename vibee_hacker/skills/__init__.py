"""Skill system: reusable security knowledge packages.

Skills are Markdown files with YAML frontmatter, organized by category.
They are loaded by name and injected into LLM prompts via Jinja2 templates.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)

_SKILLS_DIR = Path(__file__).parent

# Cached category listing (skills don't change at runtime)
_category_cache: Optional[Dict[str, List[str]]] = None


def _get_all_categories() -> Dict[str, List[str]]:
    """Discover all skill categories and their skills (cached)."""
    global _category_cache
    if _category_cache is not None:
        return _category_cache

    categories: Dict[str, List[str]] = {}
    for category_dir in sorted(_SKILLS_DIR.iterdir()):
        if category_dir.is_dir() and not category_dir.name.startswith("_"):
            skills = []
            for skill_file in sorted(category_dir.glob("*.md")):
                skills.append(skill_file.stem)
            if skills:
                categories[category_dir.name] = skills
    _category_cache = categories
    return categories


def get_available_skills() -> Dict[str, List[str]]:
    """Get all available skills organized by category.

    Returns:
        Dict mapping category name to list of skill names.
    """
    return _get_all_categories()


def validate_skill_names(names: List[str]) -> Tuple[List[str], List[str]]:
    """Validate skill names against available skills.

    Returns:
        Tuple of (valid_names, invalid_names).
    """
    all_categories = _get_all_categories()
    all_skills = set()
    for skills in all_categories.values():
        all_skills.update(skills)

    valid = [n for n in names if n in all_skills]
    invalid = [n for n in names if n not in all_skills]
    return valid, invalid


def load_skills(skill_names: List[str]) -> Dict[str, str]:
    """Load skill content by name.

    Searches across all categories for matching skill files.
    Strips YAML frontmatter, returning clean Markdown content.

    Args:
        skill_names: List of skill names (without .md extension).

    Returns:
        Dict mapping skill name to Markdown content.
    """
    skill_content: Dict[str, str] = {}
    all_categories = _get_all_categories()

    for skill_name in skill_names:
        skill_path: Optional[Path] = None

        # Reject path traversal attempts
        if ".." in skill_name or skill_name.startswith("/"):
            continue

        # Support category/name syntax
        key_name = skill_name
        if "/" in skill_name:
            parts = skill_name.split("/", 1)
            candidate = _SKILLS_DIR / parts[0] / f"{parts[1]}.md"
            if candidate.exists() and _SKILLS_DIR in candidate.resolve().parents:
                skill_path = candidate
                key_name = parts[1]
        else:
            # Search across categories
            for category, skills in all_categories.items():
                if skill_name in skills:
                    skill_path = _SKILLS_DIR / category / f"{skill_name}.md"
                    break

        if skill_path and skill_path.exists():
            content = skill_path.read_text(encoding="utf-8")
            # Strip YAML frontmatter
            content = _FRONTMATTER_PATTERN.sub("", content).lstrip()
            skill_content[key_name] = content

    return skill_content


def generate_skills_description(skill_names: List[str]) -> str:
    """Generate a combined description of loaded skills for LLM prompts."""
    skills = load_skills(skill_names)
    if not skills:
        return ""

    parts = ["# Loaded Security Skills\n"]
    for name, content in skills.items():
        parts.append(f"## {name}\n{content}\n")
    return "\n".join(parts)


# --- Scan mode auto-loading ---

# Skills auto-loaded per scan profile
_PROFILE_SKILLS: Dict[str, List[str]] = {
    "stealth":    ["http", "tls", "recon"],
    "default":    ["http", "tls", "xss", "sqli", "ssrf", "recon", "enumeration"],
    "aggressive": [
        "http", "tls", "xss", "sqli", "ssrf", "cmdi", "idor",
        "xxe", "ssti", "csrf", "cors", "path_traversal", "nosql_injection",
        "file_upload", "oauth", "deserialization", "http_smuggling",
        "race_condition", "prototype_pollution",
        "recon", "enumeration", "auth_attacks", "waf_bypass",
        "post_exploitation", "exploit_chaining",
    ],
    "ci":         ["http", "xss", "sqli", "ssrf"],
}

# Skills auto-loaded when specific tech is detected
_TECH_SKILLS: Dict[str, str] = {
    "wordpress": "wordpress",
    "wp-":       "wordpress",
    "graphql":   "graphql",
    "jwt":       "jwt",
    "json web token": "jwt",
    "nginx":     "nginx",
    "docker":    "docker",
    "kubernetes": "kubernetes",
    "k8s":       "kubernetes",
    "aws":       "aws",
    "amazon":    "aws",
    "gcp":       "gcp",
    "google cloud": "gcp",
    "azure":     "azure",
    "microsoft":  "azure",
    "websocket": "websocket",
    "ws://":     "websocket",
    "api":       "api_security",
    "rest":      "api_security",
    "swagger":   "api_security",
    "openapi":   "api_security",
}


def auto_select_skills(
    profile: Optional[str] = None,
    tech_stack: Optional[List[str]] = None,
    mode: Optional[str] = None,
) -> List[str]:
    """Auto-select skills based on scan context.

    Args:
        profile: Scan profile (stealth/default/aggressive/ci).
        tech_stack: Detected technologies from scan results.
        mode: Scan mode (blackbox/whitebox).

    Returns:
        List of skill names to load.
    """
    selected: List[str] = []

    # 1. Profile-based skills
    if profile and profile in _PROFILE_SKILLS:
        selected.extend(_PROFILE_SKILLS[profile])
    else:
        selected.extend(_PROFILE_SKILLS["default"])

    # 2. Tech-stack-based skills
    if tech_stack:
        tech_lower = " ".join(tech_stack).lower()
        for keyword, skill in _TECH_SKILLS.items():
            if keyword in tech_lower and skill not in selected:
                selected.append(skill)

    # 3. Mode-based additions
    if mode == "whitebox":
        for vuln_skill in get_available_skills().get("vulnerabilities", []):
            if vuln_skill not in selected:
                selected.append(vuln_skill)

    # 4. Agent mode always loads methodology + cloud skills
    if profile == "aggressive":
        for methodology_skill in get_available_skills().get("methodology", []):
            if methodology_skill not in selected:
                selected.append(methodology_skill)
        for cloud_skill in get_available_skills().get("cloud", []):
            if cloud_skill not in selected:
                selected.append(cloud_skill)

    # Validate against available skills
    valid, _ = validate_skill_names(selected)
    return valid
