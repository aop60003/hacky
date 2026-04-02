"""Dynamic skill loading for the agent.

Allows the agent to load security knowledge packages at runtime
based on what it discovers during the assessment.
"""

from __future__ import annotations

from typing import Any, Dict, List

from vibee_hacker.tools.registry import register_tool


@register_tool(
    description="Load a security skill (knowledge package) for the current session. "
    "Skills provide attack techniques, payloads, and remediation guidance.",
)
def load_skill(skill_name: str) -> Dict[str, Any]:
    """Load a skill and return its content.

    Args:
        skill_name: Skill name (e.g., 'xss', 'sqli', 'jwt', 'wordpress').
    """
    from vibee_hacker.skills import load_skills, get_available_skills

    loaded = load_skills([skill_name])
    if skill_name not in loaded:
        available = get_available_skills()
        all_skills = []
        for cat, names in available.items():
            all_skills.extend(names)
        return {
            "error": f"Skill '{skill_name}' not found. Available: {', '.join(all_skills)}",
        }

    return {
        "skill": skill_name,
        "content": loaded[skill_name],
        "length": len(loaded[skill_name]),
    }
