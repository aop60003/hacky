"""Scanner tool implementations for LLM agent interaction."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from vibee_hacker.tools.registry import register_tool

# Lazy-loaded singleton to avoid repeated disk I/O
_cached_loader = None


def _get_loader():
    global _cached_loader
    if _cached_loader is None:
        from vibee_hacker.core.plugin_loader import PluginLoader
        _cached_loader = PluginLoader()
        _cached_loader.load_builtin()
    return _cached_loader


@register_tool(description="List all available scanner plugins with their metadata.")
def list_plugins(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """List available scanner plugins, optionally filtered by category."""
    loader = _get_loader()
    plugins = []
    for p in loader.plugins:
        if category and p.category != category:
            continue
        plugins.append({
            "name": p.name,
            "description": p.description,
            "category": p.category,
            "phase": p.phase,
            "severity": str(p.base_severity),
        })
    return plugins


@register_tool(
    description="Run a specific plugin against a target.",
    requires_network=True,
)
async def run_plugin(
    plugin_name: str,
    target_url: str,
    mode: str = "blackbox",
) -> List[Dict[str, Any]]:
    """Run a single scanner plugin and return results."""
    from vibee_hacker.core.engine import ScanEngine
    from vibee_hacker.core.models import Target

    if mode not in ("blackbox", "whitebox"):
        return [{"error": f"Invalid mode: {mode}. Use 'blackbox' or 'whitebox'."}]

    if mode == "blackbox":
        target = Target(url=target_url, mode=mode)
    else:
        target = Target(path=target_url, mode=mode)

    loader = _get_loader()
    engine = ScanEngine(timeout_per_plugin=60, safe_mode=True)
    for p in loader.plugins:
        engine.register_plugin(p)

    results = await engine.scan(target, plugins=[plugin_name])
    return [r.to_dict() for r in results]


@register_tool(description="Get autofix suggestions for a vulnerability rule.")
def get_autofix(rule_id: str, language: Optional[str] = None) -> List[Dict[str, str]]:
    """Get fix suggestions for a vulnerability rule_id."""
    from vibee_hacker.core.autofix import AutofixEngine

    engine = AutofixEngine()
    fixes = engine.get_fixes(rule_id, language)
    return [
        {
            "rule_id": f.rule_id,
            "language": f.language,
            "description": f.description,
            "before": f.before,
            "after": f.after,
        }
        for f in fixes
    ]


@register_tool(description="Get available security skills and their categories.")
def list_skills() -> Dict[str, List[str]]:
    """List all available security skills organized by category."""
    from vibee_hacker.skills import get_available_skills
    return get_available_skills()
