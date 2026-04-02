"""Tool registry with decorator-based registration.

Follows Strix's registry pattern: tools are registered via decorators,
discoverable at runtime, and described in XML for LLM consumption.
"""

from __future__ import annotations

import inspect
import os
from html import escape as html_escape
from typing import Any, Callable, Dict, List, Optional


# Global registry
_tools: List[Dict[str, Any]] = []
_tools_by_name: Dict[str, Callable[..., Any]] = {}
_tool_schemas: Dict[str, Dict[str, Any]] = {}


def register_tool(
    func: Optional[Callable] = None,
    *,
    description: str = "",
    requires_network: bool = False,
    requires_llm: bool = False,
    sandbox_execution: bool = True,
) -> Callable:
    """Decorator to register a function as a tool.

    Args:
        func: The function to register (auto-filled when used as @register_tool).
        description: Human-readable description of the tool.
        requires_network: If True, only registered when network is available.
        requires_llm: If True, only registered when LLM is configured.
        sandbox_execution: If True, can execute inside a sandbox.
    """
    def decorator(fn: Callable) -> Callable:
        if not _should_register(requires_network=requires_network, requires_llm=requires_llm):
            return fn

        tool_name = fn.__name__
        tool_desc = description or fn.__doc__ or ""

        # Extract parameter schema from function signature
        schema = _extract_schema(fn)

        tool_entry = {
            "name": tool_name,
            "description": tool_desc.strip(),
            "function": fn,
            "requires_network": requires_network,
            "requires_llm": requires_llm,
            "sandbox_execution": sandbox_execution,
            "module": fn.__module__,
            "schema": schema,
        }

        # Prevent duplicate registration
        if tool_name in _tools_by_name:
            return fn

        _tools.append(tool_entry)
        _tools_by_name[tool_name] = fn
        _tool_schemas[tool_name] = schema

        return fn

    if func is not None:
        return decorator(func)
    return decorator


def _should_register(requires_network: bool = False, requires_llm: bool = False) -> bool:
    """Check if a tool should be registered based on environment."""
    if requires_network and os.getenv("VIBEE_OFFLINE", "").lower() in ("1", "true"):
        return False
    if requires_llm and not os.getenv("VIBEE_LLM"):
        return False
    return True


def _extract_schema(fn: Callable) -> Dict[str, Any]:
    """Extract parameter schema from function signature."""
    sig = inspect.signature(fn)
    params: Dict[str, Dict[str, str]] = {}
    required: List[str] = []

    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue

        param_info: Dict[str, str] = {"name": name}

        # Get type annotation
        if param.annotation != inspect.Parameter.empty:
            param_info["type"] = _type_to_str(param.annotation)

        # Check if required
        if param.default == inspect.Parameter.empty:
            required.append(name)
        else:
            param_info["default"] = str(param.default)

        params[name] = param_info

    return {
        "params": params,
        "required": required,
        "has_params": bool(params),
    }


def _type_to_str(annotation: Any) -> str:
    """Convert a type annotation to a string representation."""
    if hasattr(annotation, "__name__"):
        return annotation.__name__
    return str(annotation)


def get_tool_by_name(name: str) -> Optional[Callable[..., Any]]:
    """Get a registered tool function by name."""
    return _tools_by_name.get(name)


def get_tool_names() -> List[str]:
    """Get all registered tool names."""
    return list(_tools_by_name.keys())


def get_tool_schema(name: str) -> Optional[Dict[str, Any]]:
    """Get the parameter schema for a tool."""
    return _tool_schemas.get(name)


def get_tools() -> List[Dict[str, Any]]:
    """Get all registered tool entries."""
    return list(_tools)


def get_tools_prompt() -> str:
    """Generate XML description of all tools for LLM consumption."""
    if not _tools:
        return ""

    parts = ["<tools>"]
    for tool in _tools:
        parts.append(f'  <tool name="{html_escape(tool["name"])}">')
        parts.append(f"    <description>{html_escape(tool['description'])}</description>")

        schema = tool["schema"]
        if schema["has_params"]:
            parts.append("    <parameters>")
            for pname, pinfo in schema["params"].items():
                required = "true" if pname in schema["required"] else "false"
                ptype = pinfo.get("type", "string")
                default = f' default="{pinfo["default"]}"' if "default" in pinfo else ""
                parts.append(
                    f'      <parameter name="{pname}" type="{ptype}" '
                    f'required="{required}"{default}/>'
                )
            parts.append("    </parameters>")

        parts.append("  </tool>")

    parts.append("</tools>")
    return "\n".join(parts)


def clear_registry() -> None:
    """Clear all registered tools (useful for testing)."""
    _tools.clear()
    _tools_by_name.clear()
    _tool_schemas.clear()
