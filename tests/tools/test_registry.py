"""Tests for tool registry (register_tool, get_all_tools, schema generation)."""
from __future__ import annotations

import pytest
from vibee_hacker.tools.registry import (
    register_tool,
    get_tool_by_name,
    get_tool_names,
    get_tool_schema,
    get_tools,
    get_tools_prompt,
    clear_registry,
)


@pytest.fixture(autouse=True)
def isolated_registry():
    """Each test runs with a clean registry snapshot restored after."""
    from vibee_hacker.tools import registry as reg
    # Save original state
    tools_backup = list(reg._tools)
    by_name_backup = dict(reg._tools_by_name)
    schemas_backup = dict(reg._tool_schemas)
    yield
    # Restore original state
    reg._tools[:] = tools_backup
    reg._tools_by_name.clear()
    reg._tools_by_name.update(by_name_backup)
    reg._tool_schemas.clear()
    reg._tool_schemas.update(schemas_backup)


def test_register_tool_decorator_basic():
    @register_tool(description="A test tool")
    def my_test_tool_basic(x: int, y: str = "default") -> str:
        """Docstring."""
        return f"{x}{y}"

    fn = get_tool_by_name("my_test_tool_basic")
    assert fn is not None
    assert fn is my_test_tool_basic


def test_get_tool_by_name_missing_returns_none():
    result = get_tool_by_name("nonexistent_tool_xyz")
    assert result is None


def test_tool_schema_required_params():
    @register_tool(description="Schema test")
    def schema_test_tool(required_param: str, optional_param: int = 0) -> None:
        pass

    schema = get_tool_schema("schema_test_tool")
    assert schema is not None
    assert "required_param" in schema["required"]
    assert "optional_param" not in schema["required"]
    assert schema["has_params"] is True


def test_tool_schema_no_params():
    @register_tool(description="No params tool")
    def no_params_tool() -> str:
        return "ok"

    schema = get_tool_schema("no_params_tool")
    assert schema is not None
    assert schema["has_params"] is False
    assert schema["required"] == []


def test_duplicate_registration_is_ignored():
    @register_tool(description="First registration")
    def duplicate_tool_test(x: int) -> int:
        return x

    original_fn = get_tool_by_name("duplicate_tool_test")

    # Try to register again — should not overwrite
    @register_tool(description="Second registration")
    def duplicate_tool_test(x: int) -> int:  # noqa: F811
        return x * 2

    fn = get_tool_by_name("duplicate_tool_test")
    assert fn is original_fn


def test_get_tools_returns_list():
    @register_tool(description="Listed tool")
    def listed_tool_xyz() -> None:
        pass

    tools = get_tools()
    names = [t["name"] for t in tools]
    assert "listed_tool_xyz" in names


def test_get_tools_prompt_xml_format():
    @register_tool(description="XML test tool")
    def xml_test_tool(param1: str) -> str:
        return param1

    prompt = get_tools_prompt()
    assert "<tools>" in prompt
    assert "xml_test_tool" in prompt
    assert "<description>" in prompt
    assert "</tools>" in prompt
