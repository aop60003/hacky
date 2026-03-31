# tests/plugins/whitebox/test_js_xss_pattern.py
"""Tests for JsXssPatternPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_xss_pattern import JsXssPatternPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsXssPattern:
    @pytest.fixture
    def plugin(self):
        return JsXssPatternPlugin()

    @pytest.mark.asyncio
    async def test_dangerous_inner_html_detected(self, plugin, tmp_path):
        """dangerouslySetInnerHTML in JSX is flagged as HIGH."""
        (tmp_path / "Component.jsx").write_text(
            "function MyComponent({ html }) {\n"
            "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "js_xss_pattern"
        assert r.cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_clean_jsx(self, plugin, tmp_path):
        """Clean JSX without XSS patterns returns empty."""
        (tmp_path / "Component.jsx").write_text(
            "function MyComponent({ name }) {\n"
            "  return <div>{name}</div>;\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
