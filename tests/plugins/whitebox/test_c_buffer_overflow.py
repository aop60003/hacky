# tests/plugins/whitebox/test_c_buffer_overflow.py
"""Tests for CBufferOverflowPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.c_buffer_overflow import CBufferOverflowPlugin
from vibee_hacker.core.models import Target, Severity


class TestCBufferOverflow:
    @pytest.fixture
    def plugin(self):
        return CBufferOverflowPlugin()

    @pytest.mark.asyncio
    async def test_strcpy_detected(self, plugin, tmp_path):
        """strcpy() without bounds checking is flagged as HIGH."""
        (tmp_path / "main.c").write_text(
            '#include <string.h>\n'
            'void copy_input(char *dest, char *src) {\n'
            '    strcpy(dest, src);\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id == "c_buffer_overflow"
        assert r.cwe_id == "CWE-120"
        assert "strcpy" in r.title.lower()

    @pytest.mark.asyncio
    async def test_gets_detected(self, plugin, tmp_path):
        """gets() usage is flagged as HIGH."""
        (tmp_path / "input.c").write_text(
            '#include <stdio.h>\n'
            'void read_input() {\n'
            '    char buf[64];\n'
            '    gets(buf);\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "c_buffer_overflow"
        assert "gets" in r.title.lower()

    @pytest.mark.asyncio
    async def test_safe_code_no_findings(self, plugin, tmp_path):
        """Code using safe alternatives produces no findings."""
        (tmp_path / "safe.c").write_text(
            '#include <string.h>\n'
            '#include <stdio.h>\n'
            'void copy_safe(char *dest, char *src, size_t n) {\n'
            '    strncpy(dest, src, n);\n'
            '    snprintf(dest, n, "%s", src);\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Plugin returns empty list when no path is provided."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
