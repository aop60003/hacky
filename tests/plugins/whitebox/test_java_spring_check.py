# tests/plugins/whitebox/test_java_spring_check.py
"""Tests for JavaSpringCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.java_spring_check import JavaSpringCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestJavaSpringCheck:
    @pytest.fixture
    def plugin(self):
        return JavaSpringCheckPlugin()

    @pytest.mark.asyncio
    async def test_csrf_disabled_detected(self, plugin, tmp_path):
        """csrf().disable() in Spring Security is flagged."""
        (tmp_path / "SecurityConfig.java").write_text(
            "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
            "@Configuration\n"
            "public class SecurityConfig {\n"
            "    protected void configure(HttpSecurity http) throws Exception {\n"
            "        http.csrf().disable()\n"
            "            .authorizeRequests().anyRequest().authenticated();\n"
            "    }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert "java_spring_" in r.rule_id
        assert r.cwe_id == "CWE-16"

    @pytest.mark.asyncio
    async def test_csrf_enabled_clean(self, plugin, tmp_path):
        """Spring Security with CSRF enabled returns empty."""
        (tmp_path / "SecurityConfig.java").write_text(
            "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
            "@Configuration\n"
            "public class SecurityConfig {\n"
            "    protected void configure(HttpSecurity http) throws Exception {\n"
            "        http.authorizeRequests().anyRequest().authenticated();\n"
            "    }\n"
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
