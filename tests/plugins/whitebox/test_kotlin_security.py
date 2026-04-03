# tests/plugins/whitebox/test_kotlin_security.py
"""Tests for KotlinSecurityPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.kotlin_security import KotlinSecurityPlugin
from vibee_hacker.core.models import Target, Severity


class TestKotlinSecurity:
    @pytest.fixture
    def plugin(self):
        return KotlinSecurityPlugin()

    @pytest.mark.asyncio
    async def test_webview_js_enabled_detected(self, plugin, tmp_path):
        """setJavaScriptEnabled(true) in Kotlin file is flagged."""
        (tmp_path / "MainActivity.kt").write_text(
            'import android.webkit.WebView\n'
            'class MainActivity : AppCompatActivity() {\n'
            '    fun setupWebView(webView: WebView) {\n'
            '        webView.settings.setJavaScriptEnabled(true)\n'
            '        webView.loadUrl("https://example.com")\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "kotlin_webview_js_enabled"
        assert r.cwe_id == "CWE-749"
        assert r.base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_implicit_intent_detected(self, plugin, tmp_path):
        """Implicit Intent usage is flagged."""
        (tmp_path / "Sender.kt").write_text(
            'import android.content.Intent\n'
            'class Sender {\n'
            '    fun sendData(data: String) {\n'
            '        val intent = Intent()\n'
            '        intent.action = "com.example.SEND"\n'
            '        intent.putExtra("data", data)\n'
            '        startActivity(intent)\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert any(r.rule_id == "kotlin_implicit_intent" for r in results)

    @pytest.mark.asyncio
    async def test_clean_kotlin_no_findings(self, plugin, tmp_path):
        """Clean Kotlin with explicit intent and JS disabled produces no findings."""
        (tmp_path / "SafeActivity.kt").write_text(
            'import android.content.Intent\n'
            'import android.webkit.WebView\n'
            'class SafeActivity : AppCompatActivity() {\n'
            '    fun setupWebView(webView: WebView) {\n'
            '        // JavaScript intentionally disabled\n'
            '        webView.settings.setJavaScriptEnabled(false)\n'
            '    }\n'
            '    fun openActivity() {\n'
            '        val intent = Intent(this, TargetActivity::class.java)\n'
            '        startActivity(intent)\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        js_results = [r for r in results if r.rule_id == "kotlin_webview_js_enabled"]
        assert js_results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Plugin returns empty list when no path is provided."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
