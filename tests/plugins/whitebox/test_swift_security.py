# tests/plugins/whitebox/test_swift_security.py
"""Tests for SwiftSecurityPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.swift_security import SwiftSecurityPlugin
from vibee_hacker.core.models import Target, Severity


class TestSwiftSecurity:
    @pytest.fixture
    def plugin(self):
        return SwiftSecurityPlugin()

    @pytest.mark.asyncio
    async def test_arbitrary_loads_detected(self, plugin, tmp_path):
        """NSAllowsArbitraryLoads=true in plist is flagged."""
        (tmp_path / "Info.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>\n'
            '  <key>NSAppTransportSecurity</key><dict>\n'
            '    <key>NSAllowsArbitraryLoads</key>\n'
            '    <true/>\n'
            '  </dict>\n'
            '</dict></plist>\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.rule_id == "swift_arbitrary_loads"
        assert r.cwe_id == "CWE-295"
        assert r.base_severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_uiwebview_detected(self, plugin, tmp_path):
        """UIWebView usage in Swift file is flagged."""
        (tmp_path / "ViewController.swift").write_text(
            'import UIKit\n'
            'class ViewController: UIViewController {\n'
            '    var webView: UIWebView!\n'
            '    override func viewDidLoad() {\n'
            '        webView = UIWebView(frame: view.bounds)\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert any(r.rule_id == "swift_uiwebview" for r in results)

    @pytest.mark.asyncio
    async def test_clean_swift_no_findings(self, plugin, tmp_path):
        """Clean Swift code using WKWebView produces no findings."""
        (tmp_path / "ViewController.swift").write_text(
            'import UIKit\n'
            'import WebKit\n'
            'class ViewController: UIViewController {\n'
            '    var webView: WKWebView!\n'
            '    override func viewDidLoad() {\n'
            '        let config = WKWebViewConfiguration()\n'
            '        webView = WKWebView(frame: view.bounds, configuration: config)\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        # No UIWebView, no NSAllowsArbitraryLoads
        uiwebview_results = [r for r in results if r.rule_id == "swift_uiwebview"]
        arbitrary_results = [r for r in results if r.rule_id == "swift_arbitrary_loads"]
        assert uiwebview_results == []
        assert arbitrary_results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        """Plugin returns empty list when no path is provided."""
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
