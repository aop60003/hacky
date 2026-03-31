# tests/plugins/whitebox/test_java_xxe_check.py
"""Tests for JavaXxeCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.java_xxe_check import JavaXxeCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestJavaXxeCheck:
    @pytest.fixture
    def plugin(self):
        return JavaXxeCheckPlugin()

    @pytest.mark.asyncio
    async def test_dbfactory_without_secure_detected(self, plugin, tmp_path):
        """DocumentBuilderFactory without setFeature secure processing is flagged."""
        (tmp_path / "XmlParser.java").write_text(
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "public class XmlParser {\n"
            "    public void parse(InputStream is) throws Exception {\n"
            "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "        DocumentBuilder db = dbf.newDocumentBuilder();\n"
            "        Document doc = db.parse(is);\n"
            "    }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "java_xxe_unsafe"
        assert r.cwe_id == "CWE-611"

    @pytest.mark.asyncio
    async def test_secure_factory_clean(self, plugin, tmp_path):
        """DocumentBuilderFactory with FEATURE_SECURE_PROCESSING returns empty."""
        (tmp_path / "XmlParser.java").write_text(
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "import javax.xml.XMLConstants;\n"
            "public class XmlParser {\n"
            "    public void parse(InputStream is) throws Exception {\n"
            "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
            "        DocumentBuilder db = dbf.newDocumentBuilder();\n"
            "        Document doc = db.parse(is);\n"
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
