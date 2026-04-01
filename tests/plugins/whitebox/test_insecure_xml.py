# tests/plugins/whitebox/test_insecure_xml.py
"""Tests for InsecureXmlPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.insecure_xml import InsecureXmlPlugin
from vibee_hacker.core.models import Target, Severity


class TestInsecureXml:
    @pytest.fixture
    def plugin(self):
        return InsecureXmlPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: etree.parse() found
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_etree_parse_detected(self, plugin, tmp_path):
        """Plain xml.etree.parse() is flagged as CRITICAL."""
        (tmp_path / "parser.py").write_text(
            "from xml.etree import ElementTree as ET\n"
            "tree = ET.parse('data.xml')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.CRITICAL
        assert r.rule_id == "insecure_xml_parser"
        assert r.cwe_id == "CWE-611"

    # ------------------------------------------------------------------ #
    # Test 2: defusedxml used — safe
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_defusedxml_not_flagged(self, plugin, tmp_path):
        """Files using defusedxml are not flagged."""
        (tmp_path / "parser.py").write_text(
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse('data.xml')\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No path
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Bonus: minidom detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_minidom_detected(self, plugin, tmp_path):
        (tmp_path / "xmlutil.py").write_text(
            "from xml.dom import minidom\n"
            "doc = minidom.parseString(xml_data)\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "insecure_xml_parser"
