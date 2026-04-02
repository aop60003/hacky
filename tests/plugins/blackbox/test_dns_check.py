"""Tests for DNS security check plugin."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from vibee_hacker.core.models import Target
from vibee_hacker.plugins.blackbox.dns_check import DnsCheckPlugin


class TestDnsCheckPlugin:
    @pytest.fixture
    def plugin(self):
        return DnsCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="http://example.com")

    # --- is_applicable ---

    def test_is_applicable_with_url(self, plugin, target):
        assert plugin.is_applicable(target) is True

    def test_not_applicable_no_url(self, plugin):
        t = Target(url=None)
        assert plugin.is_applicable(t) is False

    # --- run: SPF/DMARC missing when _get_txt_records returns empty ---

    @pytest.mark.asyncio
    async def test_run_returns_list_missing_spf_and_dmarc(self, plugin, target):
        """When _get_txt_records returns [] both SPF and DMARC findings are raised."""
        with patch.object(plugin, "_get_txt_records", return_value=[]):
            with patch("socket.gethostbyname", side_effect=socket.gaierror):
                results = await plugin.run(target)

        assert isinstance(results, list)
        rule_ids = [r.rule_id for r in results]
        assert "dns_missing_spf" in rule_ids
        assert "dns_missing_dmarc" in rule_ids

    # --- run: SPF present suppresses dns_missing_spf ---

    @pytest.mark.asyncio
    async def test_spf_found_no_missing_spf_result(self, plugin, target):
        """When SPF record exists, dns_missing_spf is not reported."""
        def fake_get_txt(hostname: str) -> list[str]:
            if hostname.startswith("_dmarc."):
                return []
            return ['"v=spf1 include:_spf.example.com ~all"']

        with patch.object(plugin, "_get_txt_records", side_effect=fake_get_txt):
            with patch("socket.gethostbyname", side_effect=socket.gaierror):
                results = await plugin.run(target)

        rule_ids = [r.rule_id for r in results]
        assert "dns_missing_spf" not in rule_ids
        # DMARC is still missing
        assert "dns_missing_dmarc" in rule_ids

    # --- run: both SPF and DMARC present produces no email-related findings ---

    @pytest.mark.asyncio
    async def test_spf_and_dmarc_found_no_findings(self, plugin, target):
        """When both SPF and DMARC records exist, no missing-record findings."""
        def fake_get_txt(hostname: str) -> list[str]:
            if hostname.startswith("_dmarc."):
                return ['"v=DMARC1; p=reject"']
            return ['"v=spf1 include:_spf.example.com ~all"']

        with patch.object(plugin, "_get_txt_records", side_effect=fake_get_txt):
            with patch("socket.gethostbyname", side_effect=socket.gaierror):
                results = await plugin.run(target)

        rule_ids = [r.rule_id for r in results]
        assert "dns_missing_spf" not in rule_ids
        assert "dns_missing_dmarc" not in rule_ids

    # --- run: transport/lookup exception is swallowed ---

    @pytest.mark.asyncio
    async def test_transport_error_returns_list(self, plugin, target):
        """Exceptions in _get_txt_records are swallowed; still returns a list."""
        with patch.object(plugin, "_get_txt_records", side_effect=Exception("timeout")):
            with patch("socket.gethostbyname", side_effect=socket.gaierror):
                results = await plugin.run(target)

        assert isinstance(results, list)

    # --- run: no url yields empty list ---

    @pytest.mark.asyncio
    async def test_run_no_url_returns_empty(self, plugin):
        t = Target(url=None)
        results = await plugin.run(t)
        assert results == []

    # --- wildcard DNS detection ---

    @pytest.mark.asyncio
    async def test_wildcard_dns_detected(self, plugin, target):
        """Wildcard DNS (gethostbyname succeeds) raises dns_wildcard finding."""
        with patch.object(plugin, "_get_txt_records", return_value=[
            '"v=spf1 ~all"', '"v=DMARC1; p=none"',
        ]):
            with patch("socket.gethostbyname", return_value="1.2.3.4"):
                results = await plugin.run(target)

        rule_ids = [r.rule_id for r in results]
        assert "dns_wildcard" in rule_ids
