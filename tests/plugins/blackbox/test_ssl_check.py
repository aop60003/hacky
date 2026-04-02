"""Tests for SSL/TLS certificate and configuration check plugin."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from vibee_hacker.core.models import Severity, Target
from vibee_hacker.plugins.blackbox.ssl_check import SslCheckPlugin


def _make_cert(
    days_left: int = 90,
    hostname: str = "example.com",
    cn: str | None = None,
    protocol: str = "TLSv1.3",
    use_san: bool = True,
) -> tuple[dict, str]:
    """Build a mock (cert_dict, protocol_str) tuple."""
    not_after = datetime.now(timezone.utc) + timedelta(days=days_left)
    cert: dict = {
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y %Z"),
        "subject": ((("commonName", cn or hostname),),),
    }
    if use_san:
        cert["subjectAltName"] = (("DNS", hostname),)
    else:
        cert["subjectAltName"] = ()
    return cert, protocol


class _FakeSslSocket:
    """Minimal mock for ssl.SSLSocket."""

    def __init__(self, cert: dict, protocol: str):
        self._cert = cert
        self._protocol = protocol

    def getpeercert(self) -> dict:
        return self._cert

    def version(self) -> str:
        return self._protocol

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _FakeTcpSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _patch_ssl_connection(cert: dict, protocol: str):
    """Return a context manager that patches socket + ssl for SslCheckPlugin."""
    fake_ssock = _FakeSslSocket(cert, protocol)
    fake_sock = _FakeTcpSocket()

    ctx_mock = MagicMock()
    ctx_mock.wrap_socket.return_value = fake_ssock

    return (
        patch("socket.create_connection", return_value=fake_sock),
        patch("ssl.create_default_context", return_value=ctx_mock),
    )


class TestSslCheckPlugin:
    @pytest.fixture
    def plugin(self):
        return SslCheckPlugin()

    # --- is_applicable ---

    def test_is_applicable_https(self, plugin):
        t = Target(url="https://example.com")
        assert plugin.is_applicable(t) is True

    def test_not_applicable_http(self, plugin):
        t = Target(url="http://example.com")
        assert plugin.is_applicable(t) is False

    def test_not_applicable_no_url(self, plugin):
        t = Target(url=None)
        assert plugin.is_applicable(t) is False

    # --- run: connection refused returns empty ---

    @pytest.mark.asyncio
    async def test_run_connection_refused(self, plugin):
        target = Target(url="https://example.com")
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            with patch("ssl.create_default_context"):
                results = await plugin.run(target)
        assert results == []

    # --- run: socket.gaierror (DNS failure) returns empty ---

    @pytest.mark.asyncio
    async def test_run_dns_failure(self, plugin):
        target = Target(url="https://example.com")
        with patch("socket.create_connection", side_effect=socket.gaierror):
            with patch("ssl.create_default_context"):
                results = await plugin.run(target)
        assert results == []

    # --- run: valid cert with plenty of days produces no findings ---

    @pytest.mark.asyncio
    async def test_run_valid_cert_no_findings(self, plugin):
        target = Target(url="https://example.com")
        cert, proto = _make_cert(days_left=120, hostname="example.com")
        p1, p2 = _patch_ssl_connection(cert, proto)
        with p1, p2:
            results = await plugin.run(target)
        assert results == []

    # --- run: expired certificate triggers ssl_cert_expired ---

    @pytest.mark.asyncio
    async def test_run_expired_cert(self, plugin):
        target = Target(url="https://example.com")
        cert, proto = _make_cert(days_left=-5, hostname="example.com")
        p1, p2 = _patch_ssl_connection(cert, proto)
        with p1, p2:
            results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_cert_expired" in rule_ids
        exp = next(r for r in results if r.rule_id == "ssl_cert_expired")
        assert exp.base_severity == Severity.CRITICAL

    # --- run: cert expiring within 30 days triggers ssl_cert_expiring ---

    @pytest.mark.asyncio
    async def test_run_cert_expiring_soon(self, plugin):
        target = Target(url="https://example.com")
        cert, proto = _make_cert(days_left=10, hostname="example.com")
        p1, p2 = _patch_ssl_connection(cert, proto)
        with p1, p2:
            results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_cert_expiring" in rule_ids
        exp = next(r for r in results if r.rule_id == "ssl_cert_expiring")
        assert exp.base_severity == Severity.MEDIUM

    # --- run: weak TLS protocol triggers ssl_weak_protocol ---

    @pytest.mark.asyncio
    async def test_run_weak_protocol(self, plugin):
        target = Target(url="https://example.com")
        cert, _ = _make_cert(days_left=120, hostname="example.com")
        p1, p2 = _patch_ssl_connection(cert, "TLSv1")
        with p1, p2:
            results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_weak_protocol" in rule_ids
        wp = next(r for r in results if r.rule_id == "ssl_weak_protocol")
        assert wp.base_severity == Severity.HIGH

    # --- _hostname_matches ---

    def test_hostname_matches_exact(self, plugin):
        assert plugin._hostname_matches("example.com", "example.com") is True

    def test_hostname_matches_wildcard(self, plugin):
        assert plugin._hostname_matches("sub.example.com", "*.example.com") is True

    def test_hostname_not_matches_different(self, plugin):
        assert plugin._hostname_matches("other.com", "example.com") is False

    def test_hostname_not_matches_wildcard_different_domain(self, plugin):
        assert plugin._hostname_matches("sub.other.com", "*.example.com") is False

    # --- run: SSLCertVerificationError triggers ssl_cert_invalid ---

    @pytest.mark.asyncio
    async def test_run_ssl_verification_error(self, plugin):
        target = Target(url="https://example.com")
        fake_sock = _FakeTcpSocket()
        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert verify failed")
        with patch("socket.create_connection", return_value=fake_sock):
            with patch("ssl.create_default_context", return_value=ctx_mock):
                results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert "ssl_cert_invalid" in rule_ids

    # --- run: http target returns empty ---

    @pytest.mark.asyncio
    async def test_run_http_returns_empty(self, plugin):
        target = Target(url="http://example.com")
        results = await plugin.run(target)
        assert results == []

    # --- run: no url returns empty ---

    @pytest.mark.asyncio
    async def test_run_no_url_returns_empty(self, plugin):
        results = await plugin.run(Target(url=None))
        assert results == []
