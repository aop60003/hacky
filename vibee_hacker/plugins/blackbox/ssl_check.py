"""SSL/TLS certificate and configuration checks."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from vibee_hacker.core.models import InterPhaseContext, Result, Severity, Target
from vibee_hacker.core.plugin_base import PluginBase

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year in seconds


class SslCheckPlugin(PluginBase):
    name = "ssl_check"
    description = "SSL/TLS certificate validation and security checks"
    category = "blackbox"
    phase = 1
    destructive_level = 0
    detection_criteria = "Expired/expiring certificate, weak TLS protocol, or hostname mismatch"
    expected_evidence = "Certificate notAfter date, TLS version, and SAN/CN names"

    def is_applicable(self, target: Target) -> bool:
        if not target.url:
            return False
        return target.url.startswith("https://")

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []
        parsed = urlparse(target.url)
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname:
            return []

        results: list[Result] = []

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    # 1. Check certificate expiry
                    not_after = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days

                    if days_left < 0:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.CRITICAL,
                            title=f"SSL certificate expired ({abs(days_left)} days ago)",
                            description="The SSL/TLS certificate has expired.",
                            endpoint=target.url,
                            rule_id="ssl_cert_expired",
                            cwe_id="CWE-295",
                            recommendation="Renew the SSL certificate immediately.",
                        ))
                    elif days_left < 30:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.MEDIUM,
                            title=f"SSL certificate expires in {days_left} days",
                            description="The SSL certificate is expiring soon.",
                            endpoint=target.url,
                            rule_id="ssl_cert_expiring",
                            cwe_id="CWE-295",
                            recommendation="Renew the SSL certificate before it expires.",
                        ))

                    # 2. Check for weak protocol
                    if protocol and protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title=f"Weak TLS protocol: {protocol}",
                            description=f"Server uses deprecated {protocol}.",
                            endpoint=target.url,
                            rule_id="ssl_weak_protocol",
                            cwe_id="CWE-326",
                            recommendation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only.",
                        ))

                    # 3. Check subject/SAN match
                    san = [
                        entry[1]
                        for entry in cert.get("subjectAltName", [])
                        if entry[0] == "DNS"
                    ]
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    all_names = san + ([cn] if cn else [])
                    if all_names and not any(
                        self._hostname_matches(hostname, name) for name in all_names
                    ):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=Severity.HIGH,
                            title="SSL certificate hostname mismatch",
                            description=(
                                f"Certificate names {all_names} do not match {hostname}."
                            ),
                            endpoint=target.url,
                            rule_id="ssl_hostname_mismatch",
                            cwe_id="CWE-295",
                            recommendation=(
                                "Use a certificate that matches the server hostname."
                            ),
                        ))

        except ssl.SSLCertVerificationError as e:
            results.append(Result(
                plugin_name=self.name,
                base_severity=Severity.HIGH,
                title="SSL certificate verification failed",
                description=str(e),
                endpoint=target.url,
                rule_id="ssl_cert_invalid",
                cwe_id="CWE-295",
                recommendation="Fix SSL certificate issues.",
            ))
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            pass

        return results

    def _hostname_matches(self, hostname: str, pattern: str) -> bool:
        """Check if a hostname matches a certificate name (supports wildcards)."""
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".example.com"
            return hostname.endswith(suffix) or hostname == pattern[2:]
        return hostname == pattern
