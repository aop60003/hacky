# vibee_hacker/plugins/blackbox/deserialization_check.py
"""Insecure deserialization detection plugin."""

from __future__ import annotations

import base64
import re
import shlex

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

# Java serialized object magic bytes: AC ED 00 05
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"
# Minimal Java serialized payload prefix (rO0AB in base64 = AC ED 00 05)
JAVA_PAYLOAD = base64.b64decode("rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlchLooKBBMl8gAgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAA=")

JAVA_ERROR_PATTERNS = [
    re.compile(r"ClassNotFoundException", re.I),
    re.compile(r"ObjectInputStream", re.I),
    re.compile(r"java\.io\.", re.I),
    re.compile(r"readObject", re.I),
    re.compile(r"InvalidClassException", re.I),
    re.compile(r"StreamCorruptedException", re.I),
]

PHP_PAYLOAD = b'O:8:"stdClass":0:{}'

PHP_ERROR_PATTERNS = [
    re.compile(r"unserialize\(\)", re.I),
    re.compile(r"Unserialization error", re.I),
    re.compile(r"__wakeup", re.I),
]


class DeserializationCheckPlugin(PluginBase):
    name = "deserialization_check"
    description = "Detect insecure deserialization by sending serialized object payloads"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    detection_criteria = "Deserialization error strings in response after sending serialized payloads"
    expected_evidence = "ClassNotFoundException, ObjectInputStream, or java.io.* error in response body"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        results: list[Result] = []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Test Java deserialization
            try:
                resp = await client.post(
                    target.url,
                    content=JAVA_PAYLOAD,
                    headers={"Content-Type": "application/x-java-serialized-object"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(resp.text) <= 1_000_000:
                for pattern in JAVA_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="Insecure Java deserialization detected",
                            description=(
                                "The endpoint accepted a Java serialized object payload "
                                "(Content-Type: application/x-java-serialized-object) and returned "
                                "a deserialization error. This indicates the server deserializes "
                                "untrusted data, which can lead to Remote Code Execution."
                            ),
                            evidence=f"Pattern '{pattern.pattern}' matched in response | Status: {resp.status_code}",
                            recommendation=(
                                "Never deserialize untrusted data. Use safer data formats like JSON. "
                                "Implement deserialization filters and use Java's ObjectInputFilter. "
                                "Apply patches from the Apache Commons Collections vulnerability."
                            ),
                            cwe_id="CWE-502",
                            endpoint=target.url,
                            curl_command=(
                                f"curl -X POST {shlex.quote(target.url)} "
                                f"-H 'Content-Type: application/x-java-serialized-object' "
                                f"--data-binary $'\\xac\\xed\\x00\\x05'"
                            ),
                            rule_id="deserialization_unsafe",
                        ))
                        return results

            # Test PHP deserialization
            try:
                php_resp = await client.post(
                    target.url,
                    content=PHP_PAYLOAD,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return results

            if len(php_resp.text) <= 1_000_000:
                for pattern in PHP_ERROR_PATTERNS:
                    if pattern.search(php_resp.text):
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="Insecure PHP deserialization detected",
                            description=(
                                "The endpoint returned a PHP deserialization error after sending "
                                "a PHP serialized object payload. This may indicate unsafe use of "
                                "PHP's unserialize() function with user-controlled input."
                            ),
                            evidence=f"Pattern '{pattern.pattern}' matched in PHP deserialization probe",
                            recommendation=(
                                "Avoid using PHP's unserialize() with user-controlled input. "
                                "Use json_decode() instead. Apply integrity checks if deserialization is necessary."
                            ),
                            cwe_id="CWE-502",
                            endpoint=target.url,
                            curl_command=(
                                f"curl -X POST {shlex.quote(target.url)} "
                                f"-d 'O:8:\"stdClass\":0:{{}}'"
                            ),
                            rule_id="deserialization_unsafe",
                        ))
                        return results

        return results
