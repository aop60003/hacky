# tests/plugins/blackbox/test_jwt_none_attack.py
"""Tests for JWT None Algorithm attack plugin."""
import base64
import json
import pytest
import httpx
from vibee_hacker.plugins.blackbox.jwt_none_attack import JwtNoneAttackPlugin, _forge_none_token
from vibee_hacker.core.models import Target, Severity


def _make_jwt(alg: str = "RS256", sub: str = "user1", with_exp: bool = True) -> str:
    """Build a minimal valid-looking JWT for testing."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": alg, "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload_data: dict = {"sub": sub}
    if with_exp:
        payload_data["exp"] = 9999999999
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).decode().rstrip("=")
    signature = "fakesignature"
    return f"{header}.{payload}.{signature}"


class TestJwtNoneAttack:
    @pytest.fixture
    def plugin(self):
        return JwtNoneAttackPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://api.example.com/profile")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_server_accepts_none_token(self, plugin, target, httpx_mock):
        """Server returns 200 without error keywords on forged none token — CRITICAL."""
        real_jwt = _make_jwt()
        # Initial response: serve a page with a JWT token
        httpx_mock.add_response(
            url="https://api.example.com/profile",
            status_code=200,
            text=f'{{"token": "{real_jwt}", "user": "alice"}}',
            headers={"Content-Type": "application/json"},
        )
        # Subsequent responses (forged token attempts): accept without error
        httpx_mock.add_response(
            status_code=200,
            text='{"user": "alice", "role": "admin"}',
            headers={"Content-Type": "application/json"},
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        assert results[0].rule_id == "jwt_none_algorithm"
        assert results[0].cwe_id == "CWE-345"
        assert results[0].base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_server_rejects_none_token(self, plugin, target, httpx_mock):
        """Server returns 401 or error body on forged token — no results."""
        real_jwt = _make_jwt()
        httpx_mock.add_response(
            url="https://api.example.com/profile",
            status_code=200,
            text=f'{{"token": "{real_jwt}"}}',
        )
        httpx_mock.add_response(
            status_code=401,
            text='{"error": "invalid signature"}',
            is_reusable=True,
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_jwt_in_response_returns_empty(self, plugin, target, httpx_mock):
        """No JWT in response — plugin returns empty without attempting forgery."""
        httpx_mock.add_response(
            url="https://api.example.com/profile",
            status_code=200,
            text="<html>Not an API page</html>",
        )
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_transport_error_returns_empty(self, plugin, httpx_mock):
        """TransportError on initial request returns empty list."""
        target = Target(url="https://down.example.com/profile")
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        results = await plugin.run(target)
        assert results == []

    def test_forge_none_token_helper(self):
        """_forge_none_token produces valid base64url header with alg=none."""
        original = _make_jwt("RS256")
        forged = _forge_none_token(original, "none")
        parts = forged.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # Empty signature
        # Decode forged header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        assert header["alg"] == "none"
