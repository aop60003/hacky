# tests/plugins/blackbox/test_jwt_check.py
import base64
import json
import pytest
import httpx
from vibee_hacker.plugins.blackbox.jwt_check import JwtCheckPlugin
from vibee_hacker.core.models import Target, Severity


def _make_jwt(header: dict, payload: dict) -> str:
    """Build a fake JWT (unsigned) for testing."""
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(payload)}.fakesig"


class TestJwtCheck:
    @pytest.fixture
    def plugin(self):
        return JwtCheckPlugin()

    @pytest.fixture
    def target(self):
        return Target(url="https://example.com/api/profile")

    @pytest.mark.asyncio
    async def test_jwt_no_expiry(self, plugin, target, httpx_mock):
        # JWT without 'exp' claim in Set-Cookie header
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "name": "Alice"})
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            headers={"Set-Cookie": f"session={token}; Path=/"},
            text="<html>Profile</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = {r.rule_id for r in results}
        assert any("jwt_weak" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_jwt_pii_in_payload(self, plugin, target, httpx_mock):
        # JWT payload contains an email address
        token = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user1", "email": "alice@example.com", "exp": 9999999999},
        )
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            headers={"Set-Cookie": f"session={token}; Path=/"},
            text="<html>Profile</html>",
        )
        results = await plugin.run(target)
        assert len(results) >= 1
        rule_ids = {r.rule_id for r in results}
        assert any("pii" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_no_jwt(self, plugin, target, httpx_mock):
        # No JWT in response — returns empty
        httpx_mock.add_response(
            url="https://example.com/api/profile",
            text="<html>No tokens here</html>",
        )
        results = await plugin.run(target)
        assert results == []
