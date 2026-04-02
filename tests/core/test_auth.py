"""Tests for the authentication framework."""

from __future__ import annotations

import pytest
import httpx

from vibee_hacker.core.auth import AuthConfig, AuthHandler


# ---------------------------------------------------------------------------
# test_auth_config_defaults
# ---------------------------------------------------------------------------

def test_auth_config_defaults():
    config = AuthConfig()
    assert config.login_url == ""
    assert config.username == ""
    assert config.password == ""
    assert config.username_field == "username"
    assert config.password_field == "password"
    assert config.success_pattern == ""
    assert config.token_header == ""
    assert config.token_pattern == ""
    assert config.cookie_names == []


def test_auth_config_custom_fields():
    config = AuthConfig(
        login_url="http://example.com/login",
        username="admin",
        password="secret",
        username_field="email",
        password_field="pass",
        success_pattern="Welcome",
        token_header="Authorization",
        token_pattern=r'"token":"([^"]+)"',
        cookie_names=["session", "csrf"],
    )
    assert config.login_url == "http://example.com/login"
    assert config.username == "admin"
    assert config.username_field == "email"
    assert config.cookie_names == ["session", "csrf"]


# ---------------------------------------------------------------------------
# test_auth_headers_empty
# ---------------------------------------------------------------------------

def test_auth_headers_empty():
    handler = AuthHandler(AuthConfig())
    assert handler.auth_headers == {}
    assert handler.is_authenticated is False


# ---------------------------------------------------------------------------
# test_auth_headers_with_cookies
# ---------------------------------------------------------------------------

def test_auth_headers_with_cookies():
    handler = AuthHandler(AuthConfig())
    handler._cookies["session"] = "abc123"
    handler._cookies["csrf"] = "xyz789"
    handler._authenticated = True

    headers = handler.auth_headers
    assert "Cookie" in headers
    assert "session=abc123" in headers["Cookie"]
    assert "csrf=xyz789" in headers["Cookie"]


def test_auth_headers_with_token():
    handler = AuthHandler(AuthConfig(token_header="Authorization"))
    handler._headers["Authorization"] = "Bearer mytoken"
    handler._authenticated = True

    headers = handler.auth_headers
    assert headers.get("Authorization") == "Bearer mytoken"
    assert "Cookie" not in headers


def test_auth_headers_with_both_cookie_and_token():
    handler = AuthHandler(AuthConfig())
    handler._cookies["session"] = "sess1"
    handler._headers["X-Auth-Token"] = "tok1"
    handler._authenticated = True

    headers = handler.auth_headers
    assert "Cookie" in headers
    assert headers["X-Auth-Token"] == "tok1"


# ---------------------------------------------------------------------------
# test_login_success (httpx_mock)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_success(httpx_mock):
    """Login should capture cookies and mark authenticated."""
    httpx_mock.add_response(
        url="http://auth.test/login",
        status_code=200,
        text="Welcome back, admin!",
        headers={"Set-Cookie": "session=abc123; Path=/"},
    )

    config = AuthConfig(
        login_url="http://auth.test/login",
        username="admin",
        password="secret",
        success_pattern="Welcome back",
    )
    handler = AuthHandler(config)

    async with httpx.AsyncClient() as client:
        result = await handler.login(client)

    assert result is True
    assert handler.is_authenticated is True
    assert "session" in handler._cookies


@pytest.mark.asyncio
async def test_login_success_with_token(httpx_mock):
    """Login should extract JWT token from response body."""
    httpx_mock.add_response(
        url="http://auth.test/api/login",
        status_code=200,
        text='{"token": "eyJhbGci.eyJzdWIi.sig", "user": "admin"}',
    )

    config = AuthConfig(
        login_url="http://auth.test/api/login",
        username="admin",
        password="pass",
        token_header="Authorization",
        token_pattern=r'"token":\s*"([^"]+)"',
    )
    handler = AuthHandler(config)

    async with httpx.AsyncClient() as client:
        result = await handler.login(client)

    assert result is True
    assert handler.is_authenticated is True
    assert handler._headers.get("Authorization") == "eyJhbGci.eyJzdWIi.sig"
    assert "Authorization" in handler.auth_headers


# ---------------------------------------------------------------------------
# test_login_failure (httpx_mock)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_failure_no_pattern_match(httpx_mock):
    """Login should fail if success_pattern is not found in response."""
    httpx_mock.add_response(
        url="http://auth.test/login",
        status_code=200,
        text="Invalid username or password",
    )

    config = AuthConfig(
        login_url="http://auth.test/login",
        username="admin",
        password="wrong",
        success_pattern="Welcome back",
    )
    handler = AuthHandler(config)

    async with httpx.AsyncClient() as client:
        result = await handler.login(client)

    assert result is False
    assert handler.is_authenticated is False


@pytest.mark.asyncio
async def test_login_failure_no_login_url():
    """Login should return False immediately if login_url is empty."""
    handler = AuthHandler(AuthConfig())
    result = await handler.login()
    assert result is False
    assert handler.is_authenticated is False


@pytest.mark.asyncio
async def test_login_failure_network_error(httpx_mock):
    """Login should return False on network error."""
    httpx_mock.add_exception(httpx.ConnectError("connection refused"))

    config = AuthConfig(
        login_url="http://auth.test/login",
        username="admin",
        password="secret",
    )
    handler = AuthHandler(config)
    result = await handler.login()
    assert result is False
    assert handler.is_authenticated is False


# ---------------------------------------------------------------------------
# test_reset
# ---------------------------------------------------------------------------

def test_reset_clears_state():
    handler = AuthHandler(AuthConfig())
    handler._cookies["session"] = "abc"
    handler._headers["Authorization"] = "Bearer tok"
    handler._authenticated = True

    handler.reset()

    assert handler.is_authenticated is False
    assert handler._cookies == {}
    assert handler._headers == {}
    assert handler.auth_headers == {}


# ---------------------------------------------------------------------------
# test_refresh_if_needed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_refresh_if_needed_already_authenticated(httpx_mock):
    """Should return True without re-logging in when already authenticated."""
    handler = AuthHandler(AuthConfig())
    handler._authenticated = True

    async with httpx.AsyncClient() as client:
        result = await handler.refresh_if_needed(client)

    assert result is True
    # No requests should have been made
    assert len(httpx_mock.get_requests()) == 0


@pytest.mark.asyncio
async def test_refresh_if_needed_triggers_login(httpx_mock):
    """Should attempt login when not authenticated."""
    httpx_mock.add_response(
        url="http://auth.test/login",
        status_code=200,
        text="OK",
        headers={"Set-Cookie": "session=fresh; Path=/"},
    )

    config = AuthConfig(login_url="http://auth.test/login", username="u", password="p")
    handler = AuthHandler(config)
    assert handler.is_authenticated is False

    async with httpx.AsyncClient() as client:
        result = await handler.refresh_if_needed(client)

    assert result is True
    assert handler.is_authenticated is True


# ---------------------------------------------------------------------------
# Cookie filtering: cookie_names whitelist
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_login_cookie_name_filter(httpx_mock):
    """Only whitelisted cookie names should be captured."""
    httpx_mock.add_response(
        url="http://auth.test/login",
        status_code=200,
        text="OK",
        # Multiple cookies in response
        headers=[
            ("Set-Cookie", "session=abc; Path=/"),
            ("Set-Cookie", "tracking=xyz; Path=/"),
        ],
    )

    config = AuthConfig(
        login_url="http://auth.test/login",
        username="u",
        password="p",
        cookie_names=["session"],  # only capture "session"
    )
    handler = AuthHandler(config)

    async with httpx.AsyncClient() as client:
        result = await handler.login(client)

    # "session" should be captured; "tracking" should be ignored
    assert "session" in handler._cookies
    assert "tracking" not in handler._cookies
