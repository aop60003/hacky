"""Tests for OOB callback server."""
import pytest
import asyncio
from vibee_hacker.core.oob_server import OOBServer, OOBCallback


class TestOOBServer:
    def test_generate_token(self):
        server = OOBServer()
        token = server.generate_token("xss_blind", "payload1")
        assert len(token) == 16
        assert token in server._tokens

    def test_generate_token_stores_plugin_info(self):
        server = OOBServer()
        token = server.generate_token("xxe", "my payload")
        assert server._tokens[token]["plugin"] == "xxe"
        assert server._tokens[token]["info"] == "my payload"

    def test_generate_unique_tokens(self):
        server = OOBServer()
        tokens = {server.generate_token("test") for _ in range(10)}
        assert len(tokens) == 10

    def test_get_callback_url(self):
        server = OOBServer(host="10.0.0.1", port=8888)
        token = server.generate_token("xxe")
        url = server.get_callback_url(token)
        assert "http://10.0.0.1:8888/cb/" in url
        assert token in url

    def test_get_callback_url_default(self):
        server = OOBServer()
        token = server.generate_token("test")
        url = server.get_callback_url(token)
        assert url == f"http://0.0.0.0:9999/cb/{token}"

    def test_check_token_not_found(self):
        server = OOBServer()
        assert server.check_token("nonexistent") is None

    def test_check_token_found(self):
        server = OOBServer()
        token = server.generate_token("test")
        server.callbacks.append(OOBCallback(
            token=token,
            source_ip="1.2.3.4",
            path=f"/cb/{token}",
            method="GET",
            headers={},
            body="",
        ))
        result = server.check_token(token)
        assert result is not None
        assert result.source_ip == "1.2.3.4"

    def test_has_callbacks_empty(self):
        server = OOBServer()
        assert not server.has_callbacks

    def test_has_callbacks(self):
        server = OOBServer()
        assert not server.has_callbacks
        server.callbacks.append(OOBCallback(
            token="t", source_ip="x", path="/", method="GET", headers={}, body=""
        ))
        assert server.has_callbacks

    def test_oob_callback_dataclass(self):
        from datetime import timezone
        cb = OOBCallback(
            token="abc", source_ip="1.2.3.4", path="/cb/abc",
            method="POST", headers={"X-Test": "1"}, body="hello"
        )
        assert cb.token == "abc"
        assert cb.source_ip == "1.2.3.4"
        assert cb.method == "POST"
        assert cb.body == "hello"
        assert cb.timestamp is not None

    @pytest.mark.asyncio
    async def test_start_stop(self):
        server = OOBServer(host="127.0.0.1", port=19999)
        srv = await server.start()
        assert server._running
        await server.stop()
        assert not server._running

    @pytest.mark.asyncio
    async def test_http_callback_received(self):
        """Actually send an HTTP request to OOB server and verify callback captured."""
        import httpx
        server = OOBServer(host="127.0.0.1", port=20001)
        token = server.generate_token("test_plugin")
        await server.start()
        await asyncio.sleep(0.1)
        try:
            async with httpx.AsyncClient() as client:
                await client.get(f"http://127.0.0.1:20001/cb/{token}", timeout=3.0)
            await asyncio.sleep(0.1)
            cb = server.check_token(token)
            assert cb is not None
            assert token in cb.path
        finally:
            await server.stop()
