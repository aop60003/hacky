# tests/plugins/whitebox/test_js_nestjs_check.py
"""Tests for JsNestjsCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.js_nestjs_check import JsNestjsCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestJsNestjsCheck:
    @pytest.fixture
    def plugin(self):
        return JsNestjsCheckPlugin()

    @pytest.mark.asyncio
    async def test_controller_without_guard_detected(self, plugin, tmp_path):
        """NestJS @Controller without @UseGuards is flagged as HIGH."""
        (tmp_path / "users.controller.ts").write_text(
            "import { Controller, Get } from '@nestjs/common';\n"
            "@Controller('users')\n"
            "export class UsersController {\n"
            "  @Get()\n"
            "  findAll() { return []; }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = results[0]
        assert r.base_severity == Severity.HIGH
        assert r.rule_id.startswith("js_nestjs_")
        assert r.cwe_id == "CWE-862"

    @pytest.mark.asyncio
    async def test_guarded_controller_clean(self, plugin, tmp_path):
        """Controller with @UseGuards returns empty."""
        (tmp_path / "users.controller.ts").write_text(
            "import { Controller, Get, UseGuards } from '@nestjs/common';\n"
            "import { AuthGuard } from './auth.guard';\n"
            "@UseGuards(AuthGuard)\n"
            "@Controller('users')\n"
            "export class UsersController {\n"
            "  @Get()\n"
            "  findAll() { return []; }\n"
            "}\n"
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_path_returns_empty(self, plugin):
        target = Target(url="https://example.com")
        results = await plugin.run(target)
        assert results == []
