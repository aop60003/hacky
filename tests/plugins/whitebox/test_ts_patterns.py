"""Tests for TypeScript/React security pattern plugin."""

from __future__ import annotations

import pytest
from pathlib import Path

from vibee_hacker.core.models import Target, Severity
from vibee_hacker.plugins.whitebox.ts_patterns import TsPatternsPlugin


@pytest.fixture()
def plugin():
    return TsPatternsPlugin()


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_is_applicable(plugin, tmp_path):
    target_with_path = Target(path=str(tmp_path), mode="whitebox")
    target_no_path = Target(url="http://example.com", mode="blackbox")
    assert plugin.is_applicable(target_with_path) is True
    assert plugin.is_applicable(target_no_path) is False


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dangerously_set_inner_html(plugin, tmp_path):
    tsx_file = tmp_path / "Component.tsx"
    tsx_file.write_text(
        'import React from "react";\n'
        'const C = () => <div dangerouslySetInnerHTML={{ __html: userInput }} />;\n',
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("dangerouslySetInnerHTML" in r.title for r in results)
    assert any(r.cwe_id == "CWE-79" for r in results)


@pytest.mark.asyncio
async def test_eval_detected(plugin, tmp_path):
    ts_file = tmp_path / "utils.ts"
    ts_file.write_text(
        "function execute(code: string) {\n"
        "  return eval(code);\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("eval" in r.title.lower() for r in results)
    assert any(r.base_severity == Severity.HIGH for r in results)


@pytest.mark.asyncio
async def test_child_process_exec(plugin, tmp_path):
    ts_file = tmp_path / "server.ts"
    ts_file.write_text(
        'import { exec } from "child_process";\n'
        "child_process.exec(userInput, callback);\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("Command execution" in r.title for r in results)
    assert any(r.base_severity == Severity.CRITICAL for r in results)


@pytest.mark.asyncio
async def test_clean_file_no_findings(plugin, tmp_path):
    ts_file = tmp_path / "clean.ts"
    ts_file.write_text(
        "export function add(a: number, b: number): number {\n"
        "  return a + b;\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert results == []


@pytest.mark.asyncio
async def test_node_modules_excluded(plugin, tmp_path):
    # Create node_modules with a vulnerable file — should be skipped
    node_modules = tmp_path / "node_modules" / "evil-lib"
    node_modules.mkdir(parents=True)
    vuln_file = node_modules / "index.ts"
    vuln_file.write_text("eval(userInput);\n", encoding="utf-8")

    # No other .ts files in root
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert results == []


@pytest.mark.asyncio
async def test_innerHTML_detected(plugin, tmp_path):
    ts_file = tmp_path / "app.ts"
    ts_file.write_text(
        "element.innerHTML = userInput;\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("innerHTML" in r.title for r in results)
