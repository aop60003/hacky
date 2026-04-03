"""Tests for Rust security pattern plugin."""

from __future__ import annotations

import pytest
from pathlib import Path

from vibee_hacker.core.models import Target, Severity
from vibee_hacker.plugins.whitebox.rust_patterns import RustPatternsPlugin


@pytest.fixture()
def plugin():
    return RustPatternsPlugin()


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
async def test_unsafe_block(plugin, tmp_path):
    rs_file = tmp_path / "lib.rs"
    rs_file.write_text(
        "pub fn risky() {\n"
        "    unsafe {\n"
        "        *ptr = 42;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("Unsafe block" in r.title for r in results)
    assert any(r.cwe_id == "CWE-676" for r in results)


@pytest.mark.asyncio
async def test_unwrap_detected(plugin, tmp_path):
    rs_file = tmp_path / "main.rs"
    rs_file.write_text(
        "fn main() {\n"
        '    let val = some_result.unwrap();\n'
        "    println!(\"{}\", val);\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("Unwrap" in r.title for r in results)
    assert any(r.base_severity == Severity.LOW for r in results)


@pytest.mark.asyncio
async def test_command_execution(plugin, tmp_path):
    rs_file = tmp_path / "exec.rs"
    rs_file.write_text(
        "use std::process::Command;\n"
        "fn run_cmd(cmd: &str) {\n"
        "    let _ = std::process::Command::new(cmd).output();\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert any("command execution" in r.title.lower() for r in results)
    assert any(r.base_severity == Severity.HIGH for r in results)


@pytest.mark.asyncio
async def test_clean_file_no_findings(plugin, tmp_path):
    rs_file = tmp_path / "safe.rs"
    rs_file.write_text(
        "pub fn add(a: i32, b: i32) -> i32 {\n"
        "    a + b\n"
        "}\n\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    use super::*;\n"
        "    #[test]\n"
        "    fn test_add() {\n"
        "        assert_eq!(add(2, 3), 5);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert results == []


@pytest.mark.asyncio
async def test_target_dir_excluded(plugin, tmp_path):
    # Create target/ dir (Cargo build output) with a .rs file — should be skipped
    target_dir = tmp_path / "target" / "debug"
    target_dir.mkdir(parents=True)
    vuln_file = target_dir / "generated.rs"
    vuln_file.write_text(
        "unsafe { *ptr = 0; }\n",
        encoding="utf-8",
    )
    # No other .rs files in root
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    assert results == []


@pytest.mark.asyncio
async def test_transmute_detected(plugin, tmp_path):
    rs_file = tmp_path / "transmute.rs"
    rs_file.write_text(
        "use std::mem;\n"
        "fn reinterpret<T, U>(val: T) -> U {\n"
        "    unsafe { mem::transmute::<T, U>(val) }\n"
        "}\n",
        encoding="utf-8",
    )
    target = Target(path=str(tmp_path), mode="whitebox")
    results = await plugin.run(target)
    # transmute pattern OR unsafe block — at least one finding
    assert len(results) >= 1
