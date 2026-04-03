"""Tests for AutofixPR generator."""

from __future__ import annotations

import pytest
from pathlib import Path

from vibee_hacker.core.autofix_pr import FixPatch, AutofixPR, AutofixPRGenerator
from vibee_hacker.core.models import Result, Severity


# ---------------------------------------------------------------------------
# FixPatch tests
# ---------------------------------------------------------------------------

def test_fix_patch_fields():
    patch = FixPatch(
        file_path="app/views.py",
        original_line='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        fixed_line='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        line_number=42,
        description="Use parameterized queries",
        rule_id="sqli",
    )
    assert patch.file_path == "app/views.py"
    assert patch.line_number == 42
    assert patch.rule_id == "sqli"
    assert "parameterized" in patch.description


# ---------------------------------------------------------------------------
# AutofixPR tests
# ---------------------------------------------------------------------------

def _make_pr_with_patches() -> AutofixPR:
    patches = [
        FixPatch(
            file_path="app/views.py",
            original_line='cursor.execute(f"SELECT")',
            fixed_line='cursor.execute("SELECT %s", (v,))',
            line_number=10,
            description="Use parameterized queries",
            rule_id="sqli",
        ),
        FixPatch(
            file_path="app/utils.py",
            original_line='return f"<p>{user_input}</p>"',
            fixed_line='return f"<p>{escape(user_input)}</p>"',
            line_number=25,
            description="Use HTML escaping",
            rule_id="xss",
        ),
    ]
    return AutofixPR(
        title="fix(security): auto-fix 2 vulnerabilities",
        body="",
        branch_name="autofix/vibee-2-fixes",
        patches=patches,
        findings_fixed=2,
    )


def test_autofix_pr_to_dict():
    pr = _make_pr_with_patches()
    d = pr.to_dict()
    assert d["title"] == "fix(security): auto-fix 2 vulnerabilities"
    assert d["findings_fixed"] == 2
    assert len(d["patches"]) == 2
    assert d["patches"][0]["file"] == "app/views.py"
    assert d["patches"][0]["line"] == 10
    assert "branch_name" in d


def test_generate_diff():
    pr = _make_pr_with_patches()
    diff = pr.generate_diff()
    assert "--- a/app/views.py" in diff
    assert "+++ b/app/views.py" in diff
    assert "@@ -10,1 +10,1 @@" in diff
    assert "-cursor.execute" in diff
    assert "+cursor.execute" in diff
    # Second patch
    assert "--- a/app/utils.py" in diff


def test_generate_commit_message():
    pr = _make_pr_with_patches()
    msg = pr.generate_commit_message()
    assert msg.startswith("fix(security):")
    assert "2" in msg
    # rules sorted
    assert "sqli" in msg
    assert "xss" in msg


def test_generate_pr_body():
    pr = _make_pr_with_patches()
    body = pr.generate_pr_body()
    assert "## Security Autofix" in body
    assert "**Findings fixed:** 2" in body
    assert "app/views.py:10" in body
    assert "app/utils.py:25" in body
    assert "VIBEE-Hacker Autofix" in body


def test_generate_script():
    pr = _make_pr_with_patches()
    gen = AutofixPRGenerator()
    script = gen.generate_script(pr)
    assert "#!/bin/bash" in script
    assert f"git checkout -b {pr.branch_name}" in script
    assert "git add -A" in script
    assert "git commit -m" in script
    assert "git push origin" in script
    assert "gh pr create" in script


# ---------------------------------------------------------------------------
# AutofixPRGenerator tests
# ---------------------------------------------------------------------------

def test_generator_no_results_returns_none():
    gen = AutofixPRGenerator()
    result = gen.generate([])
    assert result is None


def test_generator_no_fixes_for_unknown_rule():
    gen = AutofixPRGenerator()
    results = [
        Result(
            plugin_name="unknown_plugin",
            base_severity=Severity.HIGH,
            title="Unknown vulnerability",
            description="Some issue",
            rule_id="no_such_rule_xyz",
            endpoint="app/views.py",
        )
    ]
    pr = gen.generate(results)
    assert pr is None


def test_generator_with_matching_file(tmp_path):
    # Create a file with a known vulnerable pattern
    vuln_file = tmp_path / "views.py"
    vuln_file.write_text(
        'def get_user(user_id):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        '    return cursor.fetchone()\n',
        encoding="utf-8",
    )

    gen = AutofixPRGenerator(repo_path=str(tmp_path))
    results = [
        Result(
            plugin_name="py_sql_pattern",
            base_severity=Severity.HIGH,
            title="SQL Injection",
            description="Found SQL injection",
            rule_id="sqli",
            endpoint="views.py",
        )
    ]
    pr = gen.generate(results, language="python")
    assert pr is not None
    assert pr.findings_fixed >= 1
    assert len(pr.patches) >= 1
    assert pr.patches[0].rule_id == "sqli"
    assert "autofix/vibee-" in pr.branch_name


def test_apply_patches(tmp_path):
    vuln_file = tmp_path / "views.py"
    original_content = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    vuln_file.write_text(original_content, encoding="utf-8")

    patch = FixPatch(
        file_path="views.py",
        original_line='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        fixed_line='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        line_number=1,
        description="Use parameterized queries",
        rule_id="sqli",
    )
    pr = AutofixPR(
        title="fix test",
        body="",
        branch_name="autofix/vibee-1-fixes",
        patches=[patch],
        findings_fixed=1,
    )

    gen = AutofixPRGenerator(repo_path=str(tmp_path))
    modified = gen.apply_patches(pr)
    assert modified == 1

    new_content = vuln_file.read_text(encoding="utf-8")
    assert "parameterized" not in original_content
    assert "%s" in new_content


def test_branch_name_format(tmp_path):
    vuln_file = tmp_path / "views.py"
    vuln_file.write_text(
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
        encoding="utf-8",
    )

    gen = AutofixPRGenerator(repo_path=str(tmp_path))
    results = [
        Result(
            plugin_name="py_sql_pattern",
            base_severity=Severity.HIGH,
            title="SQL Injection",
            description="Found SQL injection",
            rule_id="sqli",
            endpoint="views.py",
        )
    ]
    pr = gen.generate(results, language="python")
    assert pr is not None
    assert pr.branch_name.startswith("autofix/vibee-")
    assert pr.branch_name.endswith("-fixes")
