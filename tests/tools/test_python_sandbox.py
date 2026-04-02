"""Tests for Python execution sandboxing via _validate_code."""
from __future__ import annotations

import pytest
from vibee_hacker.tools.python_exec.tools import _validate_code


def test_valid_code_passes():
    code = "x = 1 + 2\nprint(x)"
    ok, msg = _validate_code(code)
    assert ok is True
    assert msg == "OK"


def test_syntax_error_blocked():
    code = "def foo(:\n    pass"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "Syntax error" in msg


def test_os_import_blocked():
    code = "import os\nos.system('ls')"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "os" in msg


def test_subprocess_blocked():
    code = "import subprocess\nsubprocess.run(['ls'])"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "subprocess" in msg


def test_subprocess_from_import_blocked():
    code = "from subprocess import run\nrun(['ls'])"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "subprocess" in msg


def test_exec_builtin_blocked():
    code = "exec('print(1)')"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "exec" in msg


def test_eval_builtin_blocked():
    code = "result = eval('1 + 1')"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "eval" in msg


def test_safe_math_allowed():
    code = "import math\nresult = math.sqrt(16)\nprint(result)"
    ok, msg = _validate_code(code)
    assert ok is True
    assert msg == "OK"


def test_safe_string_allowed():
    code = "s = 'hello world'\nprint(s.upper())\nprint(len(s))"
    ok, msg = _validate_code(code)
    assert ok is True
    assert msg == "OK"


def test_pathlib_blocked():
    code = "from pathlib import Path\nPath('/etc/passwd').read_text()"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "pathlib" in msg


def test_sys_import_blocked():
    code = "import sys\nsys.exit(0)"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "sys" in msg


def test_getattr_blocked():
    code = "a = getattr(object, '__class__')"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "getattr" in msg


def test_dunder_builtins_blocked():
    code = "x = __builtins__"
    ok, msg = _validate_code(code)
    assert ok is False
    assert "dunder" in msg.lower() or "__builtins__" in msg


def test_dunder_attribute_blocked():
    code = "x = foo.__class__.__bases__"
    ok, msg = _validate_code(code)
    assert ok is False


def test_dunder_method_call_blocked():
    code = "__builtins__.get('eval')"
    ok, msg = _validate_code(code)
    assert ok is False
