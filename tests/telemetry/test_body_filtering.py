"""Tests for telemetry response body sensitive data filtering."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from vibee_hacker.telemetry.tracer import Tracer, _sanitize


# ---- _sanitize unit tests ----

def test_jwt_redacted():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = _sanitize(f"response body: {jwt}")
    assert jwt not in result
    assert "[REDACTED]" in result


def test_json_password_redacted():
    text = '{"username": "admin", "password": "supersecret123"}'
    result = _sanitize(text)
    assert "supersecret123" not in result
    assert "[REDACTED]" in result


def test_aws_key_redacted():
    text = "Access key: AKIAIOSFODNN7EXAMPLE"
    result = _sanitize(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "[REDACTED]" in result


def test_normal_text_unchanged():
    text = "Host: example.com\nContent-Type: application/json\nStatus: 200 OK"
    result = _sanitize(text)
    assert result == text


def test_mixed_content_partial_redaction():
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    text = f"User logged in from 192.168.1.1. Key={aws_key}. Session active."
    result = _sanitize(text)
    assert aws_key not in result
    assert "[REDACTED]" in result
    # Non-sensitive parts should remain
    assert "192.168.1.1" in result
    assert "Session active" in result


@pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not applicable on Windows")
def test_file_permissions(tmp_path):
    """JSONL output files should be created with 0o600 permissions."""
    tracer = Tracer(scan_id="perm-test", enabled=True, output_dir=str(tmp_path))
    tracer.log_scan_started("http://example.com", "blackbox", 3)

    events_file = tracer.events_file
    assert events_file.exists()

    file_mode = stat.S_IMODE(os.stat(events_file).st_mode)
    assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
