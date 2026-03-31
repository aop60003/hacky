# tests/plugins/whitebox/test_terraform_check.py
"""Tests for TerraformCheckPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.terraform_check import TerraformCheckPlugin
from vibee_hacker.core.models import Target, Severity


class TestTerraformCheck:
    @pytest.fixture
    def plugin(self):
        return TerraformCheckPlugin()

    # ------------------------------------------------------------------ #
    # Test 1: Public S3 bucket detected
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_public_s3_detected(self, plugin, tmp_path):
        """Public S3 ACL, open ingress, no encryption, wildcard IAM are flagged."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "mybucket" {\n'
            '  bucket = "mybucket"\n'
            '  acl    = "public-read"\n'
            '}\n'
            'resource "aws_security_group_rule" "open_ingress" {\n'
            '  type        = "ingress"\n'
            '  from_port   = 22\n'
            '  to_port     = 22\n'
            '  protocol    = "tcp"\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n'
            '}\n'
            'resource "aws_s3_bucket_server_side_encryption_configuration" "no_enc" {\n'
            '  encrypted = false\n'
            '}\n'
            'resource "aws_iam_policy" "wildcard" {\n'
            '  policy = jsonencode({\n'
            '    Action = ["*"]\n'
            '  })\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        rule_ids = [r.rule_id for r in results]
        assert any("terraform_" in rid for rid in rule_ids)
        assert any("terraform_s3_public" in rid for rid in rule_ids)
        assert any("terraform_open_ingress" in rid for rid in rule_ids)
        for r in results:
            assert r.cwe_id == "CWE-284"

    # ------------------------------------------------------------------ #
    # Test 2: Secure terraform — no findings
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_secure_terraform_no_findings(self, plugin, tmp_path):
        """A hardened terraform config produces no results."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "mybucket" {\n'
            '  bucket = "mybucket"\n'
            '  acl    = "private"\n'
            '}\n'
            'resource "aws_security_group_rule" "https_only" {\n'
            '  type        = "ingress"\n'
            '  from_port   = 443\n'
            '  to_port     = 443\n'
            '  protocol    = "tcp"\n'
            '  cidr_blocks = ["10.0.0.0/8"]\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []

    # ------------------------------------------------------------------ #
    # Test 3: No .tf files — returns empty
    # ------------------------------------------------------------------ #
    @pytest.mark.asyncio
    async def test_no_tf_files_returns_empty(self, plugin, tmp_path):
        """Directories without .tf files produce no results."""
        (tmp_path / "main.py").write_text("print('hello')\n")
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert results == []
