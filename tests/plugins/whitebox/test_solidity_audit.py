# tests/plugins/whitebox/test_solidity_audit.py
"""Tests for SolidityAuditPlugin."""
import pytest
from vibee_hacker.plugins.whitebox.solidity_audit import SolidityAuditPlugin
from vibee_hacker.core.models import Target, Severity


class TestSolidityAudit:
    @pytest.fixture
    def plugin(self):
        return SolidityAuditPlugin()

    @pytest.mark.asyncio
    async def test_reentrancy_detected(self, plugin, tmp_path):
        """call.value() pattern is flagged as reentrancy risk."""
        (tmp_path / "Vault.sol").write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Vault {\n'
            '    mapping(address => uint) public balances;\n'
            '    function withdraw() public {\n'
            '        uint amount = balances[msg.sender];\n'
            '        (bool success,) = msg.sender.call{value: amount}("");\n'
            '        require(success);\n'
            '        balances[msg.sender] = 0;\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = next(r for r in results if r.rule_id == "solidity_reentrancy")
        assert r.base_severity == Severity.CRITICAL
        assert r.cwe_id == "CWE-841"

    @pytest.mark.asyncio
    async def test_tx_origin_detected(self, plugin, tmp_path):
        """tx.origin authentication is flagged."""
        (tmp_path / "Auth.sol").write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Auth {\n'
            '    address owner;\n'
            '    function privileged() public {\n'
            '        require(tx.origin == owner, "Not authorized");\n'
            '        // sensitive operation\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = next(r for r in results if r.rule_id == "solidity_tx_origin")
        assert r.cwe_id == "CWE-670"

    @pytest.mark.asyncio
    async def test_selfdestruct_detected(self, plugin, tmp_path):
        """selfdestruct() usage is flagged as CRITICAL."""
        (tmp_path / "Destructible.sol").write_text(
            'pragma solidity ^0.8.0;\n'
            'contract Destructible {\n'
            '    address owner;\n'
            '    function destroy() public {\n'
            '        require(msg.sender == owner);\n'
            '        selfdestruct(payable(owner));\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        assert len(results) >= 1
        r = next(r for r in results if r.rule_id == "solidity_selfdestruct")
        assert r.base_severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_contract_no_findings(self, plugin, tmp_path):
        """Safe contract using CEI pattern produces no reentrancy findings."""
        (tmp_path / "SafeVault.sol").write_text(
            'pragma solidity ^0.8.0;\n'
            'contract SafeVault {\n'
            '    mapping(address => uint) public balances;\n'
            '    function withdraw() public {\n'
            '        uint amount = balances[msg.sender];\n'
            '        balances[msg.sender] = 0;  // state update first\n'
            '        payable(msg.sender).transfer(amount);  // then interaction\n'
            '    }\n'
            '}\n'
        )
        target = Target(path=str(tmp_path))
        results = await plugin.run(target)
        reentrancy_results = [r for r in results if r.rule_id == "solidity_reentrancy"]
        assert reentrancy_results == []
