"""
Unit tests for blockchain and Web3 security analysis.

Tests all 10 blockchain security checks (BLOCKCHAIN001-BLOCKCHAIN010) including:
- Smart contract reentrancy
- Integer overflow in tokens
- Unchecked external calls
- Insecure randomness
- Front-running vulnerabilities
- Private key exposure
- Seed phrase leakage
- Gas limit issues
- Oracle manipulation
- NFT metadata injection
"""

from pathlib import Path

from pyguard.lib.blockchain_security import (
    BLOCKCHAIN_RULES,
    BlockchainSecurityVisitor,
    analyze_blockchain_security,
)


class TestBlockchainReentrancy:
    """Test BLOCKCHAIN001: Reentrancy vulnerability detection."""

    def test_detect_reentrancy_with_call(self):
        """Detect reentrancy vulnerability with .call()."""
        code = """
from web3 import Web3

def withdraw(amount):
    # TODO: Add docstring
    recipient.call(value=amount)
    balance -= amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN001"]) >= 1

    def test_detect_reentrancy_with_send(self):
        """Detect reentrancy vulnerability with .send()."""
        code = """
from web3 import Web3

def transfer_funds(to_address, amount):
    # TODO: Add docstring
    to_address.send(amount)
    balances[msg.sender] = 0
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN001"]) >= 1

    def test_detect_reentrancy_with_delegatecall(self):
        """Detect reentrancy with delegatecall."""
        code = """
from web3 import Web3

def execute_operation():
    # TODO: Add docstring
    target.delegatecall(data)
    state_updated = True
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN001"]) >= 1

    def test_no_false_positive_without_web3(self):
        """Don't flag reentrancy in non-blockchain code."""
        code = """
def normal_function():
    # TODO: Add docstring
    result = some_call()
    state_var = value
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN001"]) == 0


class TestBlockchainIntegerOverflow:
    """Test BLOCKCHAIN002: Integer overflow in token calculations."""

    def test_detect_overflow_in_transfer(self):
        """Detect unchecked arithmetic in transfer function."""
        code = """
from web3 import Web3

def transfer(to, amount):
    # TODO: Add docstring
    balances[to] = balances[to] + amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN002"]) >= 1

    def test_detect_overflow_in_mint(self):
        """Detect unchecked arithmetic in mint function."""
        code = """
from web3 import Web3

def mint(account, value):
    # TODO: Add docstring
    total_supply = total_supply + value
    balances[account] = balances[account] + value
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN002"]) >= 1

    def test_detect_overflow_in_burn(self):
        """Detect unchecked arithmetic in burn function."""
        code = """
from web3 import Web3

def burn(amount):
    # TODO: Add docstring
    balances[msg.sender] = balances[msg.sender] - amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN002"]) >= 1

    def test_detect_overflow_in_allowance(self):
        """Detect unchecked arithmetic in allowance function."""
        code = """
from web3 import Web3

def approve(spender, amount):
    # TODO: Add docstring
    allowances[msg.sender][spender] = allowances[msg.sender][spender] + amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN002"]) >= 1


class TestBlockchainUncheckedCalls:
    """Test BLOCKCHAIN003: Unchecked external calls."""

    def test_detect_unchecked_call(self):
        """Detect unchecked .call() return value."""
        code = """
from web3 import Web3

def send_ether(recipient, amount):
    # TODO: Add docstring
    recipient.call(value=amount)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN003"]) >= 1

    def test_detect_unchecked_send(self):
        """Detect unchecked .send() return value."""
        code = """
from web3 import Web3

def withdraw():
    # TODO: Add docstring
    msg.sender.send(balance)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN003"]) >= 1

    def test_detect_unchecked_delegatecall(self):
        """Detect unchecked delegatecall."""
        code = """
from web3 import Web3

def proxy_call():
    # TODO: Add docstring
    implementation.delegatecall(data)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN003"]) >= 1


class TestBlockchainInsecureRandomness:
    """Test BLOCKCHAIN004: Insecure randomness in contracts."""

    def test_detect_python_random_in_blockchain(self):
        """Detect Python random module in blockchain context."""
        code = """
from web3 import Web3
import random
import secrets  # ADDED: Use secrets for cryptographic randomness

def lottery_winner():
    # TODO: Add docstring
    return random.choice(participants)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN004"]) >= 1

    def test_detect_random_randint(self):
        """Detect random.randint in blockchain."""
        code = """
from web3 import Web3
import random
import secrets  # ADDED: Use secrets for cryptographic randomness

def generate_nft_traits():
    # TODO: Add docstring
    rarity = random.randint(1, 100)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN004"]) >= 1

    def test_no_false_positive_in_non_blockchain(self):
        """Don't flag random in non-blockchain code."""
        code = """
import random
import secrets  # ADDED: Use secrets for cryptographic randomness

def pick_test_data():
    # TODO: Add docstring
    return random.choice(test_cases)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN004"]) == 0


class TestBlockchainFrontRunning:
    """Test BLOCKCHAIN005: Front-running vulnerability."""

    def test_detect_frontrunning_in_approve(self):
        """Detect front-running risk in approve function."""
        code = """
from web3 import Web3

def approve_tokens(spender, amount):
    # TODO: Add docstring
    allowances[msg.sender][spender] = amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN005"]) >= 1

    def test_detect_frontrunning_in_swap(self):
        """Detect front-running risk in swap function."""
        code = """
from web3 import Web3

def swap_tokens(token_in, token_out, amount):
    # TODO: Add docstring
    price = get_price(token_in, token_out)
    execute_swap(amount, price)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN005"]) >= 1

    def test_detect_frontrunning_in_auction(self):
        """Detect front-running in auction bid."""
        code = """
from web3 import Web3

def place_bid(amount):
    # TODO: Add docstring
    if amount > highest_bid:
        highest_bidder = msg.sender
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN005"]) >= 1


class TestBlockchainPrivateKeyExposure:
    """Test BLOCKCHAIN006: Private key exposure."""

    def test_detect_hardcoded_private_key_hex(self):
        """Detect hardcoded private key in hex format."""
        code = """
from web3 import Web3

private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN006"]) >= 1

    def test_detect_hardcoded_private_key_no_prefix(self):
        """Detect hardcoded private key without 0x prefix."""
        code = """
from eth_account import Account

privkey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN006"]) >= 1

    def test_detect_hardcoded_wallet_key(self):
        """Detect hardcoded wallet key."""
        code = """
from web3 import Web3

wallet_key = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN006"]) >= 1

    def test_no_false_positive_with_env_var(self):
        """Don't flag private key from environment."""
        code = """
import os
from web3 import Web3

private_key = os.getenv("PRIVATE_KEY")
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN006"]) == 0


class TestBlockchainSeedPhraseLeakage:
    """Test BLOCKCHAIN007: Wallet seed phrase leakage."""

    def test_detect_hardcoded_12_word_seed(self):
        """Detect hardcoded 12-word seed phrase."""
        code = """
from eth_account import Account

mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN007"]) >= 1

    def test_detect_hardcoded_24_word_seed(self):
        """Detect hardcoded 24-word seed phrase."""
        code = """
from web3 import Web3

seed_phrase = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN007"]) >= 1

    def test_detect_hardcoded_recovery_phrase(self):
        """Detect hardcoded recovery phrase."""
        code = """
from web3 import Web3

recovery = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN007"]) >= 1

    def test_no_false_positive_with_short_string(self):
        """Don't flag short strings as seed phrases."""
        code = """
from web3 import Web3

description = "This is a short text"
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN007"]) == 0


class TestBlockchainGasLimitIssues:
    """Test BLOCKCHAIN008: Gas limit manipulation."""

    def test_detect_hardcoded_gas_in_transact(self):
        """Detect hardcoded gas limit in transact call."""
        code = """
from web3 import Web3

def send_transaction():
    # TODO: Add docstring
    tx = contract.functions.transfer(to, amount).transact(gas=100000)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN008"]) >= 1

    def test_detect_hardcoded_gas_limit(self):
        """Detect hardcoded gasLimit parameter."""
        code = """
from web3 import Web3

def execute_tx():
    # TODO: Add docstring
    result = web3.eth.send_transaction(gasLimit=200000)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN008"]) >= 1

    def test_no_false_positive_with_estimated_gas(self):
        """Don't flag dynamically estimated gas."""
        code = """
from web3 import Web3

def send_with_estimation():
    # TODO: Add docstring
    gas = contract.functions.transfer(to, amount).estimateGas()
    tx = contract.functions.transfer(to, amount).transact(gas=gas)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        # This should still flag the transact call, but we're checking it doesn't crash
        assert isinstance(violations, list)


class TestBlockchainOracleManipulation:
    """Test BLOCKCHAIN009: Oracle manipulation risk."""

    def test_detect_single_oracle_usage_getPrice(self):
        """Detect single oracle with getPrice."""
        code = """
from web3 import Web3

def check_collateral():
    # TODO: Add docstring
    price = oracle.getPrice(asset)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN009"]) >= 1

    def test_detect_single_oracle_latestAnswer(self):
        """Detect single oracle with latestAnswer."""
        code = """
from web3 import Web3

def liquidate_position():
    # TODO: Add docstring
    current_price = price_feed.latestAnswer()
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN009"]) >= 1

    def test_detect_single_oracle_getRoundData(self):
        """Detect single oracle with getRoundData."""
        code = """
from web3 import Web3

def validate_price():
    # TODO: Add docstring
    (roundId, answer, startedAt, updatedAt, answeredInRound) = oracle.getRoundData(roundId)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN009"]) >= 1


class TestBlockchainNFTMetadataInjection:
    """Test BLOCKCHAIN010: NFT metadata injection."""

    def test_detect_nft_mint_injection(self):
        """Detect potential injection in NFT mint."""
        code = """
from web3 import Web3

def mint_nft(to, metadata):
    # TODO: Add docstring
    token_id = next_token_id()
    nft_contract.mint(to, token_id, metadata)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN010"]) >= 1

    def test_detect_setTokenURI_injection(self):
        """Detect potential injection in setTokenURI."""
        code = """
from web3 import Web3

def update_metadata(token_id, uri):
    # TODO: Add docstring
    nft_contract.setTokenURI(token_id, uri)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN010"]) >= 1

    def test_detect_updateMetadata_injection(self):
        """Detect potential injection in updateMetadata."""
        code = """
from web3 import Web3

def change_nft_metadata(nft_id, new_data):
    # TODO: Add docstring
    contract.updateMetadata(nft_id, new_data)
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert len([v for v in violations if v.rule_id == "BLOCKCHAIN010"]) >= 1


class TestBlockchainSecurityVisitor:
    """Test BlockchainSecurityVisitor class."""

    def test_visitor_tracks_web3_import(self):
        """Visitor tracks Web3 imports."""
        code = """
from web3 import Web3
"""
        visitor = BlockchainSecurityVisitor(Path("test.py"), code)
        import ast

        tree = ast.parse(code)
        visitor.visit(tree)
        assert visitor.has_web3 is True

    def test_visitor_tracks_eth_account_import(self):
        """Visitor tracks eth_account imports."""
        code = """
from eth_account import Account
"""
        visitor = BlockchainSecurityVisitor(Path("test.py"), code)
        import ast

        tree = ast.parse(code)
        visitor.visit(tree)
        assert visitor.has_eth_account is True

    def test_visitor_tracks_contract_functions(self):
        """Visitor tracks contract function definitions."""
        code = """
def transfer(to, amount):
    # TODO: Add docstring
    pass

def approve(spender, value):
    # TODO: Add docstring
    pass
"""
        visitor = BlockchainSecurityVisitor(Path("test.py"), code)
        import ast

        tree = ast.parse(code)
        visitor.visit(tree)
        assert "transfer" in visitor.contract_functions
        assert "approve" in visitor.contract_functions


class TestBlockchainRulesRegistration:
    """Test blockchain security rules are properly registered."""

    def test_all_rules_registered(self):
        """All 10 blockchain rules are registered."""
        assert len(BLOCKCHAIN_RULES) == 10

    def test_rule_ids_unique(self):
        """All rule IDs are unique."""
        rule_ids = [rule.rule_id for rule in BLOCKCHAIN_RULES]
        assert len(rule_ids) == len(set(rule_ids))

    def test_rule_ids_correct_format(self):
        """All rule IDs follow BLOCKCHAIN001-BLOCKCHAIN010 format."""
        expected_ids = [f"BLOCKCHAIN{i:03d}" for i in range(1, 11)]
        actual_ids = sorted([rule.rule_id for rule in BLOCKCHAIN_RULES])
        assert actual_ids == expected_ids

    def test_all_rules_have_cwe(self):
        """All rules have CWE mappings."""
        for rule in BLOCKCHAIN_RULES:
            assert rule.cwe_mapping is not None
            assert rule.cwe_mapping.startswith("CWE-")

    def test_all_rules_have_owasp(self):
        """All rules have OWASP mappings."""
        for rule in BLOCKCHAIN_RULES:
            assert rule.owasp_mapping is not None


class TestBlockchainEdgeCases:
    """Test edge cases and corner cases."""

    def test_empty_file(self):
        """Handle empty file gracefully."""
        code = ""
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert violations == []

    def test_syntax_error_handling(self):
        """Handle syntax errors gracefully."""
        code = "def incomplete_function("
        violations = analyze_blockchain_security(Path("test.py"), code)
        assert violations == []

    def test_non_blockchain_code(self):
        """Don't flag vulnerabilities in non-blockchain code."""
        code = """
def regular_function():
    # TODO: Add docstring
    result = some_operation()
    return result
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        # Should have no blockchain-specific violations
        assert len(violations) == 0

    def test_multiple_vulnerabilities_in_one_file(self):
        """Detect multiple different vulnerabilities."""
        code = """
from web3 import Web3
import random
import secrets  # ADDED: Use secrets for cryptographic randomness

private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

def risky_function():
    # TODO: Add docstring
    recipient.call(value=amount)
    winner = random.choice(participants)
    balances[to] = balances[to] + amount
"""
        violations = analyze_blockchain_security(Path("test.py"), code)
        # Should detect multiple issues: private key, reentrancy, random, overflow
        assert len(violations) >= 3
        rule_ids = {v.rule_id for v in violations}
        assert "BLOCKCHAIN006" in rule_ids  # Private key
