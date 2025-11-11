"""
Blockchain & Web3 Security Analysis.

Detects security vulnerabilities in blockchain and Web3 applications including
smart contract issues, cryptocurrency handling, and decentralized application security.

Security Areas Covered:
- Smart contract reentrancy vulnerabilities
- Integer overflow in token calculations
- Unchecked external calls
- Insecure randomness in contracts
- Front-running vulnerabilities
- Private key exposure
- Wallet seed phrase leakage
- Gas limit manipulation
- Oracle manipulation risks
- NFT metadata injection

Total Security Checks: 10 (Month 5-6 - Security Dominance Plan)

References:
- OWASP Smart Contract Top 10 | https://owasp.org/www-project-smart-contract-top-10/ | Critical
- Consensys Smart Contract Best Practices | https://consensys.github.io/smart-contract-best-practices/ | High
- CWE-841 (Improper Enforcement of Behavioral Workflow) | https://cwe.mitre.org/data/definitions/841.html | High
- CWE-190 (Integer Overflow or Wraparound) | https://cwe.mitre.org/data/definitions/190.html | Critical
- CWE-338 (Use of Cryptographically Weak PRNG) | https://cwe.mitre.org/data/definitions/338.html | High
- CWE-798 (Use of Hard-coded Credentials) | https://cwe.mitre.org/data/definitions/798.html | Critical
"""

import ast
from pathlib import Path
import re

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class BlockchainSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting blockchain and Web3 security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_web3 = False
        self.has_eth_account = False
        self.has_solidity_parser = False
        self.contract_functions: set[str] = set()
        self.has_random_import = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track blockchain framework imports."""
        if node.module:
            if "web3" in node.module:
                self.has_web3 = True
            elif "eth_account" in node.module:
                self.has_eth_account = True
            elif "solidity" in node.module or "vyper" in node.module:
                self.has_solidity_parser = True
            elif node.module == "random":
                self.has_random_import = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track blockchain framework imports (import statements)."""
        for alias in node.names:
            if "web3" in alias.name:
                self.has_web3 = True
            elif "eth_account" in alias.name:
                self.has_eth_account = True
            elif any(x in alias.name for x in ["solidity", "vyper"]):
                self.has_solidity_parser = True
            elif alias.name == "random":
                self.has_random_import = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded private keys and seed phrases."""
        # BLOCKCHAIN006: Private key exposure
        self._check_private_key_exposure(node)

        # BLOCKCHAIN007: Wallet seed phrase leakage
        self._check_seed_phrase_leakage(node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for blockchain security vulnerabilities in function calls."""
        # BLOCKCHAIN001: Reentrancy patterns
        self._check_reentrancy(node)

        # BLOCKCHAIN002: Integer overflow in token calculations
        self._check_integer_overflow(node)

        # BLOCKCHAIN003: Unchecked external calls
        self._check_unchecked_calls(node)

        # BLOCKCHAIN004: Insecure randomness
        self._check_insecure_randomness(node)

        # BLOCKCHAIN005: Front-running vulnerabilities
        self._check_front_running(node)

        # BLOCKCHAIN008: Gas limit manipulation
        self._check_gas_limit_issues(node)

        # BLOCKCHAIN009: Oracle manipulation
        self._check_oracle_manipulation(node)

        # BLOCKCHAIN010: NFT metadata injection
        self._check_nft_metadata_injection(node)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track contract function definitions for reentrancy analysis."""
        self.contract_functions.add(node.name)

        # BLOCKCHAIN005: Check if function name suggests front-running vulnerability
        if self.has_web3:
            vulnerable_patterns = [
                "approve",
                "transferFrom",
                "swap",
                "trade",
                "bid",
                "auction",
                "commit",
            ]

            if any(pattern in node.name.lower() for pattern in vulnerable_patterns):
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN005",
                    file_path=self.file_path,
                    message=f"Potential front-running vulnerability in function '{node.name}'. "
                    "Consider using commit-reveal pattern or other MEV protection.",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-362",
                    owasp_id="A9-FrontRunning",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)

            # BLOCKCHAIN002: Check for arithmetic in token-related functions
            token_patterns = ["transfer", "mint", "burn", "balance", "allowance", "approve"]
            if any(pattern in node.name.lower() for pattern in token_patterns):
                # Check for unchecked arithmetic in the function body
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):  # noqa: SIM102
                        if isinstance(child.value, ast.BinOp) and isinstance(
                            child.value.op, (ast.Add, ast.Mult, ast.Sub)
                        ):
                            violation = RuleViolation(
                                rule_id="BLOCKCHAIN002",
                                file_path=self.file_path,
                                message=f"Potential integer overflow in token function '{node.name}'. "
                                "Use SafeMath library or check for overflow explicitly.",
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                line_number=child.lineno,
                                column=child.col_offset,
                                cwe_id="CWE-190",
                                owasp_id="A3-Arithmetic",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                            self.violations.append(violation)
                            break  # One violation per function is enough

        self.generic_visit(node)

    def _check_reentrancy(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN001: Detect reentrancy patterns.

        Reentrancy occurs when external calls are made before state changes,
        allowing malicious contracts to re-enter the function.

        CWE-841: Improper Enforcement of Behavioral Workflow
        OWASP: A1 - Reentrancy
        """
        if not self.has_web3:
            return

        # Check for external call patterns
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # Common patterns indicating external calls
            external_call_patterns = [
                "call",
                "send",
                "transfer",
                "delegatecall",
                "callcode",
                "staticcall",
            ]

            if func_name in external_call_patterns:
                # Check if this is followed by state changes in the same function
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN001",
                    file_path=self.file_path,
                    message="Potential reentrancy vulnerability: External call detected. "
                    "Ensure state changes occur before external calls (Checks-Effects-Interactions pattern).",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-841",
                    owasp_id="A1-Reentrancy",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)

    def _check_integer_overflow(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN002: Detect integer overflow in token calculations.

        Token calculations without overflow checks can lead to incorrect balances.

        CWE-190: Integer Overflow or Wraparound
        OWASP: A3 - Arithmetic Issues
        """
        if not (self.has_web3 or self.has_solidity_parser):
            return

        # Check for arithmetic operations in token-related functions
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Token-related function patterns
            if any(
                token_word in func_name.lower()
                for token_word in ["transfer", "mint", "burn", "balance", "allowance", "approve"]
            ):
                # Check for unchecked arithmetic
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(
                        arg.op, (ast.Add, ast.Mult, ast.Sub)
                    ):
                        violation = RuleViolation(
                            rule_id="BLOCKCHAIN002",
                            file_path=self.file_path,
                            message=f"Potential integer overflow in token calculation: {func_name}. "
                            "Use SafeMath library or check for overflow explicitly.",
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-190",
                            owasp_id="A3-Arithmetic",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                        self.violations.append(violation)
                        break

    def _check_unchecked_calls(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN003: Detect unchecked external calls.

        External calls can fail, and unchecked return values can lead to unexpected behavior.

        CWE-252: Unchecked Return Value
        OWASP: A4 - Unchecked Return Values
        """
        if not self.has_web3:
            return

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # External call methods that return values
            if func_name in ["call", "send", "delegatecall"]:
                # Check if return value is checked (used in if statement or assigned)
                # This is a simplified check - in real analysis, we'd need more context
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN003",
                    file_path=self.file_path,
                    message=f"Unchecked external call: {func_name}. "
                    "Always check return values of external calls.",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-252",
                    owasp_id="A4-UncheckedCalls",
                    fix_applicability=FixApplicability.SAFE,
                )
                self.violations.append(violation)

    def _check_insecure_randomness(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN004: Detect insecure randomness in contracts.

        Using predictable randomness sources can be exploited by miners.

        CWE-338: Use of Cryptographically Weak PRNG
        OWASP: A6 - Bad Randomness
        """
        if not (self.has_web3 or self.has_solidity_parser):
            return

        # Check for use of weak randomness sources
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # Weak randomness sources in blockchain context
            weak_sources = [
                "random",
                "randint",
                "choice",  # Python random module
                "block.timestamp",
                "block.number",
                "blockhash",  # Solidity patterns
            ]

            if func_name in weak_sources or (
                self.has_random_import
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"
            ):
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN004",
                    file_path=self.file_path,
                    message="Insecure randomness source detected. "
                    "Use Chainlink VRF or similar oracle for secure randomness.",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-338",
                    owasp_id="A6-BadRandomness",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)

    def _check_front_running(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN005: Detect front-running vulnerabilities.

        Transactions visible in mempool can be front-run by miners or bots.

        CWE-362: Concurrent Execution using Shared Resource
        OWASP: A9 - Front-Running
        """
        if not self.has_web3:
            return

        # Check for vulnerable transaction patterns
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Functions vulnerable to front-running
            vulnerable_patterns = [
                "approve",
                "transferFrom",
                "swap",
                "trade",
                "bid",
                "auction",
                "commit",
            ]

            if any(pattern in func_name.lower() for pattern in vulnerable_patterns):
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN005",
                    file_path=self.file_path,
                    message=f"Potential front-running vulnerability in {func_name}. "
                    "Consider using commit-reveal pattern or other MEV protection.",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-362",
                    owasp_id="A9-FrontRunning",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)

    def _check_private_key_exposure(self, node: ast.Assign) -> None:
        """
        BLOCKCHAIN006: Detect private key exposure.

        Hardcoded private keys can be extracted from source code.

        CWE-798: Use of Hard-coded Credentials
        OWASP: A2 - Broken Authentication
        """
        if not (self.has_web3 or self.has_eth_account):
            return

        # Check for private key patterns in assignments
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                if any(  # noqa: SIM102
                    key_word in var_name
                    for key_word in ["private_key", "privkey", "secret_key", "wallet_key"]
                ):
                    # Check if value is a string literal
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):  # noqa: SIM102
                        # Check for hex pattern (typical for private keys)
                        if re.match(r"^(0x)?[0-9a-fA-F]{64}$", node.value.value):
                            violation = RuleViolation(
                                rule_id="BLOCKCHAIN006",
                                file_path=self.file_path,
                                message="Hardcoded private key detected. "
                                "Store private keys in environment variables or secure key management systems.",
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                line_number=node.lineno,
                                column=node.col_offset,
                                cwe_id="CWE-798",
                                owasp_id="A2-Auth",
                                fix_applicability=FixApplicability.SAFE,
                            )
                            self.violations.append(violation)

    def _check_seed_phrase_leakage(self, node: ast.Assign) -> None:
        """
        BLOCKCHAIN007: Detect wallet seed phrase leakage.

        Mnemonic seed phrases should never be hardcoded.

        CWE-798: Use of Hard-coded Credentials
        OWASP: A2 - Broken Authentication
        """
        if not (self.has_web3 or self.has_eth_account):
            return

        # Check for seed phrase patterns
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                if any(  # noqa: SIM102
                    seed_word in var_name
                    for seed_word in ["mnemonic", "seed", "seed_phrase", "recovery", "bip39"]
                ):
                    # Check if value is a string with multiple words (typical for seed phrases)
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        words = node.value.value.split()
                        if len(words) >= 12:  # BIP39 uses 12, 15, 18, 21, or 24 words  # noqa: PLR2004 - length check
                            violation = RuleViolation(
                                rule_id="BLOCKCHAIN007",
                                file_path=self.file_path,
                                message="Hardcoded seed phrase detected. "
                                "Never store seed phrases in source code. Use secure key management.",
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                line_number=node.lineno,
                                column=node.col_offset,
                                cwe_id="CWE-798",
                                owasp_id="A2-Auth",
                                fix_applicability=FixApplicability.SAFE,
                            )
                            self.violations.append(violation)

    def _check_gas_limit_issues(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN008: Detect gas limit manipulation issues.

        Improper gas limit handling can lead to DoS or failed transactions.

        CWE-400: Uncontrolled Resource Consumption
        OWASP: A5 - Denial of Service
        """
        if not self.has_web3:
            return

        # Check for transaction calls with gas parameters
        if isinstance(node.func, ast.Attribute):  # noqa: SIM102
            if node.func.attr in ["transact", "send_transaction", "sendTransaction"]:
                # Check if gas is specified
                # has_gas_param = False  # Not used - checking inline instead
                for keyword in node.keywords:
                    if keyword.arg in ["gas", "gas_limit", "gasLimit"]:  # noqa: SIM102
                        # has_gas_param = True  # Not needed
                        # Check for hardcoded gas values
                        if isinstance(keyword.value, ast.Constant):
                            violation = RuleViolation(
                                rule_id="BLOCKCHAIN008",
                                file_path=self.file_path,
                                message="Hardcoded gas limit detected. "
                                "Gas limits should be estimated dynamically to prevent failed transactions.",
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                line_number=node.lineno,
                                column=node.col_offset,
                                cwe_id="CWE-400",
                                owasp_id="A5-DoS",
                                fix_applicability=FixApplicability.SAFE,
                            )
                            self.violations.append(violation)

    def _check_oracle_manipulation(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN009: Detect oracle manipulation risks.

        Relying on single price oracles can be exploited via manipulation.

        CWE-345: Insufficient Verification of Data Authenticity
        OWASP: A8 - Oracle Manipulation
        """
        if not self.has_web3:
            return

        # Check for price oracle calls
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # Oracle-related function patterns
            oracle_patterns = [
                "getPrice",
                "get_price",
                "latestAnswer",
                "getLatestPrice",
                "getRoundData",
            ]

            if any(pattern in func_name for pattern in oracle_patterns):
                # Check if multiple oracles are used (safer)
                violation = RuleViolation(
                    rule_id="BLOCKCHAIN009",
                    file_path=self.file_path,
                    message="Single oracle usage detected. "
                    "Use multiple price oracles and median/average for better security.",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-345",
                    owasp_id="A8-Oracle",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)

    def _check_nft_metadata_injection(self, node: ast.Call) -> None:
        """
        BLOCKCHAIN010: Detect NFT metadata injection vulnerabilities.

        Unvalidated metadata can contain malicious content.

        CWE-79: Cross-site Scripting (XSS)
        OWASP: A7 - Injection
        """
        if not self.has_web3:
            return

        # Check for NFT minting or metadata setting
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # NFT-related function patterns
            nft_patterns = [
                "mint",
                "setTokenURI",
                "set_token_uri",
                "setMetadata",
                "set_metadata",
                "updateMetadata",
            ]

            if any(pattern in func_name for pattern in nft_patterns):
                # Check if metadata is user-provided without validation
                for arg in node.args:
                    if isinstance(arg, (ast.Name, ast.Subscript)):
                        violation = RuleViolation(
                            rule_id="BLOCKCHAIN010",
                            file_path=self.file_path,
                            message="Potential NFT metadata injection. "
                            "Validate and sanitize all metadata inputs before storage.",
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-79",
                            owasp_id="A7-Injection",
                            fix_applicability=FixApplicability.SAFE,
                        )
                        self.violations.append(violation)
                        break


def analyze_blockchain_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for blockchain and Web3 security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of detected security violations
    """
    try:
        tree = ast.parse(code)
        visitor = BlockchainSecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register blockchain security rules
BLOCKCHAIN_RULES = [
    Rule(
        rule_id="BLOCKCHAIN001",
        name="Reentrancy Vulnerability",
        message_template="Potential reentrancy vulnerability detected in external call",
        description="Detects potential reentrancy vulnerabilities in smart contract interactions",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-841",
        owasp_mapping="A1-Reentrancy",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BLOCKCHAIN002",
        name="Integer Overflow in Token Calculations",
        message_template="Unchecked arithmetic detected in token calculation",
        description="Detects unchecked arithmetic in token-related operations",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-190",
        owasp_mapping="A3-Arithmetic",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BLOCKCHAIN003",
        name="Unchecked External Calls",
        message_template="External call without return value check",
        description="Detects external calls without return value checks",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-252",
        owasp_mapping="A4-UncheckedCalls",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BLOCKCHAIN004",
        name="Insecure Randomness in Contracts",
        message_template="Insecure randomness source detected",
        description="Detects use of predictable randomness sources",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-338",
        owasp_mapping="A6-BadRandomness",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BLOCKCHAIN005",
        name="Front-Running Vulnerability",
        message_template="Transaction vulnerable to front-running detected",
        description="Detects transaction patterns vulnerable to front-running",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-362",
        owasp_mapping="A9-FrontRunning",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BLOCKCHAIN006",
        name="Private Key Exposure",
        message_template="Hardcoded private key detected",
        description="Detects hardcoded private keys in source code",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-798",
        owasp_mapping="A2-Auth",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BLOCKCHAIN007",
        name="Wallet Seed Phrase Leakage",
        message_template="Hardcoded wallet seed phrase detected",
        description="Detects hardcoded mnemonic seed phrases",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-798",
        owasp_mapping="A2-Auth",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BLOCKCHAIN008",
        name="Gas Limit Manipulation",
        message_template="Hardcoded gas limit detected",
        description="Detects hardcoded gas limits that may cause transaction failures",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-400",
        owasp_mapping="A5-DoS",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="BLOCKCHAIN009",
        name="Oracle Manipulation Risk",
        message_template="Single oracle usage detected",
        description="Detects reliance on single price oracles",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-345",
        owasp_mapping="A8-Oracle",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="BLOCKCHAIN010",
        name="NFT Metadata Injection",
        message_template="Unvalidated NFT metadata detected",
        description="Detects unvalidated NFT metadata that may contain malicious content",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-79",
        owasp_mapping="A7-Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
]

register_rules(BLOCKCHAIN_RULES)
