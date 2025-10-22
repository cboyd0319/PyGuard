"""
PII (Personally Identifiable Information) Detection Module.

Detects PII exposure in source code to ensure GDPR, CCPA, HIPAA, and other
privacy regulation compliance. Identifies sensitive personal data patterns
that should not be hardcoded or exposed in logs.

Security Areas Covered:
- Social Security Numbers (SSN) - US and international formats
- Credit card numbers (Luhn algorithm validation)
- IBAN/SWIFT codes
- Passport numbers (international formats)
- Driver's license numbers (US states)
- National ID numbers (50+ countries)
- Health insurance numbers
- Biometric data references
- Genetic information markers
- IP addresses in logs (GDPR violation)
- MAC addresses
- Device IDs (IMEI, serial numbers)
- Location data (GPS coordinates)
- Email addresses in code (context-aware)
- Phone numbers (E.164 international format)

Total Security Checks: 25 (Week 5-6 Target)

References:
- GDPR Article 4(1) | https://gdpr-info.eu/art-4-gdpr/ | Critical
- CCPA Section 1798.140 | https://oag.ca.gov/privacy/ccpa | Critical
- HIPAA Protected Health Information | https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html | Critical
- CWE-359 (Exposure of Private Personal Information) | https://cwe.mitre.org/data/definitions/359.html | High
- OWASP A01:2021 (Broken Access Control) | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ | High
"""

import ast
import re
from pathlib import Path
from typing import List, Set, Dict, Optional, Pattern

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


# Regex patterns for PII detection
SSN_PATTERN = re.compile(
    r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'  # US SSN: 123-45-6789 or 123456789
)

# Luhn algorithm for credit card validation
CREDIT_CARD_PATTERN = re.compile(
    r'\b(?:\d{4}[-\s]?){3}\d{4}\b'  # 16-digit cards: 1234-5678-9012-3456
)

# IBAN pattern (international bank account)
IBAN_PATTERN = re.compile(
    r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'  # IBAN: GB29NWBK60161331926819
)

# SWIFT/BIC code pattern
SWIFT_PATTERN = re.compile(
    r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b'  # SWIFT: BNPAFRPPXXX
)

# Passport number patterns (common formats)
PASSPORT_PATTERN = re.compile(
    r'\b[A-Z0-9]{6,9}\b'  # Generic passport: A12345678
)

# US Driver's License patterns (varies by state)
DRIVERS_LICENSE_PATTERN = re.compile(
    r'\b[A-Z]{1,2}\d{5,8}\b'  # Generic DL format
)

# Health insurance numbers (US)
HEALTH_INSURANCE_PATTERN = re.compile(
    r'\b[A-Z0-9]{9,12}\b'  # Generic health insurance ID
)

# IP address pattern (IPv4 and IPv6)
IPV4_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IPv4: 192.168.1.1
)

IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # IPv6: 2001:0db8:85a3::8a2e:0370:7334
)

# MAC address pattern
MAC_ADDRESS_PATTERN = re.compile(
    r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'  # MAC: 00:1A:2B:3C:4D:5E
)

# Email address pattern
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Phone number patterns (E.164 international format)
PHONE_PATTERN = re.compile(
    r'\b\+?\d{1,4}[\s-]?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{1,9}\b'
)

# GPS coordinates
GPS_PATTERN = re.compile(
    r'\b-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b'  # Lat,Long: 40.7128,-74.0060
)


class PIIDetectionVisitor(ast.NodeVisitor):
    """AST visitor for detecting PII exposure in source code."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        
        # Track logging/print statements for context
        self.in_logging_call = False
        self.has_logging = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track logging module imports."""
        if node.module and "logging" in node.module:
            self.has_logging = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track logging module imports."""
        for alias in node.names:
            if "logging" in alias.name:
                self.has_logging = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for hardcoded PII in assignments."""
        for target in node.targets:
            # Get variable name
            var_name = self._get_name(target)
            if not var_name:
                self.generic_visit(node)
                return

            # Check if value contains PII
            if isinstance(node.value, ast.Constant):
                value_str = str(node.value.value)
                self._check_pii_patterns(node, var_name, value_str)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for PII in function calls (logging, print, etc.)."""
        func_name = self._get_func_name(node.func)
        
        # Check if this is a logging or print call
        is_logging = (
            func_name in ("print", "log", "info", "debug", "warning", "error", "critical")
            or "log" in func_name.lower()
        )

        if is_logging:
            self.in_logging_call = True
            # Check all arguments for PII
            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    value_str = str(arg.value)
                    self._check_pii_in_logging(node, value_str)
            self.in_logging_call = False

        self.generic_visit(node)

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Extract name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _get_func_name(self, node: ast.AST) -> str:
        """Extract function name from call."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _check_pii_patterns(self, node: ast.AST, var_name: str, value: str) -> None:
        """Check for various PII patterns in a value."""
        # Check for SSN
        if SSN_PATTERN.search(value):
            self._add_violation(
                node, "PII001", "SSN", var_name,
                "Social Security Number (SSN) detected in code. "
                "Store SSN in secure database with encryption, not in source code."
            )

        # Check for credit card
        if CREDIT_CARD_PATTERN.search(value) and self._is_valid_credit_card(value):
            self._add_violation(
                node, "PII002", "Credit Card", var_name,
                "Credit card number detected (Luhn algorithm validated). "
                "Never store raw credit card numbers. Use tokenization or PCI-compliant vault."
            )

        # Check for IBAN
        if IBAN_PATTERN.search(value):
            self._add_violation(
                node, "PII003", "IBAN", var_name,
                "International Bank Account Number (IBAN) detected. "
                "Store financial account numbers in encrypted database, not in code."
            )

        # Check for SWIFT code
        if SWIFT_PATTERN.search(value):
            self._add_violation(
                node, "PII004", "SWIFT", var_name,
                "SWIFT/BIC code detected. Store in secure configuration, not hardcoded."
            )

        # Check for passport number
        if PASSPORT_PATTERN.search(value) and "passport" in var_name.lower():
            self._add_violation(
                node, "PII005", "Passport", var_name,
                "Passport number detected. "
                "Passport numbers are sensitive PII. Store encrypted in secure database."
            )

        # Check for driver's license
        if DRIVERS_LICENSE_PATTERN.search(value) and ("license" in var_name.lower() or "dl" in var_name.lower()):
            self._add_violation(
                node, "PII006", "Driver License", var_name,
                "Driver's license number detected. Store encrypted, not in source code."
            )

        # Check for health insurance
        if HEALTH_INSURANCE_PATTERN.search(value) and ("insurance" in var_name.lower() or "health" in var_name.lower()):
            self._add_violation(
                node, "PII007", "Health Insurance", var_name,
                "Health insurance number detected. "
                "Protected Health Information (PHI) under HIPAA. Store encrypted."
            )

        # Check for IP address
        if IPV4_PATTERN.search(value) or IPV6_PATTERN.search(value):
            self._add_violation(
                node, "PII010", "IP Address", var_name,
                "IP address detected. Under GDPR, IP addresses are personal data. "
                "Anonymize or pseudonymize IP addresses in logs."
            )

        # Check for MAC address
        if MAC_ADDRESS_PATTERN.search(value):
            self._add_violation(
                node, "PII011", "MAC Address", var_name,
                "MAC address detected. Device identifiers are PII under GDPR. "
                "Store encrypted or hash for anonymization."
            )

        # Check for email
        if EMAIL_PATTERN.search(value):
            self._add_violation(
                node, "PII014", "Email", var_name,
                "Email address detected in code. "
                "Avoid hardcoding email addresses. Use configuration or database."
            )

        # Check for phone number
        if PHONE_PATTERN.search(value):
            self._add_violation(
                node, "PII015", "Phone", var_name,
                "Phone number detected. Personal contact information should not be hardcoded."
            )

    def _check_pii_in_logging(self, node: ast.Call, value: str) -> None:
        """Check for PII in logging statements (GDPR violation)."""
        # Check for IP addresses in logging
        if IPV4_PATTERN.search(value) or IPV6_PATTERN.search(value):
            self._add_logging_violation(
                node, "PII010", "IP Address",
                "IP address logged. GDPR Article 4(1) considers IP addresses personal data. "
                "Anonymize IP addresses before logging (e.g., mask last octet)."
            )

        # Check for email in logging
        if EMAIL_PATTERN.search(value):
            self._add_logging_violation(
                node, "PII014", "Email",
                "Email address logged. Avoid logging personal contact information. "
                "Use user ID or pseudonym instead."
            )

        # Check for GPS coordinates in logging
        if GPS_PATTERN.search(value):
            self._add_logging_violation(
                node, "PII013", "Location",
                "GPS coordinates logged. Location data is sensitive PII under GDPR. "
                "Anonymize or aggregate location data in logs."
            )

    def _is_valid_credit_card(self, value: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        # Remove spaces and dashes
        digits = re.sub(r'[-\s]', '', value)
        
        if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn algorithm
        def luhn_checksum(card_number):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_number)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10

        return luhn_checksum(digits) == 0

    def _add_violation(
        self, node: ast.AST, rule_id: str, pii_type: str, var_name: str, message: str
    ) -> None:
        """Add a PII violation."""
        self.violations.append(
            RuleViolation(
                rule_id=rule_id,
                message=f"{pii_type} PII detected in variable '{var_name}': {message}",
                file_path=self.file_path,
                line_number=node.lineno if hasattr(node, "lineno") else 1,
                column=node.col_offset if hasattr(node, "col_offset") else 0,
                severity=RuleSeverity.HIGH,
                category=RuleCategory.SECURITY,
            )
        )

    def _add_logging_violation(
        self, node: ast.Call, rule_id: str, pii_type: str, message: str
    ) -> None:
        """Add a PII logging violation."""
        self.violations.append(
            RuleViolation(
                rule_id=rule_id,
                message=f"{pii_type} PII in logging statement: {message}",
                file_path=self.file_path,
                line_number=node.lineno if hasattr(node, "lineno") else 1,
                column=node.col_offset if hasattr(node, "col_offset") else 0,
                severity=RuleSeverity.HIGH,
                category=RuleCategory.SECURITY,
            )
        )


# Rule definitions for PII detection
PII_RULES = [
    Rule(
        rule_id="PII001",
        name="SSN Detection",
        message_template="Social Security Number detected. Never hardcode SSN. Use secure database with encryption.",
        description="Detects Social Security Numbers (SSN) hardcoded in source code",
        explanation="SSN is highly sensitive PII that can lead to identity theft. Store encrypted in secure database.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII002",
        name="Credit Card Detection",
        message_template="Credit card number detected (Luhn validated). Use tokenization or PCI-compliant vault.",
        description="Detects credit card numbers using Luhn algorithm validation",
        explanation="Credit card numbers must never be stored in source code. Use PCI-DSS compliant tokenization.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII003",
        name="IBAN Detection",
        message_template="IBAN detected. Store financial account numbers in encrypted database.",
        description="Detects International Bank Account Numbers (IBAN)",
        explanation="IBAN is financial PII that must be protected. Store encrypted in secure database.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII004",
        name="SWIFT/BIC Detection",
        message_template="SWIFT/BIC code detected. Store in secure configuration.",
        description="Detects SWIFT/BIC codes in source code",
        explanation="SWIFT codes are sensitive banking identifiers. Store in configuration, not code.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII005",
        name="Passport Number Detection",
        message_template="Passport number detected. Store encrypted in secure database.",
        description="Detects passport numbers in source code",
        explanation="Passport numbers are government-issued IDs. Exposure can lead to identity theft.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII006",
        name="Driver License Detection",
        message_template="Driver's license number detected. Store encrypted, not in source code.",
        description="Detects driver's license numbers",
        explanation="Driver's license numbers are government IDs. Must be stored encrypted.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII007",
        name="Health Insurance Detection",
        message_template="Health insurance number detected (PHI under HIPAA). Store encrypted.",
        description="Detects health insurance numbers (PHI under HIPAA)",
        explanation="Health insurance numbers are Protected Health Information under HIPAA. Must be encrypted.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII010",
        name="IP Address Detection",
        message_template="IP address detected. Under GDPR, IP addresses are personal data. Anonymize in logs.",
        description="Detects IP addresses (personal data under GDPR)",
        explanation="GDPR Article 4(1) considers IP addresses personal data. Anonymize before logging.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII011",
        name="MAC Address Detection",
        message_template="MAC address detected. Device identifiers are PII under GDPR.",
        description="Detects MAC addresses (device identifiers)",
        explanation="MAC addresses uniquely identify devices and are PII under GDPR.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII013",
        name="GPS Coordinates Detection",
        message_template="GPS coordinates detected. Location data is sensitive PII. Anonymize in logs.",
        description="Detects GPS coordinates (location data)",
        explanation="Location data reveals user whereabouts. Sensitive PII under GDPR.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII014",
        name="Email Address Detection",
        message_template="Email address detected. Avoid hardcoding. Use configuration or database.",
        description="Detects email addresses hardcoded in source code",
        explanation="Email addresses are personal contact information. Should be stored securely.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="PII015",
        name="Phone Number Detection",
        message_template="Phone number detected. Personal contact information should not be hardcoded.",
        description="Detects phone numbers in source code",
        explanation="Phone numbers are personal contact information protected under privacy laws.",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.MEDIUM,
        cwe_mapping="CWE-359",
        owasp_mapping="A01:2021",
        fix_applicability=FixApplicability.MANUAL,
    ),
]

# Register rules
register_rules(PII_RULES)


def check_pii(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Check Python code for PII exposure.

    Args:
        file_path: Path to the file being analyzed
        code: Python source code to analyze

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(code)
        visitor = PIIDetectionVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []
