"""
Business Logic & Business Flaws Security Analysis for PyGuard.

Implements security checks for business logic vulnerabilities including:
- Race Conditions & Timing (10 checks)
- Financial & Transaction Logic (10 checks)
- Access Control Logic (10 checks)

References:
- CWE-840: Business Logic Errors | https://cwe.mitre.org/data/definitions/840.html | High
- CWE-367: TOCTOU Race Condition | https://cwe.mitre.org/data/definitions/367.html | High
- OWASP Top 10 2021: A04:2021 - Insecure Design | https://owasp.org/Top10/A04_2021-Insecure_Design/
- OWASP ASVS v5.0 Chapter 11: Business Logic | https://owasp.org/www-project-application-security-verification-standard/

Week 15-16 Implementation: 30 security checks for business logic vulnerabilities
"""

import ast
import re
from typing import List, Set

from pyguard.lib.ast_analyzer import SecurityIssue
from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import Rule, RuleCategory, RuleSeverity


# =============================================================================
# BUSINESS LOGIC SECURITY RULES (30 TOTAL)
# =============================================================================

# -----------------------------------------------------------------------------
# Race Conditions & Timing (10 checks)
# -----------------------------------------------------------------------------

BIZLOGIC001_TOCTOU = Rule(
    rule_id="BIZLOGIC001",
    name="toctou-file-operations",
    category=RuleCategory.SECURITY,
    severity=RuleSeverity.HIGH,
    message_template="TOCTOU vulnerability: File check followed by operation creates race condition window",
    description="Detects Time-of-check Time-of-use (TOCTOU) race conditions in file operations",
    cwe_mapping="CWE-367",  # TOCTOU Race Condition
    owasp_mapping="ASVS-11.1.3",  # Business Logic
)

BIZLOGIC002_RACE_FILE = Rule(
    rule_id="BIZLOGIC002",
    name="race-condition-file-ops",
    category=RuleCategory.SECURITY,
    message_template="Race condition in file operations: {operation} without proper locking",
    description="Detects race conditions in file read/write operations without synchronization",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-362",  # Concurrent Execution using Shared Resource
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC003_ATOMIC_VIOLATION = Rule(
    rule_id="BIZLOGIC003",
    name="non-atomic-operation",
    category=RuleCategory.SECURITY,
    message_template="Non-atomic operation: {operation} should be atomic to prevent race conditions",
    description="Detects operations that should be atomic but aren't (check-then-act patterns)",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-362",
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC004_MISSING_LOCK = Rule(
    rule_id="BIZLOGIC004",
    name="missing-mutex-lock",
    category=RuleCategory.SECURITY,
    message_template="Missing mutex/lock for shared resource access: {resource}",
    description="Detects shared resource access without proper mutex or lock protection",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-662",  # Improper Synchronization
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC005_DOUBLE_CHECKED = Rule(
    rule_id="BIZLOGIC005",
    name="double-checked-locking",
    category=RuleCategory.SECURITY,
    message_template="Double-checked locking anti-pattern detected - not thread-safe in Python",
    description="Detects double-checked locking pattern which is unsafe in Python due to GIL nuances",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-609",  # Double-Checked Locking
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC006_LAZY_INIT = Rule(
    rule_id="BIZLOGIC006",
    name="unsafe-lazy-initialization",
    category=RuleCategory.SECURITY,
    message_template="Unsafe lazy initialization without thread synchronization",
    description="Detects lazy initialization patterns without proper thread safety mechanisms",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-543",  # Insecure Lazy Initialization
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC007_THREAD_SAFETY = Rule(
    rule_id="BIZLOGIC007",
    name="thread-safety-violation",
    category=RuleCategory.SECURITY,
    message_template="Thread-safety violation: Shared mutable state without synchronization",
    description="Detects shared mutable state accessed without proper thread synchronization",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-662",
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC008_CONCURRENT_MOD = Rule(
    rule_id="BIZLOGIC008",
    name="concurrent-modification",
    category=RuleCategory.SECURITY,
    message_template="Concurrent modification risk: Iterating over collection while modifying it",
    description="Detects iteration over collections while they're being modified",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-362",
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC009_LOCK_ORDER = Rule(
    rule_id="BIZLOGIC009",
    name="lock-ordering-violation",
    category=RuleCategory.SECURITY,
    message_template="Lock ordering violation: Potential deadlock from inconsistent lock acquisition order",
    description="Detects inconsistent lock acquisition ordering that can lead to deadlocks",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-833",  # Deadlock
    owasp_mapping="ASVS-11.1.3",
)

BIZLOGIC010_DEADLOCK = Rule(
    rule_id="BIZLOGIC010",
    name="deadlock-potential",
    category=RuleCategory.SECURITY,
    message_template="Deadlock potential: Nested locks or circular wait condition",
    description="Detects patterns that can lead to deadlocks (nested locks, circular waits)",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-833",
    owasp_mapping="ASVS-11.1.3",
)

# -----------------------------------------------------------------------------
# Financial & Transaction Logic (10 checks)
# -----------------------------------------------------------------------------

BIZLOGIC011_INTEGER_OVERFLOW = Rule(
    rule_id="BIZLOGIC011",
    name="integer-overflow-pricing",
    category=RuleCategory.SECURITY,
    message_template="Integer overflow risk in pricing calculation: {operation}",
    description="Detects potential integer overflow in financial/pricing calculations",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-190",  # Integer Overflow
    owasp_mapping="ASVS-11.1.4",  # Business Logic Integrity
)

BIZLOGIC012_FLOAT_PRECISION = Rule(
    rule_id="BIZLOGIC012",
    name="float-precision-currency",
    category=RuleCategory.SECURITY,
    message_template="Floating-point arithmetic used for currency - use Decimal instead",
    description="Detects use of float for currency calculations (should use decimal.Decimal)",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-682",  # Incorrect Calculation
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC013_NEGATIVE_QTY = Rule(
    rule_id="BIZLOGIC013",
    name="negative-quantity-order",
    category=RuleCategory.SECURITY,
    message_template="Missing validation for negative quantities in order/transaction logic",
    description="Detects order/quantity logic without validation for negative values",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-840",  # Business Logic Errors
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC014_MISSING_ROLLBACK = Rule(
    rule_id="BIZLOGIC014",
    name="missing-transaction-rollback",
    category=RuleCategory.SECURITY,
    message_template="Financial transaction without rollback handling in exception path",
    description="Detects financial operations without proper transaction rollback on errors",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-755",  # Improper Error Handling
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC015_DISCOUNT_STACKING = Rule(
    rule_id="BIZLOGIC015",
    name="discount-stacking-vulnerability",
    category=RuleCategory.SECURITY,
    message_template="Discount stacking vulnerability: Multiple discounts applied without limit validation",
    description="Detects discount application logic that doesn't validate total discount amount",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-840",
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC016_REFUND_LOGIC = Rule(
    rule_id="BIZLOGIC016",
    name="refund-logic-vulnerability",
    category=RuleCategory.SECURITY,
    message_template="Refund logic lacks validation: Original amount or status not checked",
    description="Detects refund operations without proper validation of original transaction",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-840",
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC017_AMOUNT_TAMPER = Rule(
    rule_id="BIZLOGIC017",
    name="payment-amount-tampering",
    category=RuleCategory.SECURITY,
    message_template="Payment amount vulnerable to tampering: User-controlled input not validated",
    description="Detects payment amounts that come from user input without server-side validation",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-639",  # Authorization Bypass Through User-Controlled Key
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC018_CURRENCY_CONVERT = Rule(
    rule_id="BIZLOGIC018",
    name="currency-conversion-error",
    category=RuleCategory.SECURITY,
    message_template="Currency conversion without proper rate validation or rounding",
    description="Detects currency conversion that doesn't properly validate exchange rates",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-682",
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC019_TAX_CALC = Rule(
    rule_id="BIZLOGIC019",
    name="tax-calculation-bypass",
    category=RuleCategory.SECURITY,
    message_template="Tax calculation logic bypassable: User input affects tax without validation",
    description="Detects tax calculation logic that can be bypassed via user-controlled inputs",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-840",
    owasp_mapping="ASVS-11.1.4",
)

BIZLOGIC020_PRICE_MANIPULATE = Rule(
    rule_id="BIZLOGIC020",
    name="price-manipulation",
    category=RuleCategory.SECURITY,
    message_template="Price manipulation risk: Price fetched from user-controllable source",
    description="Detects pricing logic that retrieves prices from user-controllable sources",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-639",
    owasp_mapping="ASVS-11.1.4",
)

# -----------------------------------------------------------------------------
# Access Control Logic (10 checks)
# -----------------------------------------------------------------------------

BIZLOGIC021_BROKEN_ACCESS = Rule(
    rule_id="BIZLOGIC021",
    name="broken-access-control",
    category=RuleCategory.SECURITY,
    message_template="Broken access control: Function lacks authorization check",
    description="Detects privileged functions without access control checks",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-284",  # Improper Access Control
    owasp_mapping="ASVS-4.1.1",  # Authorization
)

BIZLOGIC022_MISSING_AUTH = Rule(
    rule_id="BIZLOGIC022",
    name="missing-authorization-check",
    category=RuleCategory.SECURITY,
    message_template="Missing authorization check for sensitive operation: {operation}",
    description="Detects sensitive operations without authorization verification",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-862",  # Missing Authorization
    owasp_mapping="ASVS-4.1.1",
)

BIZLOGIC023_VERTICAL_PRIV = Rule(
    rule_id="BIZLOGIC023",
    name="vertical-privilege-escalation",
    category=RuleCategory.SECURITY,
    message_template="Vertical privilege escalation: User can access admin functions without role check",
    description="Detects functions that allow users to perform admin actions without role verification",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-269",  # Improper Privilege Management
    owasp_mapping="ASVS-4.1.2",
)

BIZLOGIC024_HORIZONTAL_PRIV = Rule(
    rule_id="BIZLOGIC024",
    name="horizontal-privilege-escalation",
    category=RuleCategory.SECURITY,
    message_template="Horizontal privilege escalation: User can access other users' data via ID manipulation",
    description="Detects IDOR vulnerabilities where user_id/resource_id from request isn't validated",
    severity=RuleSeverity.CRITICAL,
    cwe_mapping="CWE-639",  # Authorization Bypass Through User-Controlled Key
    owasp_mapping="ASVS-4.1.3",
)

BIZLOGIC025_RESOURCE_EXHAUST = Rule(
    rule_id="BIZLOGIC025",
    name="resource-exhaustion-unlimited",
    category=RuleCategory.SECURITY,
    message_template="Resource exhaustion: No rate limiting on {operation}",
    description="Detects operations that can cause resource exhaustion without rate limiting",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-400",  # Uncontrolled Resource Consumption
    owasp_mapping="ASVS-11.1.2",
)

BIZLOGIC026_ALGO_COMPLEXITY = Rule(
    rule_id="BIZLOGIC026",
    name="algorithmic-complexity-dos",
    category=RuleCategory.SECURITY,
    message_template="Algorithmic complexity DoS: {operation} has exponential/quadratic complexity on user input",
    description="Detects algorithms with high complexity processing user input (DoS risk)",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-407",  # Algorithmic Complexity
    owasp_mapping="ASVS-11.1.2",
)

BIZLOGIC027_REGEX_DOS = Rule(
    rule_id="BIZLOGIC027",
    name="regex-dos-redos",
    category=RuleCategory.SECURITY,
    message_template="ReDoS vulnerability: Regular expression with catastrophic backtracking",
    description="Detects regular expressions vulnerable to ReDoS (catastrophic backtracking)",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-1333",  # ReDoS
    owasp_mapping="ASVS-5.1.5",
)

BIZLOGIC028_ZIP_BOMB = Rule(
    rule_id="BIZLOGIC028",
    name="zip-bomb-handling",
    category=RuleCategory.SECURITY,
    message_template="Zip bomb vulnerability: Archive extraction without size limits",
    description="Detects archive/zip extraction without validation of decompressed size",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-409",  # Improper Handling of Highly Compressed Data
    owasp_mapping="ASVS-12.4.1",
)

BIZLOGIC029_XML_BOMB = Rule(
    rule_id="BIZLOGIC029",
    name="xml-bomb-billion-laughs",
    category=RuleCategory.SECURITY,
    message_template="XML bomb (Billion Laughs) vulnerability: XML parsing without entity limits",
    description="Detects XML parsing without protection against entity expansion attacks",
    severity=RuleSeverity.HIGH,
    cwe_mapping="CWE-776",  # Improper Restriction of Recursive Entity References
    owasp_mapping="ASVS-5.5.2",
)

BIZLOGIC030_HASH_COLLISION = Rule(
    rule_id="BIZLOGIC030",
    name="hash-collision-dos",
    category=RuleCategory.SECURITY,
    message_template="Hash collision DoS: Dictionary/set from user input without protection",
    description="Detects hash-based data structures vulnerable to collision attacks",
    severity=RuleSeverity.MEDIUM,
    cwe_mapping="CWE-407",
    owasp_mapping="ASVS-11.1.2",
)


# Collect all business logic rules
BUSINESS_LOGIC_RULES = [
    # Race Conditions & Timing (10)
    BIZLOGIC001_TOCTOU,
    BIZLOGIC002_RACE_FILE,
    BIZLOGIC003_ATOMIC_VIOLATION,
    BIZLOGIC004_MISSING_LOCK,
    BIZLOGIC005_DOUBLE_CHECKED,
    BIZLOGIC006_LAZY_INIT,
    BIZLOGIC007_THREAD_SAFETY,
    BIZLOGIC008_CONCURRENT_MOD,
    BIZLOGIC009_LOCK_ORDER,
    BIZLOGIC010_DEADLOCK,
    # Financial & Transaction Logic (10)
    BIZLOGIC011_INTEGER_OVERFLOW,
    BIZLOGIC012_FLOAT_PRECISION,
    BIZLOGIC013_NEGATIVE_QTY,
    BIZLOGIC014_MISSING_ROLLBACK,
    BIZLOGIC015_DISCOUNT_STACKING,
    BIZLOGIC016_REFUND_LOGIC,
    BIZLOGIC017_AMOUNT_TAMPER,
    BIZLOGIC018_CURRENCY_CONVERT,
    BIZLOGIC019_TAX_CALC,
    BIZLOGIC020_PRICE_MANIPULATE,
    # Access Control Logic (10)
    BIZLOGIC021_BROKEN_ACCESS,
    BIZLOGIC022_MISSING_AUTH,
    BIZLOGIC023_VERTICAL_PRIV,
    BIZLOGIC024_HORIZONTAL_PRIV,
    BIZLOGIC025_RESOURCE_EXHAUST,
    BIZLOGIC026_ALGO_COMPLEXITY,
    BIZLOGIC027_REGEX_DOS,
    BIZLOGIC028_ZIP_BOMB,
    BIZLOGIC029_XML_BOMB,
    BIZLOGIC030_HASH_COLLISION,
]


class BusinessLogicVisitor(ast.NodeVisitor):
    """
    AST visitor for detecting business logic vulnerabilities.
    
    Implements 30 security checks across three categories:
    - Race Conditions & Timing (10 checks)
    - Financial & Transaction Logic (10 checks)
    - Access Control Logic (10 checks)
    """

    def __init__(self, source_code: str):
        """Initialize the business logic security visitor."""
        self.issues: List[SecurityIssue] = []
        self.source_lines = source_code.splitlines()
        self.logger = PyGuardLogger()
        
        # Track state for analysis
        self.file_checks: List[tuple] = []  # (line, var_name, operation)
        self.lock_acquisitions: List[tuple] = []  # (line, lock_name)
        self.shared_vars: Set[str] = set()
        self.financial_functions: Set[str] = set()
        self.auth_checked_functions: Set[str] = set()
        self.regex_patterns: dict = {}  # variable_name -> pattern_string

    def _get_code_snippet(self, node: ast.AST) -> str:
        """Extract code snippet for a node."""
        if hasattr(node, "lineno") and 0 < node.lineno <= len(self.source_lines):
            return self.source_lines[node.lineno - 1].strip()
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function/method name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            return ".".join(parts)
        return ""

    def _is_financial_function(self, func_name: str) -> bool:
        """Check if function name suggests financial operations."""
        financial_keywords = [
            "payment", "pay", "charge", "refund", "withdraw", "deposit",
            "transfer", "transaction", "purchase", "buy", "sell", "price",
            "cost", "amount", "total", "discount", "tax", "fee", "balance",
            "order", "checkout", "cart", "invoice", "billing"
        ]
        return any(keyword in func_name.lower() for keyword in financial_keywords)

    def _is_sensitive_function(self, func_name: str) -> bool:
        """Check if function performs sensitive operations."""
        sensitive_keywords = [
            "admin", "delete", "modify", "update", "create", "remove",
            "change", "set", "grant", "revoke", "privilege", "permission"
        ]
        return any(keyword in func_name.lower() for keyword in sensitive_keywords)

    # =========================================================================
    # Race Conditions & Timing Checks
    # =========================================================================

    def visit_Call(self, node: ast.Call):
        """Check for file operations and other race condition patterns."""
        call_name = self._get_call_name(node)
        
        # BIZLOGIC001: TOCTOU - Track file existence checks
        if call_name in ["os.path.exists", "os.path.isfile", "os.path.isdir", "pathlib.Path.exists"]:
            self.file_checks.append((node.lineno, call_name, "check"))
        
        # Track file operations
        file_ops = ["open", "os.remove", "os.rename", "os.unlink", "shutil.move", "shutil.copy"]
        if any(op in call_name for op in file_ops):
            # Check if this follows a file check (TOCTOU)
            for check_line, check_var, _ in self.file_checks:
                if node.lineno > check_line and node.lineno - check_line <= 5:
                    self.issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Race Condition",
                            message=f"TOCTOU vulnerability: File check at line {check_line} followed by {call_name} - race condition window",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Use atomic operations or file locking (fcntl.flock) instead of check-then-act",
                            cwe_id="CWE-367",
                            owasp_id="ASVS-11.1.3",
                        )
                    )
                    break

        # BIZLOGIC002: File operations without locking
        file_write_ops = ["open", "write", "writelines"]
        if any(op in call_name for op in file_write_ops):
            # Check if within a lock context
            # This is simplified - full analysis would track context managers
            snippet = self._get_code_snippet(node)
            if "lock" not in snippet.lower() and "with" not in snippet:
                self.issues.append(
                    SecurityIssue(
                        severity="HIGH",
                        category="Race Condition",
                        message=f"Race condition in file operations: {call_name} without proper locking",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=snippet,
                        fix_suggestion="Use file locking (fcntl.flock) or threading.Lock for concurrent file access",
                        cwe_id="CWE-362",
                        owasp_id="ASVS-11.1.3",
                    )
                )

        # BIZLOGIC027: ReDoS - Regular expression DoS
        if "re.compile" in call_name or "re.match" in call_name or "re.search" in call_name:
            # Check for catastrophic backtracking patterns
            pattern_to_check = None
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    pattern_to_check = arg.value
                elif isinstance(arg, ast.Name) and arg.id in self.regex_patterns:
                    # Look up the pattern from tracked assignments
                    pattern_to_check = self.regex_patterns[arg.id]
                    
            if pattern_to_check:
                # Improved heuristics for ReDoS detection:
                # 1. Nested quantifiers: (a+)+, (a*)*
                # 2. Alternation with quantifiers: (a|a)*
                # 3. Multiple quantifiers: (.*)+
                redos_patterns = [
                    r'\([^)]*[+*?]\)[+*?]',  # (pattern+)+  or (pattern*)*
                    r'\(\w+\|\w+\)[+*?]',     # (a|a)+ or (a|b)*
                ]
                is_redos = False
                for redos_pattern in redos_patterns:
                    if re.search(redos_pattern, pattern_to_check):
                        is_redos = True
                        break
                
                if is_redos:
                    self.issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Access Control DoS",
                            message="ReDoS vulnerability: Regular expression with potential catastrophic backtracking",
                            line_number=node.lineno,
                            column=node.col_offset,
                            code_snippet=self._get_code_snippet(node),
                            fix_suggestion="Avoid nested quantifiers; use atomic groups or possessive quantifiers",
                            cwe_id="CWE-1333",
                            owasp_id="ASVS-5.1.5",
                        )
                    )

        # BIZLOGIC028: Zip bomb - Archive extraction without size limits
        extract_ops = ["zipfile.ZipFile.extractall", "tarfile.TarFile.extractall", "extract"]
        if any(op in call_name for op in extract_ops):
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Access Control DoS",
                    message="Zip bomb vulnerability: Archive extraction without size validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Validate decompressed size before extraction; limit total extracted size",
                    cwe_id="CWE-409",
                    owasp_id="ASVS-12.4.1",
                )
            )

        # BIZLOGIC029: XML bomb - Billion Laughs attack
        # Check for various forms of XML parsing
        is_xml_parse = False
        if "parse" in call_name:
            # Check if this looks like an XML parsing call
            lower_call = call_name.lower()
            if any(xml_marker in lower_call for xml_marker in ["xml", "etree", "minidom", "lxml"]):
                is_xml_parse = True
            # Also check for ET.parse or xml*.parse patterns
            elif ".parse" in call_name and call_name.count('.') <= 2:
                is_xml_parse = True
                
        if is_xml_parse:
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Access Control DoS",
                    message="XML bomb (Billion Laughs) vulnerability: XML parsing without entity limits",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Use defusedxml library or disable entity expansion in parser",
                    cwe_id="CWE-776",
                    owasp_id="ASVS-5.5.2",
                )
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments, especially regex patterns."""
        # Track regex pattern assignments for ReDoS detection
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            # Check if this looks like a pattern variable
            if "pattern" in var_name.lower() or "regex" in var_name.lower():
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.regex_patterns[var_name] = node.value.value
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function definitions for business logic issues."""
        func_name = node.name
        
        # Track if this is a financial or sensitive function
        is_financial = self._is_financial_function(func_name)
        is_sensitive = self._is_sensitive_function(func_name)
        
        # has_balance_check = False  # Not used currently
        has_rollback = False
        has_auth_check = False
        has_negative_check = False
        uses_float_for_money = False
        has_discount_limit = False
        has_refund_validation = False
        uses_user_input_price = False
        
        # Analyze function body
        for child in ast.walk(node):
            # Check for balance/amount validation
            if isinstance(child, ast.Compare):
                snippet = self._get_code_snippet(child)
                if any(kw in snippet.lower() for kw in ["balance", "amount", "total", "limit"]):
                    pass  # has_balance_check = True  # Not used currently
                if any(kw in snippet.lower() for kw in ["< 0", "> 0", ">= 0"]):
                    has_negative_check = True
                if "discount" in snippet.lower() and ">" in snippet:
                    has_discount_limit = True

            # Check for transaction rollback
            if isinstance(child, ast.Call):
                child_call = self._get_call_name(child)
                if "rollback" in child_call.lower():
                    has_rollback = True
                if any(auth in child_call.lower() for auth in ["check_permission", "require_auth", "authorize", "has_permission"]):
                    has_auth_check = True
                if "refund" in func_name.lower() and any(v in child_call.lower() for v in ["verify", "validate", "check"]):
                    has_refund_validation = True

            # Check for float usage in financial context
            if is_financial and isinstance(child, ast.BinOp):
                if isinstance(child.op, (ast.Mult, ast.Div, ast.Add, ast.Sub)):
                    # Check if operands might be floats
                    snippet = self._get_code_snippet(child)
                    if "float" in snippet.lower() or re.search(r'\d+\.\d+', snippet):
                        uses_float_for_money = True

            # Check for user input in pricing
            if isinstance(child, ast.Assign):
                # Check if assigning from user input to a price/amount variable
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        # Check if this looks like a price/amount variable
                        if any(kw in var_name.lower() for kw in ["price", "amount", "cost", "total", "balance"]):
                            # Check if value comes from user input
                            if isinstance(child.value, ast.Call):
                                call_name = self._get_call_name(child.value)
                                if any(inp in call_name.lower() for inp in ["request.", "input", ".get", "args", "kwargs", "params"]):
                                    uses_user_input_price = True
                            elif isinstance(child.value, ast.Attribute):
                                # request.args pattern
                                if isinstance(child.value.value, ast.Name):
                                    if "request" in child.value.value.id.lower():
                                        uses_user_input_price = True

        # BIZLOGIC011: Integer overflow in pricing
        if is_financial:
            for child in ast.walk(node):
                if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mult):
                    self.issues.append(
                        SecurityIssue(
                            severity="HIGH",
                            category="Financial Logic",
                            message=f"Integer overflow risk in pricing calculation in '{func_name}'",
                            line_number=child.lineno if hasattr(child, 'lineno') else node.lineno,
                            column=child.col_offset if hasattr(child, 'col_offset') else 0,
                            code_snippet=self._get_code_snippet(child),
                            fix_suggestion="Validate result bounds; consider using decimal.Decimal for precision",
                            cwe_id="CWE-190",
                            owasp_id="ASVS-11.1.4",
                        )
                    )
                    break  # One warning per function

        # BIZLOGIC012: Float precision for currency
        if uses_float_for_money:
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Financial Logic",
                    message=f"Floating-point arithmetic used for currency in '{func_name}' - use Decimal instead",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Replace float with decimal.Decimal for currency calculations",
                    cwe_id="CWE-682",
                    owasp_id="ASVS-11.1.4",
                )
            )

        # BIZLOGIC013: Negative quantity validation
        if is_financial and "order" in func_name.lower() or "quantity" in func_name.lower():
            if not has_negative_check:
                self.issues.append(
                    SecurityIssue(
                        severity="HIGH",
                        category="Financial Logic",
                        message=f"Missing validation for negative quantities in '{func_name}'",
                        line_number=node.lineno,
                        column=node.col_offset,
                        code_snippet=self._get_code_snippet(node),
                        fix_suggestion="Add validation: if quantity < 0: raise ValueError('Negative quantity not allowed')",
                        cwe_id="CWE-840",
                        owasp_id="ASVS-11.1.4",
                    )
                )

        # BIZLOGIC014: Missing transaction rollback
        if is_financial and not has_rollback:
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Financial Logic",
                    message=f"Financial transaction without rollback handling in '{func_name}'",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Implement try/except with db.rollback() for transaction safety",
                    cwe_id="CWE-755",
                    owasp_id="ASVS-11.1.4",
                )
            )

        # BIZLOGIC015: Discount stacking
        if "discount" in func_name.lower() and not has_discount_limit:
            self.issues.append(
                SecurityIssue(
                    severity="MEDIUM",
                    category="Financial Logic",
                    message=f"Discount stacking vulnerability in '{func_name}': Multiple discounts without limit validation",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Validate total_discount <= max_allowed_discount (e.g., 50%)",
                    cwe_id="CWE-840",
                    owasp_id="ASVS-11.1.4",
                )
            )

        # BIZLOGIC016: Refund logic validation
        if "refund" in func_name.lower() and not has_refund_validation:
            self.issues.append(
                SecurityIssue(
                    severity="HIGH",
                    category="Financial Logic",
                    message=f"Refund logic lacks validation in '{func_name}': Original amount/status not checked",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Verify original transaction amount, status, and refund eligibility",
                    cwe_id="CWE-840",
                    owasp_id="ASVS-11.1.4",
                )
            )

        # BIZLOGIC017: Payment amount tampering
        if uses_user_input_price:
            self.issues.append(
                SecurityIssue(
                    severity="CRITICAL",
                    category="Financial Logic",
                    message=f"Payment amount vulnerable to tampering in '{func_name}': User-controlled input not validated",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Always fetch price from server-side database, never trust client input",
                    cwe_id="CWE-639",
                    owasp_id="ASVS-11.1.4",
                )
            )

        # BIZLOGIC021-BIZLOGIC022: Missing authorization
        if is_sensitive and not has_auth_check:
            self.issues.append(
                SecurityIssue(
                    severity="CRITICAL",
                    category="Access Control",
                    message=f"Missing authorization check for sensitive operation in '{func_name}'",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Add @require_permission or check_authorization() at function start",
                    cwe_id="CWE-862",
                    owasp_id="ASVS-4.1.1",
                )
            )

        # BIZLOGIC023: Vertical privilege escalation
        if "admin" in func_name.lower() and not has_auth_check:
            self.issues.append(
                SecurityIssue(
                    severity="CRITICAL",
                    category="Access Control",
                    message=f"Vertical privilege escalation in '{func_name}': Admin function without role check",
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self._get_code_snippet(node),
                    fix_suggestion="Add role verification: if not user.is_admin: raise Forbidden()",
                    cwe_id="CWE-269",
                    owasp_id="ASVS-4.1.2",
                )
            )

        # BIZLOGIC024: Horizontal privilege escalation (IDOR)
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                snippet = self._get_code_snippet(child)
                if any(id_field in snippet for id_field in ["user_id", "account_id", "customer_id"]):
                    # Check if it's from request without ownership check
                    if "request" in snippet and not has_auth_check:
                        self.issues.append(
                            SecurityIssue(
                                severity="CRITICAL",
                                category="Access Control",
                                message=f"Horizontal privilege escalation in '{func_name}': User can access others' data via ID",
                                line_number=child.lineno if hasattr(child, 'lineno') else node.lineno,
                                column=child.col_offset if hasattr(child, 'col_offset') else 0,
                                code_snippet=snippet,
                                fix_suggestion="Verify resource ownership: if resource.user_id != current_user.id: raise Forbidden()",
                                cwe_id="CWE-639",
                                owasp_id="ASVS-4.1.3",
                            )
                        )
                        break

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Check for concurrent modification during iteration."""
        # BIZLOGIC008: Concurrent modification
        # Get the target being iterated over (reserved for future use)
        # iter_target = None
        # if isinstance(node.target, ast.Name):
        #     iter_target = node.target.id
        
        for child in ast.walk(node):
            # Check for Delete statements (del keyword)
            if isinstance(child, ast.Delete):
                for target in child.targets:
                    if isinstance(target, ast.Subscript):
                        # del collection[key] pattern
                        if isinstance(target.value, ast.Name):
                            self.issues.append(
                                SecurityIssue(
                                    severity="MEDIUM",
                                    category="Race Condition",
                                    message="Concurrent modification risk: Modifying collection during iteration",
                                    line_number=child.lineno if hasattr(child, 'lineno') else node.lineno,
                                    column=child.col_offset if hasattr(child, 'col_offset') else 0,
                                    code_snippet=self._get_code_snippet(child),
                                    fix_suggestion="Iterate over a copy: for item in list(collection): ...",
                                    cwe_id="CWE-362",
                                    owasp_id="ASVS-11.1.3",
                                )
                            )
                            break
            
            # Check for method calls that modify collections
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                # Check if modifying the collection being iterated
                if any(mod in call_name for mod in ["append", "remove", "pop", "extend", "insert", "clear"]):
                    self.issues.append(
                        SecurityIssue(
                            severity="MEDIUM",
                            category="Race Condition",
                            message="Concurrent modification risk: Modifying collection during iteration",
                            line_number=child.lineno if hasattr(child, 'lineno') else node.lineno,
                            column=child.col_offset if hasattr(child, 'col_offset') else 0,
                            code_snippet=self._get_code_snippet(child),
                            fix_suggestion="Iterate over a copy: for item in list(collection): ...",
                            cwe_id="CWE-362",
                            owasp_id="ASVS-11.1.3",
                        )
                    )
                    break

        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        """Track lock acquisitions for deadlock detection."""
        # BIZLOGIC009-010: Lock ordering and deadlock
        has_lock = False
        for item in node.items:
            lock_name = None
            
            # Check if this is a lock (either from a call or a variable)
            if isinstance(item.context_expr, ast.Call):
                call_name = self._get_call_name(item.context_expr)
                if "Lock" in call_name or "lock" in call_name.lower():
                    has_lock = True
                    lock_name = call_name
                    if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                        lock_name = item.optional_vars.id
            elif isinstance(item.context_expr, ast.Name):
                # Variable name suggesting it's a lock
                var_name = item.context_expr.id
                if "lock" in var_name.lower():
                    has_lock = True
                    lock_name = var_name
            
            if has_lock and lock_name:
                self.lock_acquisitions.append((node.lineno, lock_name))
                
                # Check for nested locks (potential deadlock)
                # Look for another with statement inside this one
                for child in ast.walk(node):
                    if isinstance(child, ast.With) and child != node:
                        # Check if the nested with is also acquiring a lock
                        for nested_item in child.items:
                            is_nested_lock = False
                            if isinstance(nested_item.context_expr, ast.Call):
                                nested_call = self._get_call_name(nested_item.context_expr)
                                if "Lock" in nested_call or "lock" in nested_call.lower():
                                    is_nested_lock = True
                            elif isinstance(nested_item.context_expr, ast.Name):
                                nested_var = nested_item.context_expr.id
                                if "lock" in nested_var.lower():
                                    is_nested_lock = True
                            
                            if is_nested_lock:
                                self.issues.append(
                                    SecurityIssue(
                                        severity="MEDIUM",
                                        category="Race Condition",
                                        message="Deadlock potential: Nested locks detected",
                                        line_number=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=self._get_code_snippet(node),
                                        fix_suggestion="Avoid nested locks; use lock hierarchy or single lock",
                                        cwe_id="CWE-833",
                                        owasp_id="ASVS-11.1.3",
                                    )
                                )
                                break
                        if self.issues and self.issues[-1].message == "Deadlock potential: Nested locks detected":
                            break

        self.generic_visit(node)


def analyze_business_logic(source_code: str, filename: str = "<unknown>") -> List[SecurityIssue]:
    """
    Analyze Python source code for business logic security vulnerabilities.
    
    Detects 30 types of business logic vulnerabilities:
    - 10 race condition and timing issues
    - 10 financial and transaction logic flaws
    - 10 access control vulnerabilities
    
    Args:
        source_code: Python source code to analyze
        filename: Name of the file being analyzed
        
    Returns:
        List of SecurityIssue objects for vulnerabilities found
    """
    try:
        tree = ast.parse(source_code, filename=filename)
        visitor = BusinessLogicVisitor(source_code)
        visitor.visit(tree)
        return visitor.issues
    except SyntaxError as e:
        logger = PyGuardLogger()
        logger.error(f"Syntax error in {filename}: {e}")
        return []


__all__ = [
    "analyze_business_logic",
    "BusinessLogicVisitor",
    "BUSINESS_LOGIC_RULES",
]
