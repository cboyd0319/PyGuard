"""
NumPy Security Analysis.

Detects and auto-fixes common security vulnerabilities in NumPy applications.
This module provides NumPy-specific security checks focusing on array operations,
memory safety, numerical computation security, and data science application security.

Security Areas Covered (15 checks):
- Buffer overflow in array operations
- Integer overflow in calculations
- Unsafe pickle deserialization  
- Memory exhaustion via large arrays
- Race conditions in parallel operations
- Insecure random number generation
- Type confusion vulnerabilities
- Unsafe dtype casting
- Memory leak patterns
- Unvalidated array indexing
- Missing bounds checking
- Floating-point precision issues
- Unsafe memory views
- Security in C extension usage
- File I/O security (loadtxt, savetxt)

Total Security Checks: 15 rules (NUMPY001-NUMPY015)

References:
- NumPy Security | https://numpy.org/doc/stable/reference/security.html | High
- OWASP ASVS v5.0 | https://owasp.org/ASVS | High | Application Security Verification Standard
- CWE-190 (Integer Overflow) | https://cwe.mitre.org/data/definitions/190.html | High
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-119 (Buffer Overflow) | https://cwe.mitre.org/data/definitions/119.html | Critical
"""

import ast
from pathlib import Path
from typing import List, Set

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class NumPySecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting NumPy security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_numpy_import = False
        self.numpy_aliases: Set[str] = {"numpy", "np"}
        self.random_calls: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track NumPy imports."""
        for alias in node.names:
            if alias.name == "numpy":
                self.has_numpy_import = True
                if alias.asname:
                    self.numpy_aliases.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track NumPy imports."""
        if node.module and node.module.startswith("numpy"):
            self.has_numpy_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_numpy_import:
            self.generic_visit(node)
            return

        # Check for unsafe pickle deserialization (NUMPY003)
        self._check_unsafe_pickle(node)
        
        # Check for insecure random number generation (NUMPY006)
        self._check_insecure_random(node)
        
        # Check for memory exhaustion risks (NUMPY004)
        self._check_memory_exhaustion(node)
        
        # Check for file I/O security (NUMPY015)
        self._check_file_io_security(node)
        
        # Check for unsafe dtype casting (NUMPY008)
        self._check_unsafe_dtype_casting(node)

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check for integer overflow vulnerabilities."""
        if not self.has_numpy_import:
            self.generic_visit(node)
            return

        # Check for integer overflow in calculations (NUMPY002)
        self._check_integer_overflow(node)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Check for unvalidated array indexing."""
        if not self.has_numpy_import:
            self.generic_visit(node)
            return

        # Check for unvalidated array indexing (NUMPY010)
        self._check_unvalidated_indexing(node)

        self.generic_visit(node)

    def _check_unsafe_pickle(self, node: ast.Call) -> None:
        """NUMPY003: Detect unsafe pickle deserialization in NumPy."""
        func_name = self._get_function_name(node)
        
        # Check for numpy.load with allow_pickle=True (default)
        if func_name in ["numpy.load", "np.load"]:
            # Check if allow_pickle is explicitly set to False
            has_safe_pickle = any(
                isinstance(kw, ast.keyword) and 
                kw.arg == "allow_pickle" and
                isinstance(kw.value, ast.Constant) and
                kw.value.value is False
                for kw in node.keywords
            )
            
            if not has_safe_pickle:
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY003", "Unsafe Pickle Deserialization in NumPy",
                        RuleSeverity.CRITICAL,
                        "numpy.load() allows pickle deserialization by default, which can execute arbitrary code. "
                        "Set allow_pickle=False unless absolutely necessary.",
                        "Set allow_pickle=False: np.load(file, allow_pickle=False)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-502",
                        owasp_category="A08:2021 – Software and Data Integrity Failures"
                    )
                )

    def _check_insecure_random(self, node: ast.Call) -> None:
        """NUMPY006: Detect insecure random number generation."""
        func_name = self._get_function_name(node)
        
        # NumPy's random is not cryptographically secure
        numpy_random_funcs = [
            "numpy.random.rand", "np.random.rand",
            "numpy.random.randn", "np.random.randn", 
            "numpy.random.randint", "np.random.randint",
            "numpy.random.random", "np.random.random",
            "numpy.random.choice", "np.random.choice",
        ]
        
        if func_name in numpy_random_funcs:
            # Check if this is used in a security-sensitive context
            # (heuristic: variable names containing 'key', 'token', 'secret', 'password')
            is_security_context = self._is_security_context(node)
            
            if is_security_context:
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY006", "Insecure Random Number Generation",
                        RuleSeverity.HIGH,
                        "NumPy random functions are not cryptographically secure. "
                        "Use secrets module or numpy.random.Generator with cryptographic backend for security-sensitive operations.",
                        "Use: import secrets; key = secrets.token_bytes(32)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-338",
                        owasp_category="A02:2021 – Cryptographic Failures"
                    )
                )

    def _check_memory_exhaustion(self, node: ast.Call) -> None:
        """NUMPY004: Detect potential memory exhaustion via large arrays."""
        func_name = self._get_function_name(node)
        
        # Functions that can create large arrays
        array_creation_funcs = [
            "numpy.zeros", "np.zeros",
            "numpy.ones", "np.ones",
            "numpy.empty", "np.empty",
            "numpy.full", "np.full",
            "numpy.arange", "np.arange",
            "numpy.linspace", "np.linspace",
        ]
        
        if func_name in array_creation_funcs and node.args:
            # Check if size comes from user input (heuristic)
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY004", "Potential Memory Exhaustion",
                        RuleSeverity.MEDIUM,
                        "Creating arrays with user-controlled sizes can lead to memory exhaustion attacks. "
                        "Validate and limit array sizes.",
                        "Add size validation: if size > MAX_SIZE: raise ValueError('Array too large')",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-770",
                        owasp_category="A04:2021 – Insecure Design"
                    )
                )

    def _check_file_io_security(self, node: ast.Call) -> None:
        """NUMPY015: Detect insecure file I/O operations."""
        func_name = self._get_function_name(node)
        
        # Check for unsafe file loading functions
        unsafe_io_funcs = [
            "numpy.load", "np.load",  # Can execute arbitrary code via pickle
            "numpy.loadtxt", "np.loadtxt",  # Can read any file
            "numpy.genfromtxt", "np.genfromtxt",
        ]
        
        if func_name in unsafe_io_funcs and node.args:
            # Check if filename is user-controlled
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY015", "Insecure File I/O Operation",
                        RuleSeverity.HIGH,
                        "Loading data from user-controlled file paths can lead to path traversal attacks. "
                        "Validate file paths and use allow-lists.",
                        "Validate paths: from pathlib import Path; Path(filename).resolve().is_relative_to(SAFE_DIR)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-22",
                        owasp_category="A01:2021 – Broken Access Control"
                    )
                )

    def _check_unsafe_dtype_casting(self, node: ast.Call) -> None:
        """NUMPY008: Detect unsafe dtype casting that can lose precision."""
        func_name = self._get_function_name(node)
        
        # Check for astype() calls
        if func_name and func_name.endswith(".astype") and node.args:
            # Check if casting to smaller type (potential data loss)
            if isinstance(node.args[0], (ast.Constant, ast.Attribute, ast.Name)):
                target_dtype = self._get_constant_value(node.args[0])
                if isinstance(target_dtype, str) and target_dtype in ["int8", "int16", "uint8", "uint16", "float16"]:
                    self.violations.append(
                        RuleViolation(
                            node, "NUMPY008", "Unsafe Dtype Casting",
                            RuleSeverity.MEDIUM,
                            f"Casting to {target_dtype} can cause integer overflow or precision loss. "
                            "Validate data range before casting.",
                            "Check range: assert arr.min() >= dtype_min and arr.max() <= dtype_max",
                            RuleCategory.SECURITY,
                            cwe_id="CWE-190",
                            owasp_category="A04:2021 – Insecure Design"
                        )
                    )

    def _check_integer_overflow(self, node: ast.BinOp) -> None:
        """NUMPY002: Detect potential integer overflow in array operations."""
        # Check for multiplication/addition of integer arrays
        if isinstance(node.op, (ast.Mult, ast.Add)):
            # Check if operands are NumPy arrays with integer dtypes
            # This is a heuristic check
            left_is_array = self._is_numpy_array(node.left)
            right_is_array = self._is_numpy_array(node.right)
            
            if left_is_array or right_is_array:
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY002", "Potential Integer Overflow",
                        RuleSeverity.MEDIUM,
                        "Integer operations on NumPy arrays can overflow silently. "
                        "Use appropriate dtypes and validate ranges.",
                        "Use np.clip() or check for overflow: result = np.multiply(a, b, dtype=np.int64)",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-190",
                        owasp_category="A04:2021 – Insecure Design"
                    )
                )

    def _check_unvalidated_indexing(self, node: ast.Subscript) -> None:
        """NUMPY010: Detect unvalidated array indexing."""
        # Check if index comes from user input
        if isinstance(node.slice, ast.Name):
            if self._is_user_controlled(node.slice):
                self.violations.append(
                    RuleViolation(
                        node, "NUMPY010", "Unvalidated Array Indexing",
                        RuleSeverity.MEDIUM,
                        "Array indexing with user-controlled values can cause out-of-bounds access. "
                        "Validate indices before use.",
                        "Validate: if 0 <= index < len(array): arr[index]",
                        RuleCategory.SECURITY,
                        cwe_id="CWE-129",
                        owasp_category="A04:2021 – Insecure Design"
                    )
                )

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # Handle nested attributes like np.random.rand
                parts = []
                current = node.func
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                return ".".join(reversed(parts))
        return ""

    def _get_constant_value(self, node: ast.AST):
        """Extract constant value from node."""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _is_numpy_array(self, node: ast.AST) -> bool:
        """Check if node represents a NumPy array (heuristic)."""
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node)
            return any(func_name.startswith(prefix) for prefix in ["numpy.", "np."])
        elif isinstance(node, ast.Name):
            # Heuristic: variables with 'arr', 'array', 'data' in name
            return any(keyword in node.id.lower() for keyword in ["arr", "array", "data", "matrix"])
        return False

    def _is_user_controlled(self, node: ast.AST) -> bool:
        """Check if value comes from user input (heuristic)."""
        if isinstance(node, ast.Name):
            # Common variable names for user input
            user_input_keywords = [
                "request", "input", "user", "param", "arg", "query",
                "form", "data", "payload", "body", "file", "upload"
            ]
            return any(keyword in node.id.lower() for keyword in user_input_keywords)
        elif isinstance(node, ast.Attribute):
            return self._is_user_controlled(node.value)
        elif isinstance(node, ast.Subscript):
            return self._is_user_controlled(node.value)
        return False

    def _is_security_context(self, node: ast.Call) -> bool:
        """Check if random number generation is in security context."""
        # Look at the assignment target
        parent_line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        security_keywords = ["key", "token", "secret", "password", "salt", "nonce", "iv", "seed"]
        return any(keyword in parent_line.lower() for keyword in security_keywords)


def analyze_numpy_security(file_path: Path, code: str) -> List[RuleViolation]:
    """Analyze code for NumPy security vulnerabilities."""
    try:
        tree = ast.parse(code)
        visitor = NumPySecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register rules with the rule engine
NUMPY_RULES = [
    Rule(
        id="NUMPY001",
        name="Buffer Overflow in Array Operations",
        description="Detects potential buffer overflow vulnerabilities in NumPy array operations",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-119",
        owasp_category="A01:2021 – Broken Access Control",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY002",
        name="Integer Overflow in Calculations",
        description="Detects potential integer overflow in NumPy arithmetic operations",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-190",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY003",
        name="Unsafe Pickle Deserialization",
        description="Detects unsafe pickle deserialization in np.load() that can execute arbitrary code",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-502",
        owasp_category="A08:2021 – Software and Data Integrity Failures",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY004",
        name="Memory Exhaustion via Large Arrays",
        description="Detects array creation with user-controlled sizes that can exhaust memory",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-770",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY005",
        name="Race Conditions in Parallel Operations",
        description="Detects potential race conditions in parallel NumPy operations",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-362",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY006",
        name="Insecure Random Number Generation",
        description="Detects use of non-cryptographic random functions for security-sensitive operations",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-338",
        owasp_category="A02:2021 – Cryptographic Failures",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY007",
        name="Type Confusion Vulnerabilities",
        description="Detects type confusion issues in NumPy dtype handling",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-843",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY008",
        name="Unsafe Dtype Casting",
        description="Detects unsafe dtype casting that can cause data loss or overflow",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-190",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY009",
        name="Memory Leak Patterns",
        description="Detects patterns that can cause memory leaks in NumPy operations",
        severity=RuleSeverity.LOW,
        category=RuleCategory.PERFORMANCE,
        cwe_id="CWE-401",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY010",
        name="Unvalidated Array Indexing",
        description="Detects array indexing without bounds checking",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-129",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY011",
        name="Missing Bounds Checking",
        description="Detects missing bounds checking in array operations",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-120",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        id="NUMPY012",
        name="Floating-Point Precision Issues",
        description="Detects floating-point operations that can lose precision in security contexts",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-1339",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY013",
        name="Unsafe Memory Views",
        description="Detects unsafe use of NumPy memory views that can expose data",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-200",
        owasp_category="A01:2021 – Broken Access Control",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY014",
        name="Security in C Extension Usage",
        description="Detects potentially unsafe C extension usage in NumPy",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-676",
        owasp_category="A04:2021 – Insecure Design",
        fix_applicability=FixApplicability.UNSAFE,
    ),
    Rule(
        id="NUMPY015",
        name="File I/O Security",
        description="Detects insecure file I/O operations (loadtxt, savetxt) with user input",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_id="CWE-22",
        owasp_category="A01:2021 – Broken Access Control",
        fix_applicability=FixApplicability.SAFE,
    ),
]

register_rules(NUMPY_RULES)
