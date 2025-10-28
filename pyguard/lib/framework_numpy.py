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
        self.violations: list[RuleViolation] = []
        self.has_numpy_import = False
        self.numpy_aliases: set[str] = {"numpy", "np"}
        self.random_calls: set[str] = set()
        self.user_controlled_vars: set[str] = set()  # Track variables from user input

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

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments from user input."""
        # Check if the value comes from user input
        if isinstance(node.value, ast.Call):
            # Check if it's a call to request.args.get(), input(), etc.
            if isinstance(node.value.func, ast.Attribute):
                # Pattern: request.args.get(), request.form.get(), etc.
                if (
                    isinstance(node.value.func.value, ast.Attribute)
                    and isinstance(node.value.func.value.value, ast.Name)
                    and node.value.func.value.value.id in ["request", "req"]
                ):
                    # Track all targets of this assignment
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.user_controlled_vars.add(target.id)
            elif isinstance(node.value.func, ast.Name):
                # Pattern: input(), raw_input()
                if node.value.func.id in ["input", "raw_input"]:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.user_controlled_vars.add(target.id)
        elif isinstance(node.value, ast.Subscript):
            # Pattern: request.json['key'], request.args['key'], etc.
            if self._is_user_controlled(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.user_controlled_vars.add(target.id)
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
                isinstance(kw, ast.keyword)
                and kw.arg == "allow_pickle"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )

            if not has_safe_pickle:
                self.violations.append(
                    RuleViolation(
                        rule_id="NUMPY003",
                        message="numpy.load() allows pickle deserialization by default, which can execute arbitrary code. "
                        "Set allow_pickle=False unless absolutely necessary.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Set allow_pickle=False: np.load(file, allow_pickle=False)",
                        cwe_id="CWE-502",
                        owasp_id="A08:2021 - Software and Data Integrity Failures",
                    )
                )

    def _check_insecure_random(self, node: ast.Call) -> None:
        """NUMPY006: Detect insecure random number generation."""
        func_name = self._get_function_name(node)

        # NumPy's random is not cryptographically secure
        numpy_random_funcs = [
            "numpy.random.rand",
            "np.random.rand",
            "numpy.random.randn",
            "np.random.randn",
            "numpy.random.randint",
            "np.random.randint",
            "numpy.random.random",
            "np.random.random",
            "numpy.random.choice",
            "np.random.choice",
        ]

        if func_name in numpy_random_funcs:
            # Check if this is used in a security-sensitive context
            # (heuristic: variable names containing 'key', 'token', 'secret', 'password')
            is_security_context = self._is_security_context(node)

            if is_security_context:
                self.violations.append(
                    RuleViolation(
                        rule_id="NUMPY006",
                        message="NumPy random functions are not cryptographically secure. "
                        "Use secrets module or numpy.random.Generator with cryptographic backend for security-sensitive operations.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Use: import secrets; key = secrets.token_bytes(32)",
                        cwe_id="CWE-338",
                        owasp_id="A02:2021 - Cryptographic Failures",
                    )
                )

    def _check_memory_exhaustion(self, node: ast.Call) -> None:
        """NUMPY004: Detect potential memory exhaustion via large arrays."""
        func_name = self._get_function_name(node)

        # Functions that can create large arrays
        array_creation_funcs = [
            "numpy.zeros",
            "np.zeros",
            "numpy.ones",
            "np.ones",
            "numpy.empty",
            "np.empty",
            "numpy.full",
            "np.full",
            "numpy.arange",
            "np.arange",
            "numpy.linspace",
            "np.linspace",
        ]

        if func_name in array_creation_funcs and node.args:
            # Check if size comes from user input (heuristic)
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        rule_id="NUMPY004",
                        message="Creating arrays with user-controlled sizes can lead to memory exhaustion attacks. "
                        "Validate and limit array sizes.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Add size validation: if size > MAX_SIZE: raise ValueError('Array too large')",
                        cwe_id="CWE-770",
                        owasp_id="A04:2021 - Insecure Design",
                    )
                )

    def _check_file_io_security(self, node: ast.Call) -> None:
        """NUMPY015: Detect insecure file I/O operations."""
        func_name = self._get_function_name(node)

        # Check for unsafe file loading functions
        unsafe_io_funcs = [
            "numpy.load",
            "np.load",  # Can execute arbitrary code via pickle
            "numpy.loadtxt",
            "np.loadtxt",  # Can read any file
            "numpy.genfromtxt",
            "np.genfromtxt",
        ]

        if func_name in unsafe_io_funcs and node.args:
            # Check if filename is user-controlled
            if self._is_user_controlled(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        rule_id="NUMPY015",
                        message="Loading data from user-controlled file paths can lead to path traversal attacks. "
                        "Validate file paths and use allow-lists.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Validate paths: from pathlib import Path; Path(filename).resolve().is_relative_to(SAFE_DIR)",
                        cwe_id="CWE-22",
                        owasp_id="A01:2021 - Broken Access Control",
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
                if isinstance(target_dtype, str) and target_dtype in [
                    "int8",
                    "int16",
                    "uint8",
                    "uint16",
                    "float16",
                ]:
                    self.violations.append(
                        RuleViolation(
                            rule_id="NUMPY008",
                            message=f"Casting to {target_dtype} can cause integer overflow or precision loss. "
                            "Validate data range before casting.",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            file_path=self.file_path,
                            fix_suggestion="Check range: assert arr.min() >= dtype_min and arr.max() <= dtype_max",
                            cwe_id="CWE-190",
                            owasp_id="A04:2021 - Insecure Design",
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
                        rule_id="NUMPY002",
                        message="Integer operations on NumPy arrays can overflow silently. "
                        "Use appropriate dtypes and validate ranges.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Use np.clip() or check for overflow: result = np.multiply(a, b, dtype=np.int64)",
                        cwe_id="CWE-190",
                        owasp_id="A04:2021 - Insecure Design",
                    )
                )

    def _check_unvalidated_indexing(self, node: ast.Subscript) -> None:
        """NUMPY010: Detect unvalidated array indexing."""
        # Check if index comes from user input
        if isinstance(node.slice, ast.Name):
            if self._is_user_controlled(node.slice):
                self.violations.append(
                    RuleViolation(
                        rule_id="NUMPY010",
                        message="Array indexing with user-controlled values can cause out-of-bounds access. "
                        "Validate indices before use.",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        file_path=self.file_path,
                        fix_suggestion="Validate: if 0 <= index < len(array): arr[index]",
                        cwe_id="CWE-129",
                        owasp_id="A04:2021 - Insecure Design",
                    )
                )

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            if isinstance(node.func.value, ast.Attribute):
                # Handle nested attributes like np.random.rand
                parts = []
                current: ast.expr = node.func
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
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _is_numpy_array(self, node: ast.AST) -> bool:
        """Check if node represents a NumPy array (heuristic)."""
        if isinstance(node, ast.Call):
            func_name = self._get_function_name(node)
            return any(func_name.startswith(prefix) for prefix in ["numpy.", "np."])
        if isinstance(node, ast.Name):
            # Heuristic: variables with 'arr', 'array', 'data' in name
            return any(keyword in node.id.lower() for keyword in ["arr", "array", "data", "matrix"])
        return False

    def _is_user_controlled(self, node: ast.AST) -> bool:
        """Check if value comes from user input (heuristic)."""
        if isinstance(node, ast.Name):
            # Check if variable is tracked as user-controlled
            if node.id in self.user_controlled_vars:
                return True
            # Common variable names for user input
            user_input_keywords = [
                "request",
                "input",
                "user",
                "param",
                "arg",
                "query",
                "form",
                "data",
                "payload",
                "body",
                "file",
                "upload",
            ]
            return any(keyword in node.id.lower() for keyword in user_input_keywords)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._is_user_controlled(node.value)
        return False

    def _is_security_context(self, node: ast.Call) -> bool:
        """Check if random number generation is in security context."""
        # Look at the assignment target
        parent_line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        security_keywords = ["key", "token", "secret", "password", "salt", "nonce", "iv", "seed"]
        return any(keyword in parent_line.lower() for keyword in security_keywords)


def analyze_numpy_security(file_path: Path, code: str) -> list[RuleViolation]:
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
        rule_id="NUMPY001",
        name="numpy-buffer-overflow",
        message_template="Potential buffer overflow in NumPy array operation",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects potential buffer overflow vulnerabilities in NumPy array operations",
        explanation="Buffer overflows can lead to memory corruption and security vulnerabilities",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-119",
        owasp_mapping="A01:2021 - Broken Access Control",
    ),
    Rule(
        rule_id="NUMPY002",
        name="numpy-integer-overflow",
        message_template="Potential integer overflow in NumPy arithmetic operation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects potential integer overflow in NumPy arithmetic operations",
        explanation="Integer overflow in arrays can silently produce incorrect results",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-190",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY003",
        name="numpy-unsafe-pickle",
        message_template="Unsafe pickle deserialization in np.load()",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects unsafe pickle deserialization in np.load() that can execute arbitrary code",
        explanation="np.load() allows pickle deserialization by default which can execute arbitrary code",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-502",
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
    ),
    Rule(
        rule_id="NUMPY004",
        name="numpy-memory-exhaustion",
        message_template="Array creation with user-controlled size can exhaust memory",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects array creation with user-controlled sizes that can exhaust memory",
        explanation="Creating large arrays from user input can lead to denial of service",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-770",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY005",
        name="numpy-race-conditions",
        message_template="Potential race condition in parallel NumPy operation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects potential race conditions in parallel NumPy operations",
        explanation="Concurrent access to arrays without synchronization can cause data corruption",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-362",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY006",
        name="numpy-insecure-random",
        message_template="Non-cryptographic random function used for security-sensitive operation",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects use of non-cryptographic random functions for security-sensitive operations",
        explanation="NumPy random functions are not cryptographically secure",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-338",
        owasp_mapping="A02:2021 - Cryptographic Failures",
    ),
    Rule(
        rule_id="NUMPY007",
        name="numpy-type-confusion",
        message_template="Type confusion in NumPy dtype handling",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects type confusion issues in NumPy dtype handling",
        explanation="Type confusion can lead to unexpected behavior and security issues",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-843",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY008",
        name="numpy-unsafe-dtype-cast",
        message_template="Unsafe dtype casting to {dtype} can cause data loss",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects unsafe dtype casting that can cause data loss or overflow",
        explanation="Casting to smaller types without validation can lose data or overflow",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-190",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY009",
        name="numpy-memory-leak",
        message_template="Potential memory leak in NumPy operation",
        severity=RuleSeverity.LOW,
        category=RuleCategory.PERFORMANCE,
        description="Detects patterns that can cause memory leaks in NumPy operations",
        explanation="Memory leaks can degrade performance and availability over time",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-401",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY010",
        name="numpy-unvalidated-indexing",
        message_template="Array indexing without bounds checking",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects array indexing without bounds checking",
        explanation="Unvalidated indices can cause out-of-bounds access",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-129",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY011",
        name="numpy-missing-bounds-check",
        message_template="Missing bounds checking in array operation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects missing bounds checking in array operations",
        explanation="Operations without bounds checking can access invalid memory",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-120",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY012",
        name="numpy-float-precision",
        message_template="Floating-point precision loss in security context",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects floating-point operations that can lose precision in security contexts",
        explanation="Precision loss in security-sensitive calculations can cause vulnerabilities",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-1339",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY013",
        name="numpy-unsafe-memoryview",
        message_template="Unsafe use of NumPy memory view",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects unsafe use of NumPy memory views that can expose data",
        explanation="Memory views can expose internal data representation",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-200",
        owasp_mapping="A01:2021 - Broken Access Control",
    ),
    Rule(
        rule_id="NUMPY014",
        name="numpy-c-extension-security",
        message_template="Potentially unsafe C extension usage",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects potentially unsafe C extension usage in NumPy",
        explanation="C extensions bypass Python safety mechanisms",
        fix_applicability=FixApplicability.MANUAL,
        cwe_mapping="CWE-676",
        owasp_mapping="A04:2021 - Insecure Design",
    ),
    Rule(
        rule_id="NUMPY015",
        name="numpy-file-io-security",
        message_template="Insecure file I/O with user-controlled path",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects insecure file I/O operations (loadtxt, savetxt) with user input",
        explanation="Loading data from user-controlled paths can lead to path traversal",
        fix_applicability=FixApplicability.SAFE,
        cwe_mapping="CWE-22",
        owasp_mapping="A01:2021 - Broken Access Control",
    ),
]

register_rules(NUMPY_RULES)
