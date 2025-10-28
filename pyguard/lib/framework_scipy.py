"""
SciPy Security Analysis.

Detects and auto-fixes common security vulnerabilities in SciPy applications.
This module provides scientific computing framework-specific security checks focusing on
numerical computation security, file I/O security, optimization security, and signal processing security.

Security Areas Covered (10 checks implemented):
- Unsafe optimization parameters (SCP001)
- Signal processing injection (SCP002)
- FFT input validation (SCP003)
- Sparse matrix vulnerabilities (SCP004)
- Integration function risks (SCP005)
- Linear algebra security (SCP006)
- Interpolation injection (SCP007)
- File format vulnerabilities (SCP008)
- Statistics calculation manipulation (SCP009)
- Spatial algorithm DoS (SCP010)

Total Security Checks: 10 rules (SCP001-SCP010)

References:
- SciPy Security | https://scipy.org/ | High
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
- CWE-20 (Improper Input Validation) | https://cwe.mitre.org/data/definitions/20.html | High
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
"""

import ast
from pathlib import Path

from pyguard.lib.custom_rules import RuleViolation


class ScipySecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting SciPy security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = str(file_path)
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_scipy_import = False
        self.scipy_aliases: set[str] = {"scipy"}
        self.scipy_submodules: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track SciPy imports."""
        for alias in node.names:
            if alias.name == "scipy" or alias.name.startswith("scipy."):
                self.has_scipy_import = True
                if alias.asname:
                    self.scipy_aliases.add(alias.asname)
                if "." in alias.name:
                    submodule = alias.name.split(".")[1]
                    self.scipy_submodules.add(submodule)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track SciPy imports."""
        if node.module and node.module.startswith("scipy"):
            self.has_scipy_import = True
            if "." in node.module:
                submodule = node.module.split(".")[1]
                self.scipy_submodules.add(submodule)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_scipy_import:
            self.generic_visit(node)
            return

        # Check for unsafe optimization parameters (SCP001)
        self._check_unsafe_optimization(node)

        # Check for signal processing injection (SCP002)
        self._check_signal_processing_injection(node)

        # Check for FFT input validation (SCP003)
        self._check_fft_input_validation(node)

        # Check for sparse matrix vulnerabilities (SCP004)
        self._check_sparse_matrix_issues(node)

        # Check for integration function risks (SCP005)
        self._check_integration_risks(node)

        # Check for linear algebra security (SCP006)
        self._check_linalg_security(node)

        # Check for interpolation injection (SCP007)
        self._check_interpolation_injection(node)

        # Check for file format vulnerabilities (SCP008)
        self._check_file_format_vulnerabilities(node)

        # Check for statistics calculation manipulation (SCP009)
        self._check_stats_manipulation(node)

        # Check for spatial algorithm DoS (SCP010)
        self._check_spatial_dos(node)

        self.generic_visit(node)

    def _check_unsafe_optimization(self, node: ast.Call) -> None:
        """Check for unsafe optimization parameters (SCP001)."""
        func_name = self._get_func_name(node)

        # Check for minimize, minimize_scalar, etc. without bounds
        optimization_funcs = [
            "minimize",
            "minimize_scalar",
            "differential_evolution",
            "basinhopping",
            "shgo",
            "dual_annealing",
        ]

        if any(opt in func_name for opt in optimization_funcs):
            has_bounds = any(kw.arg == "bounds" for kw in node.keywords)
            has_maxiter = any(kw.arg in ["maxiter", "max_iter"] for kw in node.keywords)

            if not has_bounds:
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP001",
                        rule_name="Unsafe Optimization Parameters",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without bounds - may cause resource exhaustion or unexpected results",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Set bounds parameter to limit search space and prevent unbounded optimization",
                    )
                )

            if not has_maxiter:
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP001",
                        rule_name="Unsafe Optimization Parameters",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without max iterations - may cause infinite loop or DoS",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Set maxiter parameter to prevent infinite loops and resource exhaustion",
                    )
                )

    def _check_signal_processing_injection(self, node: ast.Call) -> None:
        """Check for signal processing injection (SCP002)."""
        func_name = self._get_func_name(node)

        # Check for filter design functions with user input
        signal_funcs = ["butter", "cheby1", "cheby2", "ellip", "bessel", "iirfilter"]

        if any(sig in func_name for sig in signal_funcs):
            # Check if filter order comes from user input or is a variable (not a constant)
            if node.args and self._is_potentially_user_input_or_variable(node.args[0]):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP002",
                        rule_name="Signal Processing Injection",
                        severity="HIGH",
                        category="SECURITY",
                        message=f"{func_name} with potentially unsafe filter order - may cause DoS",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate and limit filter order before use to prevent resource exhaustion",
                    )
                )

    def _check_fft_input_validation(self, node: ast.Call) -> None:
        """Check for FFT input validation (SCP003)."""
        func_name = self._get_func_name(node)

        # Check for FFT functions without input validation
        fft_funcs = ["fft", "fft2", "fftn", "rfft", "irfft", "ifft"]

        if any(fft in func_name for fft in fft_funcs):
            if not self._has_input_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP003",
                        rule_name="FFT Input Validation",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without input validation - may be vulnerable to DoS",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate FFT input size and type to prevent resource exhaustion",
                    )
                )

    def _check_sparse_matrix_issues(self, node: ast.Call) -> None:
        """Check for sparse matrix vulnerabilities (SCP004)."""
        func_name = self._get_func_name(node)

        # Check for sparse matrix construction without size limits
        sparse_constructors = [
            "csr_matrix",
            "csc_matrix",
            "coo_matrix",
            "lil_matrix",
            "dok_matrix",
            "dia_matrix",
            "bsr_matrix",
        ]

        if any(sparse in func_name for sparse in sparse_constructors):
            # Check if shape is validated
            if not self._has_shape_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP004",
                        rule_name="Sparse Matrix Vulnerabilities",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without shape validation - may cause memory exhaustion",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate sparse matrix dimensions before construction to prevent DoS",
                    )
                )

    def _check_integration_risks(self, node: ast.Call) -> None:
        """Check for integration function risks (SCP005)."""
        func_name = self._get_func_name(node)

        # Check for integration functions without limits
        integration_funcs = ["quad", "dblquad", "tplquad", "nquad", "romberg", "quadrature"]

        if any(integ in func_name for integ in integration_funcs):
            has_limit = any(kw.arg in ["limit", "maxiter"] for kw in node.keywords)

            if not has_limit:
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP005",
                        rule_name="Integration Function Risks",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without iteration limit - may cause resource exhaustion",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Set limit or maxiter parameter to prevent infinite loops",
                    )
                )

    def _check_linalg_security(self, node: ast.Call) -> None:
        """Check for linear algebra security (SCP006)."""
        func_name = self._get_func_name(node)

        # Check for matrix decomposition without error handling
        linalg_funcs = ["inv", "solve", "lstsq", "eig", "svd", "qr", "cholesky"]

        if any(linalg in func_name for linalg in linalg_funcs):
            # Check if there's error handling for singular matrices
            if not self._has_error_handling_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP006",
                        rule_name="Linear Algebra Security",
                        severity="LOW",
                        category="SECURITY",
                        message=f"{func_name} without error handling - may crash on singular matrices",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Add try-except block to handle LinAlgError for singular or ill-conditioned matrices",
                    )
                )

    def _check_interpolation_injection(self, node: ast.Call) -> None:
        """Check for interpolation injection (SCP007)."""
        func_name = self._get_func_name(node)

        # Check for interpolation functions with user input
        interp_funcs = ["interp1d", "interp2d", "interpn", "griddata", "Rbf"]

        if any(interp in func_name for interp in interp_funcs):
            # Check if interpolation points are validated
            if not self._has_input_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP007",
                        rule_name="Interpolation Injection",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without input validation - may cause DoS with large datasets",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate interpolation points size and range to prevent resource exhaustion",
                    )
                )

    def _check_file_format_vulnerabilities(self, node: ast.Call) -> None:
        """Check for file format vulnerabilities (SCP008)."""
        func_name = self._get_func_name(node)

        # Check for unsafe file loading (MATLAB, NetCDF, etc.)
        file_funcs = ["loadmat", "savemat", "whosmat"]

        if any(file_func in func_name for file_func in file_funcs):
            self.violations.append(
                RuleViolation(
                    rule_id="SCP008",
                    rule_name="File Format Vulnerabilities",
                    severity="HIGH",
                    category="SECURITY",
                    message=f"{func_name} may execute arbitrary code from malicious files",
                    line_number=node.lineno,
                    file_path=self.file_path,
                    suggestion="Validate file source and use struct_as_record=False to prevent code execution",
                )
            )

    def _check_stats_manipulation(self, node: ast.Call) -> None:
        """Check for statistics calculation manipulation (SCP009)."""
        func_name = self._get_func_name(node)

        # Check for statistical functions without input validation
        stats_funcs = ["ttest_ind", "kstest", "mannwhitneyu", "wilcoxon", "kruskal"]

        if any(stat in func_name for stat in stats_funcs):
            # Check if sample size is validated
            if not self._has_input_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP009",
                        rule_name="Statistics Calculation Manipulation",
                        severity="LOW",
                        category="SECURITY",
                        message=f"{func_name} without sample size validation - results may be unreliable",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate sample sizes and check for NaN/Inf values before statistical tests",
                    )
                )

    def _check_spatial_dos(self, node: ast.Call) -> None:
        """Check for spatial algorithm DoS (SCP010)."""
        func_name = self._get_func_name(node)

        # Check for spatial algorithms without size limits
        spatial_funcs = ["KDTree", "cKDTree", "distance_matrix", "cdist", "pdist"]

        if any(spatial in func_name for spatial in spatial_funcs):
            # Check if data size is validated
            if not self._has_size_validation_nearby(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SCP010",
                        rule_name="Spatial Algorithm DoS",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without size validation - may cause memory exhaustion",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate input data size before spatial operations to prevent DoS",
                    )
                )

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from a call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _is_potentially_user_input_or_variable(self, node: ast.expr) -> bool:
        """Check if a node might represent user input or a variable (not a safe constant)."""
        # Check for common patterns of user input or variables
        if isinstance(node, ast.Name):
            # Any variable name is potentially unsafe
            user_input_patterns = ["input", "user", "request", "param", "arg", "data", "order"]
            return any(pattern in node.id.lower() for pattern in user_input_patterns)
        # Also check for attribute access like request.args
        if isinstance(node, ast.Attribute):
            return True
        # Constants (numbers) are safe
        if isinstance(node, ast.Constant):
            return False
        return False

    def _has_input_validation_nearby(self, node: ast.Call) -> bool:
        """Check if there's input validation near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : line])
            validation_patterns = ["len(", "size", "shape", "validate", "check", "assert"]
            return any(pattern in context.lower() for pattern in validation_patterns)
        return False

    def _has_shape_validation_nearby(self, node: ast.Call) -> bool:
        """Check if there's shape validation near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : line])
            validation_patterns = ["shape", "size", "ndim", "validate", "check"]
            return any(pattern in context.lower() for pattern in validation_patterns)
        return False

    def _has_size_validation_nearby(self, node: ast.Call) -> bool:
        """Check if there's size validation near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : line])
            validation_patterns = ["len(", "size", "count", "validate", "check", "limit"]
            return any(pattern in context.lower() for pattern in validation_patterns)
        return False

    def _has_error_handling_nearby(self, node: ast.Call) -> bool:
        """Check if there's error handling near a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 5) : min(len(self.lines), line + 5)])
            error_patterns = ["try:", "except", "linalgerror", "catch"]
            return any(pattern in context.lower() for pattern in error_patterns)
        return False


def analyze_scipy_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for SciPy security vulnerabilities.

    Args:
        file_path: Path to the Python file being analyzed
        code: Source code to analyze

    Returns:
        List of rule violations found
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    visitor = ScipySecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations
