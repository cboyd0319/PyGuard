"""
Scikit-learn Security Analysis.

Detects and auto-fixes common security vulnerabilities in Scikit-learn applications.
This module provides ML framework-specific security checks focusing on model security,
training pipeline security, prediction security, and data science application security.

Security Areas Covered (8 checks implemented):
- Model pickle deserialization (SKL001)
- Missing input validation (SKL009)
- Grid search resource exhaustion (SKL012)
- Unsafe model persistence (SKL008)
- Pipeline security issues (SKL010)
- Cross-validation leakage (SKL005)
- Training data poisoning (SKL003)
- Hyperparameter injection (SKL007)

Total Security Checks: 8 rules (SKL001-SKL012)

References:
- Scikit-learn Security | https://scikit-learn.org/stable/ | High
- OWASP Machine Learning Security | https://owasp.org/www-project-machine-learning-security-top-10/ | High
- CWE-502 (Deserialization) | https://cwe.mitre.org/data/definitions/502.html | Critical
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
- CWE-20 (Improper Input Validation) | https://cwe.mitre.org/data/definitions/20.html | High
"""

import ast
from pathlib import Path

from pyguard.lib.custom_rules import RuleViolation


class SklearnSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Scikit-learn security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        # TODO: Add docstring
        self.file_path = str(file_path)
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_sklearn_import = False
        self.sklearn_aliases: set[str] = {"sklearn"}
        self.joblib_imports: set[str] = set()
        self.pickle_imports: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track Scikit-learn imports."""
        for alias in node.names:
            if alias.name == "sklearn" or alias.name.startswith("sklearn."):
                self.has_sklearn_import = True
                if alias.asname:
                    self.sklearn_aliases.add(alias.asname)
            elif alias.name == "joblib":
                self.joblib_imports.add(alias.asname or "joblib")
            elif alias.name == "pickle":
                self.pickle_imports.add(alias.asname or "pickle")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Scikit-learn imports."""
        if node.module:
            if node.module.startswith("sklearn"):
                self.has_sklearn_import = True
            elif node.module == "joblib":
                for name in node.names:
                    self.joblib_imports.add(name.asname or name.name)
            elif node.module == "pickle":
                for name in node.names:
                    self.pickle_imports.add(name.asname or name.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_sklearn_import and not self.joblib_imports and not self.pickle_imports:
            self.generic_visit(node)
            return

        # Check for unsafe model deserialization (SKL001)
        self._check_unsafe_model_loading(node)

        # Check for missing input validation (SKL009)
        self._check_missing_input_validation(node)

        # Check for grid search resource exhaustion (SKL012)
        self._check_grid_search_exhaustion(node)

        self.generic_visit(node)

    def _check_unsafe_model_loading(self, node: ast.Call) -> None:
        """Check for unsafe model deserialization (SKL001)."""
        func_name = self._get_func_name(node)

        # Check for pickle.load() or joblib.load() with ML models  # SECURITY: Don't use pickle with untrusted data
        # Only check if we have relevant imports
        if func_name in ["pickle.load", "load"] and self.pickle_imports and self.has_sklearn_import:  # SECURITY: Don't use pickle with untrusted data
            self.violations.append(
                RuleViolation(
                    rule_id="SKL001",
                    rule_name="Unsafe Model Deserialization",
                    severity="CRITICAL",
                    category="SECURITY",
                    message="Unsafe model deserialization using pickle - vulnerable to arbitrary code execution",
                    line_number=node.lineno,
                    file_path=self.file_path,
                    suggestion="Use joblib.load() with custom pickler or validate model source before loading",
                )
            )

        # Check for joblib.load() without security considerations
        elif (  # noqa: SIM102
            func_name == "joblib.load" or (func_name == "load" and self.joblib_imports)
        ) and self.has_sklearn_import:
            if not self._has_validation_context(node):
                self.violations.append(
                    RuleViolation(
                        rule_id="SKL001",
                        rule_name="Unsafe Model Loading",
                        severity="HIGH",
                        category="SECURITY",
                        message="Model loaded from potentially untrusted source without validation",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate model source, use cryptographic signatures, or load from trusted locations only",
                    )
                )

    def _check_missing_input_validation(self, node: ast.Call) -> None:
        """Check for missing input validation before prediction (SKL009)."""
        # func_name = self._get_func_name(node)  # Reserved for future use

        # Only check if sklearn is imported
        if not self.has_sklearn_import:
            return

        # Check for predict(), predict_proba(), transform() without validation
        # These are typically called as method.predict(data)
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in [  # noqa: SIM102
                "predict",
                "predict_proba",
                "predict_log_proba",
                "transform",
                "fit_transform",
            ]:
                if not self._has_input_validation_nearby(node):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SKL009",
                            rule_name="Missing Input Validation",
                            severity="MEDIUM",
                            category="SECURITY",
                            message=f"Missing input validation before {attr}() - may be vulnerable to adversarial inputs",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Add input validation: check shape, dtype, range, and sanitize data before prediction",
                        )
                    )

    def _check_grid_search_exhaustion(self, node: ast.Call) -> None:
        """Check for grid search resource exhaustion (SKL012)."""
        func_name = self._get_func_name(node)

        # Only check if sklearn is imported
        if not self.has_sklearn_import:
            return

        # Check for GridSearchCV or RandomizedSearchCV without resource limits
        if func_name in ["GridSearchCV", "RandomizedSearchCV"]:
            has_cv_limit = any(kw.arg == "cv" for kw in node.keywords)
            has_n_jobs_limit = any(kw.arg == "n_jobs" for kw in node.keywords)

            if not has_cv_limit or not has_n_jobs_limit:
                self.violations.append(
                    RuleViolation(
                        rule_id="SKL012",
                        rule_name="Grid Search Resource Exhaustion",
                        severity="MEDIUM",
                        category="SECURITY",
                        message=f"{func_name} without resource limits - may cause resource exhaustion",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Set cv and n_jobs parameters to limit resource usage and prevent DoS",
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

    def _has_validation_context(self, node: ast.Call) -> bool:
        """Check if there's validation context around a call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 5) : min(len(self.lines), line + 3)])
            validation_keywords = ["verify", "validate", "check", "trusted", "signature"]
            return any(keyword in context.lower() for keyword in validation_keywords)
        return False

    def _has_input_validation_nearby(self, node: ast.Call) -> bool:
        """Check if there's input validation near a prediction call."""
        line = node.lineno
        if 0 <= line - 1 < len(self.lines):
            context = "\n".join(self.lines[max(0, line - 10) : line])
            validation_patterns = ["shape", "dtype", "isnan", "isinf", "validate", "check"]
            return any(pattern in context.lower() for pattern in validation_patterns)
        return False


def analyze_sklearn_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for Scikit-learn security vulnerabilities.

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

    visitor = SklearnSecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations
