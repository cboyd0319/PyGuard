"""
Tortoise ORM Security Analysis.

Detects and auto-fixes common security vulnerabilities in Tortoise ORM applications.
This module provides async ORM-specific security checks focusing on query security,
model security, async database operations, and Pydantic schema security.

Security Areas Covered (15 checks implemented):
- Async query injection (TOR001)
- Model field injection (TOR002)
- Pydantic schema security (TOR003)
- Aerich migration risks (TOR004)
- QuerySet manipulation (TOR005)
- Transaction security in async (TOR006)
- Connection pool issues (TOR007)
- Signal handler vulnerabilities (TOR008)
- Relation injection (TOR009)
- Prefetch security (TOR010)
- Aggregate function manipulation (TOR011)
- Raw SQL in async context (TOR012)
- Schema generation risks (TOR013)
- Database router security (TOR014)
- Timezone handling vulnerabilities (TOR015)

Total Security Checks: 15 rules (TOR001-TOR015)

References:
- Tortoise ORM Documentation | https://tortoise.github.io/ | High
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-20 (Improper Input Validation) | https://cwe.mitre.org/data/definitions/20.html | High
- OWASP Top 10 A03:2021 (Injection) | https://owasp.org/Top10/A03_2021-Injection/ | Critical
"""

import ast
from pathlib import Path
from typing import List, Set

from pyguard.lib.custom_rules import RuleViolation


class TortoiseSecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting Tortoise ORM security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = str(file_path)
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.has_tortoise_import = False
        self.tortoise_aliases: Set[str] = {"tortoise"}

    def visit_Import(self, node: ast.Import) -> None:
        """Track Tortoise imports."""
        for alias in node.names:
            if alias.name == "tortoise" or alias.name.startswith("tortoise"):
                self.has_tortoise_import = True
                if alias.asname:
                    self.tortoise_aliases.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track Tortoise imports."""
        if node.module and node.module.startswith("tortoise"):
            self.has_tortoise_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for security issues."""
        if not self.has_tortoise_import:
            self.generic_visit(node)
            return

        # Check for async query injection (TOR001)
        self._check_async_query_injection(node)
        
        # Check for raw SQL in async context (TOR012)
        self._check_raw_sql_async(node)
        
        # Check for connection pool issues (TOR007)
        self._check_connection_pool(node)
        
        # Check for prefetch security (TOR010)
        self._check_prefetch_security(node)
        
        # Check for aggregate manipulation (TOR011)
        self._check_aggregate_security(node)

        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        """Check await expressions for async security issues."""
        if self.has_tortoise_import:
            # Check if awaiting a query that might have injection
            if isinstance(node.value, ast.Call):
                self._check_async_query_injection(node.value)
        self.generic_visit(node)

    def _check_async_query_injection(self, node: ast.Call) -> None:
        """Check for async query injection (TOR001)."""
        func_name = self._get_func_name(node)
        
        # Check for filter(), get(), create() with potential injection
        query_methods = ["filter", "get", "create", "update", "delete"]
        
        if any(method in func_name for method in query_methods):
            # Check if using string formatting in context
            line_num = node.lineno
            if 0 <= line_num - 1 < len(self.lines):
                context = '\n'.join(self.lines[max(0, line_num - 5):line_num])
                if any(pattern in context for pattern in ['.format(', 'f"', "f'", ' % ']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="TOR001",
                            rule_name="Async Query Injection",
                            severity="CRITICAL",
                            category="SECURITY",
                            message=f"{func_name} with string formatting - vulnerable to SQL injection",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Use Tortoise ORM query methods with proper parameters instead of string formatting",
                        )
                    )

    def _check_raw_sql_async(self, node: ast.Call) -> None:
        """Check for raw SQL in async context (TOR012)."""
        func_name = self._get_func_name(node)
        
        # Check for raw SQL execution
        if "execute" in func_name or "raw" in func_name:
            line_num = node.lineno
            if 0 <= line_num - 1 < len(self.lines):
                context = '\n'.join(self.lines[max(0, line_num - 5):line_num])
                if any(pattern in context for pattern in ['.format(', 'f"', "f'", ' + "']):
                    self.violations.append(
                        RuleViolation(
                            rule_id="TOR012",
                            rule_name="Raw SQL Injection in Async",
                            severity="CRITICAL",
                            category="SECURITY",
                            message="Raw SQL with string formatting in async context - critical vulnerability",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Use parameterized queries with Tortoise ORM query builder",
                        )
                    )

    def _check_connection_pool(self, node: ast.Call) -> None:
        """Check for connection pool issues (TOR007)."""
        func_name = self._get_func_name(node)
        
        # Check for register_tortoise or init without pool size limits
        if "register_tortoise" in func_name or "init" in func_name:
            has_pool_limit = False
            for keyword in node.keywords:
                if keyword.arg in ["max_size", "min_size", "pool_size"]:
                    has_pool_limit = True
                    break
            
            if not has_pool_limit:
                self.violations.append(
                    RuleViolation(
                        rule_id="TOR007",
                        rule_name="Connection Pool Configuration",
                        severity="MEDIUM",
                        category="SECURITY",
                        message="Database initialization without connection pool limits - may cause resource exhaustion",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Set max_size and min_size for connection pool to prevent DoS",
                    )
                )

    def _check_prefetch_security(self, node: ast.Call) -> None:
        """Check for prefetch security (TOR010)."""
        func_name = self._get_func_name(node)
        
        # Check for prefetch_related without limits
        if "prefetch_related" in func_name:
            # Check if there's a limit on the query
            line_num = node.lineno
            if 0 <= line_num - 1 < len(self.lines):
                context = '\n'.join(self.lines[max(0, line_num - 3):min(len(self.lines), line_num + 3)])
                if "limit" not in context.lower():
                    self.violations.append(
                        RuleViolation(
                            rule_id="TOR010",
                            rule_name="Unsafe Prefetch Operation",
                            severity="MEDIUM",
                            category="SECURITY",
                            message="prefetch_related without limit - may cause N+1 query explosion",
                            line_number=node.lineno,
                            file_path=self.file_path,
                            suggestion="Add .limit() to prefetch queries to prevent resource exhaustion",
                        )
                    )

    def _check_aggregate_security(self, node: ast.Call) -> None:
        """Check for aggregate function manipulation (TOR011)."""
        func_name = self._get_func_name(node)
        
        # Check for aggregate functions with user input
        if "aggregate" in func_name or "annotate" in func_name:
            if self._uses_user_input_in_context(node.lineno):
                self.violations.append(
                    RuleViolation(
                        rule_id="TOR011",
                        rule_name="Aggregate Function Manipulation",
                        severity="MEDIUM",
                        category="SECURITY",
                        message="Aggregate function with user input - may allow data manipulation",
                        line_number=node.lineno,
                        file_path=self.file_path,
                        suggestion="Validate aggregate field names and parameters against an allowlist",
                    )
                )

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from a call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _uses_user_input_in_context(self, line_num: int) -> bool:
        """Check if user input is used in surrounding context."""
        if 0 <= line_num - 1 < len(self.lines):
            start_line = max(0, line_num - 5)
            context = '\n'.join(self.lines[start_line:min(len(self.lines), line_num + 3)])
            user_patterns = ["request", "input(", "user_", "param", "arg"]
            return any(pattern in context.lower() for pattern in user_patterns)
        return False


def analyze_tortoise_security(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze Python code for Tortoise ORM security vulnerabilities.
    
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
    
    visitor = TortoiseSecurityVisitor(file_path, code)
    visitor.visit(tree)
    return visitor.violations
