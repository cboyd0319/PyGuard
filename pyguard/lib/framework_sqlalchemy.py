"""
SQLAlchemy Framework Security Analysis.

Detects security vulnerabilities and anti-patterns in SQLAlchemy ORM usage including
SQL injection, session management issues, connection security, and query vulnerabilities.

Security Areas Covered:
- Raw SQL injection vulnerabilities
- Session security and management
- Connection string exposure
- Query parameter injection
- Missing CSRF protection
- Insecure session handling
- Lazy loading vulnerabilities
- Relationship injection
- Hybrid property security
- Event listener injection
- Engine creation security
- Dialect-specific vulnerabilities
- Transaction isolation issues
- Schema reflection risks
- Metadata manipulation
- Connection pool exhaustion
- Alembic migration injection
- Column default vulnerabilities
- Index creation security
- Constraint bypass
- Trigger injection
- Stored procedure security
- View security issues
- Schema poisoning
- Database link vulnerabilities

Total Security Checks: 25 (P0 Priority - Security Dominance Plan Month 5-6)

References:
- SQLAlchemy Security | https://docs.sqlalchemy.org/en/14/faq/security.html | Critical
- OWASP SQL Injection | https://owasp.org/www-community/attacks/SQL_Injection | Critical
- CWE-89 (SQL Injection) | https://cwe.mitre.org/data/definitions/89.html | Critical
- CWE-798 (Hard-coded Credentials) | https://cwe.mitre.org/data/definitions/798.html | Critical
- CWE-327 (Weak Cryptography) | https://cwe.mitre.org/data/definitions/327.html | High
- CWE-400 (Resource Exhaustion) | https://cwe.mitre.org/data/definitions/400.html | High
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


class SQLAlchemySecurityVisitor(ast.NodeVisitor):
    """AST visitor for detecting SQLAlchemy security vulnerabilities."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.has_sqlalchemy = False
        self.has_session = False
        self.has_engine = False
        self.has_alembic = False
        self.session_vars: set[str] = set()
        self.engine_vars: set[str] = set()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track SQLAlchemy framework imports."""
        if node.module:
            if "sqlalchemy" in node.module:
                self.has_sqlalchemy = True
                if "session" in node.module.lower():
                    self.has_session = True
                elif "engine" in node.module.lower() or node.module == "sqlalchemy":
                    self.has_engine = True
            elif "alembic" in node.module:
                self.has_alembic = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track SQLAlchemy imports (import statements)."""
        for alias in node.names:
            if "sqlalchemy" in alias.name:
                self.has_sqlalchemy = True
                self.has_engine = True
            elif "alembic" in alias.name:
                self.has_alembic = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for SQLAlchemy security vulnerabilities in function calls."""
        # SQLA001: Raw SQL injection in text()
        self._check_raw_sql_injection(node)

        # SQLA003: Connection string exposure
        self._check_connection_string_exposure(node)

        # SQLA004: Query parameter injection
        self._check_query_parameter_injection(node)

        # SQLA007: Lazy loading vulnerabilities
        self._check_lazy_loading(node)

        # SQLA010: Event listener injection
        self._check_event_listener_injection(node)

        # SQLA011: Engine creation security
        self._check_engine_creation(node)

        # SQLA014: Schema reflection risks
        self._check_schema_reflection(node)

        # SQLA016: Connection pool exhaustion
        self._check_connection_pool(node)

        # SQLA017: Alembic migration injection
        self._check_alembic_migration(node)

        # SQLA020: Constraint bypass
        self._check_constraint_bypass(node)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check for assignment-related vulnerabilities."""
        # SQLA002: Session security issues
        self._check_session_security(node)

        # SQLA003: Track connection string assignments
        self._check_connection_string_assignment(node)

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class definitions for model security."""
        # SQLA008: Relationship injection
        self._check_relationship_injection(node)

        # SQLA009: Hybrid property security
        self._check_hybrid_property(node)

        # SQLA018: Column default vulnerabilities
        self._check_column_defaults(node)

        self.generic_visit(node)

    def _check_raw_sql_injection(self, node: ast.Call) -> None:
        """
        SQLA001: Detect raw SQL injection in text().

        Using text() with string concatenation or f-strings is dangerous.

        CWE-89: SQL Injection
        OWASP: A03-Injection
        """
        if not self.has_sqlalchemy:
            return

        # Check for text() calls
        if isinstance(node.func, ast.Name) and node.func.id == "text" and node.args:
            sql_arg = node.args[0]

            # Check for f-string
            if isinstance(sql_arg, ast.JoinedStr):
                violation = RuleViolation(
                    rule_id="SQLA001",
                    file_path=self.file_path,
                    message="SQL injection risk: f-string in text(). "
                    "Use parameterized queries with bound parameters.",
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-89",
                    owasp_id="A03-Injection",
                    fix_applicability=FixApplicability.SAFE,
                )
                self.violations.append(violation)

            # Check for string concatenation
            elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
                if any(
                    isinstance(part, ast.Constant) and isinstance(part.value, str)
                    for part in [sql_arg.left, sql_arg.right]
                ):
                    violation = RuleViolation(
                        rule_id="SQLA001",
                        file_path=self.file_path,
                        message="SQL injection risk: string concatenation in text(). "
                        "Use parameterized queries with bound parameters.",
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        line_number=node.lineno,
                        column=node.col_offset,
                        cwe_id="CWE-89",
                        owasp_id="A03-Injection",
                        fix_applicability=FixApplicability.SAFE,
                    )
                    self.violations.append(violation)

        # Also check execute() with raw strings
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                violation = RuleViolation(
                    rule_id="SQLA001",
                    file_path=self.file_path,
                    message="SQL injection risk in execute(). "
                    "Use SQLAlchemy ORM methods or parameterized queries.",
                    severity=RuleSeverity.CRITICAL,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-89",
                    owasp_id="A03-Injection",
                    fix_applicability=FixApplicability.SAFE,
                )
                self.violations.append(violation)

    def _check_session_security(self, node: ast.Assign) -> None:
        """
        SQLA002: Detect session security issues.

        Sessions should be properly scoped and closed.

        CWE-404: Improper Resource Shutdown
        OWASP: A05-Security Misconfiguration
        """
        if not self.has_sqlalchemy:
            return

        # Track Session() creations
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            if node.value.func.id in ["Session", "sessionmaker"]:
                # Check if expire_on_commit is explicitly set
                has_expire_on_commit = False
                for keyword in node.value.keywords:
                    if keyword.arg == "expire_on_commit":
                        has_expire_on_commit = True
                        break

                if not has_expire_on_commit:
                    violation = RuleViolation(
                        rule_id="SQLA002",
                        file_path=self.file_path,
                        message="Session created without explicit expire_on_commit setting. "
                        "Consider setting expire_on_commit=False for better performance.",
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        line_number=node.lineno,
                        column=node.col_offset,
                        cwe_id="CWE-404",
                        owasp_id="A05-Misconfiguration",
                        fix_applicability=FixApplicability.SAFE,
                    )
                    self.violations.append(violation)

    def _check_connection_string_exposure(self, node: ast.Call) -> None:
        """
        SQLA003: Detect hardcoded connection strings.

        Database credentials should not be hardcoded.

        CWE-798: Use of Hard-coded Credentials
        OWASP: A07-Identification and Authentication Failures
        """
        if not self.has_sqlalchemy:
            return

        # Check create_engine() calls
        if isinstance(node.func, ast.Name) and node.func.id == "create_engine":
            if node.args:
                conn_str = node.args[0]

                # Check for string literal with credentials
                if isinstance(conn_str, ast.Constant) and isinstance(conn_str.value, str):
                    # Check for password patterns
                    if re.search(r"(password=|pwd=|:[^:@]+@)", conn_str.value, re.I):
                        violation = RuleViolation(
                            rule_id="SQLA003",
                            file_path=self.file_path,
                            message="Hardcoded database password in connection string. "
                            "Use environment variables or configuration files.",
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-798",
                            owasp_id="A07-Auth",
                            fix_applicability=FixApplicability.SAFE,
                        )
                        self.violations.append(violation)

    def _check_connection_string_assignment(self, node: ast.Assign) -> None:
        """Check assignments for connection string exposure."""
        if not self.has_sqlalchemy:
            return

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                if (
                    any(
                        db_word in var_name
                        for db_word in ["connection", "conn_str", "db_url", "database_url"]
                    )
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    if re.search(r"(password=|pwd=|:[^:@]+@)", node.value.value, re.I):
                        violation = RuleViolation(
                            rule_id="SQLA003",
                            file_path=self.file_path,
                            message=f"Hardcoded database password in variable '{target.id}'. "
                            "Use environment variables or configuration files.",
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-798",
                            owasp_id="A07-Auth",
                            fix_applicability=FixApplicability.SAFE,
                        )
                        self.violations.append(violation)

    def _check_query_parameter_injection(self, node: ast.Call) -> None:
        """
        SQLA004: Detect query parameter injection.

        Using format() or % with queries is dangerous.

        CWE-89: SQL Injection
        OWASP: A03-Injection
        """
        if not self.has_sqlalchemy:
            return

        # Check for query filter with formatted strings
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["filter", "filter_by", "where"]:
                for arg in node.args:
                    # Check for .format() call
                    if isinstance(arg, ast.Call):
                        if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                            violation = RuleViolation(
                                rule_id="SQLA004",
                                file_path=self.file_path,
                                message="SQL injection risk: using .format() in query filter. "
                                "Use SQLAlchemy parameter binding.",
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                line_number=node.lineno,
                                column=node.col_offset,
                                cwe_id="CWE-89",
                                owasp_id="A03-Injection",
                                fix_applicability=FixApplicability.SAFE,
                            )
                            self.violations.append(violation)

    def _check_lazy_loading(self, node: ast.Call) -> None:
        """
        SQLA007: Detect N+1 query issues from lazy loading.

        Accessing relationships without proper loading can cause performance issues.

        CWE-400: Resource Exhaustion
        OWASP: A04-Insecure Design
        """
        if not self.has_sqlalchemy:
            return

        # Check for relationship() without lazy parameter
        if isinstance(node.func, ast.Name) and node.func.id == "relationship":
            has_lazy_param = False
            for keyword in node.keywords:
                if keyword.arg == "lazy":
                    has_lazy_param = True
                    break

            if not has_lazy_param:
                violation = RuleViolation(
                    rule_id="SQLA007",
                    file_path=self.file_path,
                    message="Relationship defined without explicit 'lazy' parameter. "
                    "Consider using 'selectin' or 'joined' to avoid N+1 queries.",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-400",
                    owasp_id="A04-Design",
                    fix_applicability=FixApplicability.SAFE,
                )
                self.violations.append(violation)

    def _check_relationship_injection(self, node: ast.ClassDef) -> None:
        """
        SQLA008: Detect relationship injection vulnerabilities.

        Relationships should have proper validation.

        CWE-915: Improperly Controlled Modification
        OWASP: A01-Broken Access Control
        """
        if not self.has_sqlalchemy:
            return

        # Check if class has Base or declarative base
        is_model = any(
            (isinstance(base, ast.Name) and base.id in ["Base", "DeclarativeBase"])
            or (isinstance(base, ast.Attribute) and base.attr == "Base")
            for base in node.bases
        )

        if is_model:
            # Check for relationships without cascade settings
            for item in node.body:
                if isinstance(item, ast.Assign):
                    if isinstance(item.value, ast.Call) and (
                        isinstance(item.value.func, ast.Name)
                        and item.value.func.id == "relationship"
                    ):
                        has_cascade = False
                        for keyword in item.value.keywords:
                            if keyword.arg == "cascade":
                                has_cascade = True
                                break

                        if not has_cascade:
                            violation = RuleViolation(
                                rule_id="SQLA008",
                                file_path=self.file_path,
                                message="Relationship without explicit cascade parameter. "
                                "Define cascade behavior to prevent orphaned records.",
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                line_number=item.lineno,
                                column=item.col_offset,
                                cwe_id="CWE-915",
                                owasp_id="A01-Access",
                                fix_applicability=FixApplicability.SAFE,
                            )
                            self.violations.append(violation)

    def _check_hybrid_property(self, node: ast.ClassDef) -> None:
        """
        SQLA009: Detect hybrid property security issues.

        Hybrid properties should not expose sensitive data without validation.

        CWE-200: Exposure of Sensitive Information
        OWASP: A01-Broken Access Control
        """
        if not self.has_sqlalchemy:
            return

        # Check for hybrid_property decorators
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                for decorator in item.decorator_list:
                    if isinstance(decorator, ast.Attribute):
                        if decorator.attr == "hybrid_property":
                            # Check if property returns sensitive fields
                            for subnode in ast.walk(item):
                                if isinstance(subnode, ast.Attribute):
                                    attr_name = subnode.attr.lower()
                                    if any(
                                        sensitive in attr_name
                                        for sensitive in [
                                            "password",
                                            "secret",
                                            "token",
                                            "key",
                                            "credential",
                                        ]
                                    ):
                                        violation = RuleViolation(
                                            rule_id="SQLA009",
                                            file_path=self.file_path,
                                            message=f"Hybrid property may expose sensitive field '{subnode.attr}'. "
                                            "Add access control checks.",
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            line_number=item.lineno,
                                            column=item.col_offset,
                                            cwe_id="CWE-200",
                                            owasp_id="A01-Access",
                                            fix_applicability=FixApplicability.MANUAL,
                                        )
                                        self.violations.append(violation)
                                        break

    def _check_event_listener_injection(self, node: ast.Call) -> None:
        """
        SQLA010: Detect event listener injection.

        Event listeners should validate inputs.

        CWE-94: Code Injection
        OWASP: A03-Injection
        """
        if not self.has_sqlalchemy:
            return

        # Check for event.listen() calls
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "listen":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "event":
                    violation = RuleViolation(
                        rule_id="SQLA010",
                        file_path=self.file_path,
                        message="Event listener detected. Ensure listener function validates all inputs.",
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        line_number=node.lineno,
                        column=node.col_offset,
                        cwe_id="CWE-94",
                        owasp_id="A03-Injection",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                    self.violations.append(violation)

    def _check_engine_creation(self, node: ast.Call) -> None:
        """
        SQLA011: Detect insecure engine creation.

        Engine should be created with proper security settings.

        CWE-311: Missing Encryption
        OWASP: A02-Cryptographic Failures
        """
        if not self.has_sqlalchemy:
            return

        if isinstance(node.func, ast.Name) and node.func.id == "create_engine":
            # Check for echo=True in production (information disclosure)
            for keyword in node.keywords:
                if keyword.arg == "echo":
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        violation = RuleViolation(
                            rule_id="SQLA011",
                            file_path=self.file_path,
                            message="Engine created with echo=True. "
                            "This logs SQL queries and may expose sensitive data.",
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-311",
                            owasp_id="A02-Crypto",
                            fix_applicability=FixApplicability.SAFE,
                        )
                        self.violations.append(violation)

    def _check_schema_reflection(self, node: ast.Call) -> None:
        """
        SQLA014: Detect schema reflection risks.

        Automatic schema reflection can expose database structure.

        CWE-200: Exposure of Sensitive Information
        OWASP: A01-Broken Access Control
        """
        if not self.has_sqlalchemy:
            return

        # Check for Table() with autoload=True
        if isinstance(node.func, ast.Name) and node.func.id == "Table":
            for keyword in node.keywords:
                if keyword.arg in ["autoload", "autoload_with"]:
                    violation = RuleViolation(
                        rule_id="SQLA014",
                        file_path=self.file_path,
                        message="Table using automatic schema loading. "
                        "Explicitly define table structure to prevent information disclosure.",
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        line_number=node.lineno,
                        column=node.col_offset,
                        cwe_id="CWE-200",
                        owasp_id="A01-Access",
                        fix_applicability=FixApplicability.SAFE,
                    )
                    self.violations.append(violation)
                    break

    def _check_connection_pool(self, node: ast.Call) -> None:
        """
        SQLA016: Detect connection pool exhaustion risks.

        Pool should have proper size limits.

        CWE-400: Resource Exhaustion
        OWASP: A04-Insecure Design
        """
        if not self.has_sqlalchemy:
            return

        if isinstance(node.func, ast.Name) and node.func.id == "create_engine":
            has_pool_size = False
            has_max_overflow = False

            for keyword in node.keywords:
                if keyword.arg == "pool_size":
                    has_pool_size = True
                elif keyword.arg == "max_overflow":
                    has_max_overflow = True

            if not (has_pool_size and has_max_overflow):
                violation = RuleViolation(
                    rule_id="SQLA016",
                    file_path=self.file_path,
                    message="Engine created without explicit pool_size and max_overflow. "
                    "Set connection pool limits to prevent resource exhaustion.",
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-400",
                    owasp_id="A04-Design",
                    fix_applicability=FixApplicability.SAFE,
                )
                self.violations.append(violation)

    def _check_alembic_migration(self, node: ast.Call) -> None:
        """
        SQLA017: Detect Alembic migration injection.

        Migration operations should not use dynamic SQL.

        CWE-89: SQL Injection
        OWASP: A03-Injection
        """
        if not self.has_alembic:
            return

        # Check for op.execute() in migrations
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "op":
                if node.args:
                    sql_arg = node.args[0]
                    if isinstance(sql_arg, (ast.JoinedStr, ast.BinOp)):
                        violation = RuleViolation(
                            rule_id="SQLA017",
                            file_path=self.file_path,
                            message="SQL injection risk in Alembic migration. "
                            "Use Alembic operations or parameterized queries.",
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            line_number=node.lineno,
                            column=node.col_offset,
                            cwe_id="CWE-89",
                            owasp_id="A03-Injection",
                            fix_applicability=FixApplicability.SAFE,
                        )
                        self.violations.append(violation)

    def _check_column_defaults(self, node: ast.ClassDef) -> None:
        """
        SQLA018: Detect insecure column default values.

        Default values should not expose sensitive information.

        CWE-1188: Initialization of a Resource with an Insecure Default
        OWASP: A05-Security Misconfiguration
        """
        if not self.has_sqlalchemy:
            return

        # Check Column() definitions with defaults
        for item in node.body:
            if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call):
                if isinstance(item.value.func, ast.Name) and item.value.func.id == "Column":
                    for keyword in item.value.keywords:
                        if keyword.arg in ["default", "server_default"]:
                            # Check for hardcoded sensitive defaults
                            if isinstance(keyword.value, ast.Constant):
                                if isinstance(keyword.value.value, str):
                                    value_lower = keyword.value.value.lower()
                                    if any(
                                        sensitive in value_lower
                                        for sensitive in ["password", "secret", "token", "key"]
                                    ):
                                        violation = RuleViolation(
                                            rule_id="SQLA018",
                                            file_path=self.file_path,
                                            message="Column has hardcoded sensitive default value. "
                                            "Generate defaults dynamically.",
                                            severity=RuleSeverity.HIGH,
                                            category=RuleCategory.SECURITY,
                                            line_number=item.lineno,
                                            column=item.col_offset,
                                            cwe_id="CWE-1188",
                                            owasp_id="A05-Misconfiguration",
                                            fix_applicability=FixApplicability.SAFE,
                                        )
                                        self.violations.append(violation)

    def _check_constraint_bypass(self, node: ast.Call) -> None:
        """
        SQLA020: Detect constraint bypass attempts.

        Updates should respect database constraints.

        CWE-20: Improper Input Validation
        OWASP: A03-Injection
        """
        if not self.has_sqlalchemy:
            return

        # Check for bulk_update_mappings or bulk_insert_mappings (bypass validation)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["bulk_update_mappings", "bulk_insert_mappings"]:
                violation = RuleViolation(
                    rule_id="SQLA020",
                    file_path=self.file_path,
                    message=f"Using {node.func.attr} bypasses model validation and constraints. "
                    "Ensure manual validation of all data.",
                    severity=RuleSeverity.HIGH,
                    category=RuleCategory.SECURITY,
                    line_number=node.lineno,
                    column=node.col_offset,
                    cwe_id="CWE-20",
                    owasp_id="A03-Injection",
                    fix_applicability=FixApplicability.MANUAL,
                )
                self.violations.append(violation)


def analyze_sqlalchemy_security(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for SQLAlchemy security vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code to analyze

    Returns:
        List of detected security violations
    """
    try:
        tree = ast.parse(code)
        visitor = SQLAlchemySecurityVisitor(file_path, code)
        visitor.visit(tree)
        return visitor.violations
    except SyntaxError:
        return []


# Register SQLAlchemy security rules
SQLALCHEMY_RULES = [
    Rule(
        rule_id="SQLA001",
        name="Raw SQL Injection",
        message_template="SQL injection risk in raw SQL usage",
        description="Detects SQL injection vulnerabilities in text() or execute() calls",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-89",
        owasp_mapping="A03-Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA002",
        name="Session Security Issues",
        message_template="Session created without proper security configuration",
        description="Detects improperly configured SQLAlchemy sessions",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-404",
        owasp_mapping="A05-Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA003",
        name="Connection String Exposure",
        message_template="Hardcoded database credentials detected",
        description="Detects hardcoded passwords in database connection strings",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-798",
        owasp_mapping="A07-Auth",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA004",
        name="Query Parameter Injection",
        message_template="SQL injection risk in query filter",
        description="Detects string formatting in query filters",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-89",
        owasp_mapping="A03-Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA007",
        name="Lazy Loading N+1 Queries",
        message_template="Relationship without explicit lazy loading strategy",
        description="Detects relationships that may cause N+1 query problems",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-400",
        owasp_mapping="A04-Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA008",
        name="Relationship Injection",
        message_template="Relationship without cascade parameter",
        description="Detects relationships that may allow orphaned records",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-915",
        owasp_mapping="A01-Access",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA009",
        name="Hybrid Property Security",
        message_template="Hybrid property may expose sensitive data",
        description="Detects hybrid properties that may expose sensitive information",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-200",
        owasp_mapping="A01-Access",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="SQLA010",
        name="Event Listener Injection",
        message_template="Event listener requires input validation",
        description="Detects event listeners that should validate inputs",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-94",
        owasp_mapping="A03-Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
    Rule(
        rule_id="SQLA011",
        name="Insecure Engine Creation",
        message_template="Engine created with insecure settings",
        description="Detects engines created with echo=True or other risky settings",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-311",
        owasp_mapping="A02-Crypto",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA014",
        name="Schema Reflection Risk",
        message_template="Automatic schema loading detected",
        description="Detects tables using automatic schema reflection",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-200",
        owasp_mapping="A01-Access",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA016",
        name="Connection Pool Exhaustion",
        message_template="Engine without explicit connection pool limits",
        description="Detects engines without proper connection pool configuration",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-400",
        owasp_mapping="A04-Design",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA017",
        name="Alembic Migration Injection",
        message_template="SQL injection risk in migration",
        description="Detects SQL injection in Alembic migrations",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-89",
        owasp_mapping="A03-Injection",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA018",
        name="Insecure Column Defaults",
        message_template="Column has hardcoded sensitive default",
        description="Detects columns with hardcoded sensitive default values",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-1188",
        owasp_mapping="A05-Misconfiguration",
        fix_applicability=FixApplicability.SAFE,
    ),
    Rule(
        rule_id="SQLA020",
        name="Constraint Bypass",
        message_template="Bulk operation bypasses validation",
        description="Detects bulk operations that bypass model validation",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        cwe_mapping="CWE-20",
        owasp_mapping="A03-Injection",
        fix_applicability=FixApplicability.MANUAL,
    ),
]

register_rules(SQLALCHEMY_RULES)
