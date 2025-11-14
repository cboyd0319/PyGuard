"""
Django Framework Rules (DJ) - Django-specific best practices and security.

This module implements detection for Django-specific issues including:
- Security vulnerabilities in views and templates
- ORM anti-patterns and SQL injection risks
- Model design issues
- Settings configuration problems
- URL routing issues

References:
- Django security: https://docs.djangoproject.com/en/stable/topics/security/
- Ruff Django rules: https://docs.astral.sh/ruff/rules/#flake8-django-dj
"""

import ast
from pathlib import Path

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class DjangoVisitor(ast.NodeVisitor):
    """AST visitor for Django-specific issues."""

    def __init__(self, file_path: Path, code: str):
        # TODO: Add docstring
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []
        self.is_django_file = self._detect_django_imports(code)

    def _detect_django_imports(self, code: str) -> bool:
        """Check if file uses Django."""
        # String literal check for import detection, not SQL injection
        return "from django" in code or "import django" in code  # pyguard: disable=CWE-89

    def visit_Call(self, node: ast.Call) -> None:
        """Detect Django-specific call issues (DJ001-DJ013)."""
        if not self.is_django_file:
            self.generic_visit(node)
            return

        # DJ001: Django ORM .raw() SQL query - potential SQL injection
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "raw":  # noqa: SIM102
                # Check if SQL is using string formatting
                if len(node.args) > 0:
                    sql_arg = node.args[0]
                    if isinstance(sql_arg, ast.JoinedStr):  # f-string
                        self.violations.append(
                            RuleViolation(
                                rule_id="DJ001",
                                message="SQL injection risk in Django ORM .raw() - use parameterized queries",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

            # DJ006: Django model without __str__ method
            # This is checked in visit_ClassDef

            # DJ008: Model without Meta.ordering
            # This is checked in visit_ClassDef

            # DJ012: Model .objects.get() without exception handling
            if node.func.attr == "get" and isinstance(node.func.value, ast.Attribute):  # noqa: SIM102
                if node.func.value.attr == "objects":
                    # Check if wrapped in try-except
                    # This requires parent context, handled in checker
                    pass

        # DJ003: Django render() without csrf_token
        if isinstance(node.func, ast.Name) and node.func.id == "render":
            # Check if template context has csrf_token
            # This is complex and requires template analysis
            pass

        # DJ007: Django forms without clean methods
        # This is checked in visit_ClassDef

        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: PLR0912 - Complex Django model analysis requires many checks
        """Detect Django model and form issues (DJ006-DJ013)."""
        if not self.is_django_file:
            self.generic_visit(node)
            return

        # Check if this is a Django Model
        is_model = False
        is_form = False

        for base in node.bases:
            if isinstance(base, ast.Attribute):
                if base.attr in ("Model", "AbstractModel"):
                    is_model = True
                elif base.attr in ("Form", "ModelForm"):
                    is_form = True

        if is_model:
            # DJ006: Model without __str__ method
            has_str = any(
                isinstance(item, ast.FunctionDef) and item.name == "__str__" for item in node.body
            )
            if not has_str:
                self.violations.append(
                    RuleViolation(
                        rule_id="DJ006",
                        message="Django model should have __str__ method for better admin interface",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.STYLE,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

            # DJ008: Model without Meta.ordering
            has_meta = False
            has_ordering = False
            for item in node.body:
                if isinstance(item, ast.ClassDef) and item.name == "Meta":
                    has_meta = True
                    for meta_item in item.body:
                        if isinstance(meta_item, ast.Assign):
                            for target in meta_item.targets:
                                if isinstance(target, ast.Name) and target.id == "ordering":
                                    has_ordering = True

            if has_meta and not has_ordering:
                self.violations.append(
                    RuleViolation(
                        rule_id="DJ008",
                        message="Django model should specify Meta.ordering to avoid non-deterministic query results",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.CONVENTION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

        if is_form:
            # DJ007: Forms should have clean methods for validation
            clean_methods = [
                item.name
                for item in node.body
                if isinstance(item, ast.FunctionDef) and item.name.startswith("clean")
            ]

            # Check if form has fields but no clean methods
            has_fields = any(isinstance(item, ast.Assign) for item in node.body)

            if has_fields and not clean_methods:
                self.violations.append(
                    RuleViolation(
                        rule_id="DJ007",
                        message="Django form should have clean methods for validation",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.CONVENTION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.NONE,
                    )
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect Django settings issues (DJ010-DJ013)."""
        if not self.is_django_file:
            self.generic_visit(node)
            return

        # DJ013: Django settings - DEBUG = True in production
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id == "DEBUG":  # noqa: SIM102
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        self.violations.append(
                            RuleViolation(
                                rule_id="DJ013",
                                message="DEBUG = True should not be in production settings",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

                # DJ010: SECRET_KEY hardcoded
                if target.id == "SECRET_KEY":  # noqa: SIM102
                    if isinstance(node.value, ast.Constant):
                        self.violations.append(
                            RuleViolation(
                                rule_id="DJ010",
                                message="Django SECRET_KEY should not be hardcoded - use environment variables",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.CRITICAL,
                                category=RuleCategory.SECURITY,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

        self.generic_visit(node)


class DjangoRulesChecker:
    """Main checker for Django-specific rules."""

    def __init__(self):
        # TODO: Add docstring
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a Python file for Django-specific issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            # Only check files that appear to be Django-related
            if "django" not in code.lower():
                return []

            tree = ast.parse(code)
            visitor = DjangoVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []


# Define rules for registration
DJANGO_RULES = [
    Rule(
        rule_id="DJ001",
        name="django-raw-sql",
        description="SQL injection risk in Django ORM .raw()",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.HIGH,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use parameterized queries to prevent SQL injection",
    ),
    Rule(
        rule_id="DJ006",
        name="django-model-without-dunder-str",
        description="Django model without __str__ method",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Add __str__ method for better admin interface",
    ),
    Rule(
        rule_id="DJ007",
        name="django-form-without-clean",
        description="Django form without clean methods",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.NONE,
        message_template="Add clean methods for form validation",
    ),
    Rule(
        rule_id="DJ008",
        name="django-model-without-dunder-str",
        description="Django model without Meta.ordering",
        category=RuleCategory.CONVENTION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Specify Meta.ordering for deterministic query results",
    ),
    Rule(
        rule_id="DJ010",
        name="django-secret-key-hardcoded",
        description="Django SECRET_KEY hardcoded",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use environment variables for SECRET_KEY",
    ),
    Rule(
        rule_id="DJ012",
        name="django-untyped-object-get",
        description="Django .objects.get() without exception handling",
        category=RuleCategory.ERROR,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Wrap .objects.get() in try-except DoesNotExist",
    ),
    Rule(
        rule_id="DJ013",
        name="django-debug-true",
        description="DEBUG = True in settings",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Set DEBUG = False in production",
    ),
]
