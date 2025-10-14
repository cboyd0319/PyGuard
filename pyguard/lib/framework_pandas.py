"""
Pandas Framework Rules (PD) - pandas-specific best practices and anti-patterns.

This module implements detection for pandas-specific issues including:
- DataFrame anti-patterns
- Performance issues
- API deprecations
- Vectorization opportunities
- Index usage

References:
- pandas documentation: https://pandas.pydata.org/docs/
- Ruff pandas rules: https://docs.astral.sh/ruff/rules/#pandas-vet-pd
"""

import ast
from pathlib import Path
from typing import List

from pyguard.lib.core import PyGuardLogger
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
)


class PandasVisitor(ast.NodeVisitor):
    """AST visitor for pandas-specific issues."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.is_pandas_file = self._detect_pandas(code)

    def _detect_pandas(self, code: str) -> bool:
        """Check if file uses pandas."""
        return 'import pandas' in code or 'from pandas' in code

    def visit_Call(self, node: ast.Call) -> None:
        """Detect pandas call issues (PD001-PD015)."""
        if not self.is_pandas_file:
            self.generic_visit(node)
            return

        # PD002: inplace=True usage
        for keyword in node.keywords:
            if keyword.arg == 'inplace':
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.violations.append(
                        RuleViolation(
                            rule_id="PD002",
                            message="Avoid inplace=True - use assignment instead for clarity",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.STYLE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

        # PD003: Use of deprecated pandas methods
        if isinstance(node.func, ast.Attribute):
            deprecated_methods = {
                'append': 'Use pd.concat() instead',
                'ix': 'Use .loc[] or .iloc[] instead',
            }

            if node.func.attr in deprecated_methods:
                self.violations.append(
                    RuleViolation(
                        rule_id="PD003",
                        message=f"Deprecated pandas method: {node.func.attr}. {deprecated_methods[node.func.attr]}",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SUGGESTED,
                    )
                )

            # PD008: Use .loc for assignment
            # This is detected in visit_Assign

            # PD010: Use .to_numpy() instead of .values
            if node.func.attr == 'values':
                self.violations.append(
                    RuleViolation(
                        rule_id="PD010",
                        message="Use .to_numpy() instead of .values for better clarity",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.MODERNIZATION,
                        file_path=self.file_path,
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

            # PD011: Use .to_numpy() instead of np.asarray() on DataFrame/Series
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'np':
                if node.func.attr in ('asarray', 'array'):
                    if len(node.args) > 0:
                        self.violations.append(
                            RuleViolation(
                                rule_id="PD011",
                                message="Use .to_numpy() instead of np.asarray() on pandas objects",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.STYLE,
                                file_path=self.file_path,
                                fix_applicability=FixApplicability.SUGGESTED,
                            )
                        )

            # PD013: Use .melt() instead of .stack()
            if node.func.attr == 'stack':
                # Context-dependent, but generally melt is preferred
                pass

        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Detect iteration anti-patterns (PD007-PD009)."""
        if not self.is_pandas_file:
            self.generic_visit(node)
            return

        # PD007: Iterating over DataFrame with .iterrows()
        if isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Attribute):
                if node.iter.func.attr == 'iterrows':
                    self.violations.append(
                        RuleViolation(
                            rule_id="PD007",
                            message="Avoid .iterrows() - use vectorized operations or .itertuples() instead",
                            line_number=node.lineno,
                            column=node.col_offset,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.PERFORMANCE,
                            file_path=self.file_path,
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

                # PD009: Using .apply() when a vectorized alternative exists
                elif node.iter.func.attr == 'apply':
                    # This requires semantic analysis to determine if vectorization is possible
                    pass

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect indexing issues (PD008-PD009, PD012)."""
        if not self.is_pandas_file:
            self.generic_visit(node)
            return

        # PD008: Use .loc or .iloc for indexing, not chained indexing
        # Check for chained indexing: df[...][...]
        if isinstance(node.value, ast.Subscript):
            self.violations.append(
                RuleViolation(
                    rule_id="PD008",
                    message="Avoid chained indexing - use .loc[] or .iloc[] instead",
                    line_number=node.lineno,
                    column=node.col_offset,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.WARNING,
                    file_path=self.file_path,
                    fix_applicability=FixApplicability.SUGGESTED,
                )
            )

        self.generic_visit(node)


class PandasRulesChecker:
    """Main checker for pandas-specific rules."""

    def __init__(self):
        self.logger = PyGuardLogger()

    def check_file(self, file_path: Path) -> List[RuleViolation]:
        """
        Check a Python file for pandas-specific issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            # Only check files that use pandas
            if 'pandas' not in code and 'pd.' not in code:
                return []

            tree = ast.parse(code)
            visitor = PandasVisitor(file_path, code)
            visitor.visit(tree)

            return visitor.violations

        except SyntaxError as e:
            self.logger.warning(f"Syntax error in file: {e}", file_path=str(file_path))
            return []
        except Exception as e:
            self.logger.error(f"Error checking file: {e}", file_path=str(file_path))
            return []


# Define rules for registration
PANDAS_RULES = [
    Rule(
        rule_id="PD002",
        name="pandas-use-of-inplace",
        description="Avoid inplace=True for clarity",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use assignment instead of inplace=True",
    ),
    Rule(
        rule_id="PD003",
        name="pandas-use-of-deprecated-method",
        description="Use of deprecated pandas method",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Update to non-deprecated alternative",
    ),
    Rule(
        rule_id="PD007",
        name="pandas-use-of-iterrows",
        description="Avoid .iterrows() - use vectorization",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use vectorized operations or .itertuples()",
    ),
    Rule(
        rule_id="PD008",
        name="pandas-use-of-chained-indexing",
        description="Avoid chained indexing",
        category=RuleCategory.WARNING,
        severity=RuleSeverity.MEDIUM,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use .loc[] or .iloc[] instead",
    ),
    Rule(
        rule_id="PD010",
        name="pandas-use-of-dot-values",
        description="Use .to_numpy() instead of .values",
        category=RuleCategory.MODERNIZATION,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SAFE,
        message_template="Replace .values with .to_numpy()",
    ),
    Rule(
        rule_id="PD011",
        name="pandas-use-of-dot-asarray",
        description="Use .to_numpy() instead of np.asarray()",
        category=RuleCategory.STYLE,
        severity=RuleSeverity.LOW,
        fix_applicability=FixApplicability.SUGGESTED,
        message_template="Use .to_numpy() method",
    ),
]
