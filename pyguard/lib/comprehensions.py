"""
Comprehension Pattern Analysis Module

Implements Ruff C4 rules for detecting opportunities to use comprehensions.
"""

import ast
from pathlib import Path

from .rule_engine import FixApplicability, Rule, RuleCategory, RuleSeverity, RuleViolation


class ComprehensionVisitor(ast.NodeVisitor):
    """AST visitor for detecting comprehension opportunities."""

    def __init__(self, file_path: Path = Path("<string>")):
        self.violations: list[RuleViolation] = []
        self.file_path = file_path

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to detect comprehension opportunities."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Handle cases where we have exactly 1 argument
            if len(node.args) == 1:
                arg = node.args[0]

                # Check for different patterns based on func_name and arg type
                if func_name == "list":
                    # C400: Unnecessary generator (use list comprehension)
                    if isinstance(arg, ast.GeneratorExp):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C400",
                                message="Unnecessary generator - use list comprehension instead",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace list(generator) with [comprehension]",
                            )
                        )
                    # C410: Unnecessary list passed to list()
                    elif isinstance(arg, ast.List):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C410",
                                message="Unnecessary list passed to list()",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                fix_suggestion="Remove redundant list() call",
                                file_path=self.file_path,
                            )
                        )
                    # C411: Unnecessary list call around sorted()
                    elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        if arg.func.id == "sorted":
                            self.violations.append(
                                RuleViolation(
                                    rule_id="C411",
                                    message="Unnecessary list() around sorted()",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.REFACTOR,
                                    fix_suggestion="sorted() already returns a list",
                                    file_path=self.file_path,
                                )
                            )
                    # C416: Unnecessary list comprehension
                    if isinstance(arg, (ast.ListComp, ast.SetComp)):
                        # Check if it's just iterating without transformation
                        comp = arg
                        if len(comp.generators) == 1:
                            gen = comp.generators[0]
                            if isinstance(comp.elt, ast.Name) and isinstance(gen.target, ast.Name):
                                if comp.elt.id == gen.target.id and not gen.ifs:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="C416",
                                            message="Unnecessary comprehension - use constructor directly",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            severity=RuleSeverity.LOW,
                                            category=RuleCategory.REFACTOR,
                                            file_path=self.file_path,
                                            fix_suggestion=f"Replace {func_name}([x for x in ...]) with {func_name}(...)",
                                        )
                                    )

                elif func_name == "set":
                    # C401: Unnecessary generator (use set comprehension)
                    if isinstance(arg, ast.GeneratorExp):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C401",
                                message="Unnecessary generator - use set comprehension instead",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace set(generator) with {comprehension}",
                            )
                        )
                    # C403: Unnecessary list comprehension (use set comprehension)
                    elif isinstance(arg, ast.ListComp):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C403",
                                message="Unnecessary list comprehension - use set comprehension",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace set([...]) with {...}",
                            )
                        )
                    # C405: Unnecessary list literal (use set literal)
                    elif isinstance(arg, ast.List):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C405",
                                message="Unnecessary list literal - use set literal",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace set([...]) with {...}",
                            )
                        )
                    # C416: Unnecessary set comprehension
                    if isinstance(arg, (ast.ListComp, ast.SetComp)):
                        # Check if it's just iterating without transformation
                        comp = arg
                        if len(comp.generators) == 1:
                            gen = comp.generators[0]
                            if isinstance(comp.elt, ast.Name) and isinstance(gen.target, ast.Name):
                                if comp.elt.id == gen.target.id and not gen.ifs:
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="C416",
                                            message="Unnecessary comprehension - use constructor directly",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            severity=RuleSeverity.LOW,
                                            category=RuleCategory.REFACTOR,
                                            file_path=self.file_path,
                                            fix_suggestion=f"Replace {func_name}({{x for x in ...}}) with {func_name}(...)",
                                        )
                                    )

                elif func_name == "dict":
                    # C402: Unnecessary generator (use dict comprehension)
                    if isinstance(arg, ast.GeneratorExp):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C402",
                                message="Unnecessary generator - use dict comprehension instead",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace dict(generator) with {k: v for ...}",
                            )
                        )
                    # C404: Unnecessary list comprehension (use dict comprehension)
                    elif isinstance(arg, ast.ListComp):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C404",
                                message="Unnecessary list comprehension - use dict comprehension",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace dict([...]) with {k: v for ...}",
                            )
                        )
                    # C406: Unnecessary list literal (use dict literal)
                    elif isinstance(arg, ast.List):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C406",
                                message="Unnecessary list literal - use dict literal",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                file_path=self.file_path,
                                fix_suggestion="Replace dict([...]) with {...}",
                            )
                        )

                elif func_name == "tuple":
                    # C409: Unnecessary list passed to tuple()
                    if isinstance(arg, ast.List):
                        self.violations.append(
                            RuleViolation(
                                rule_id="C409",
                                message="Unnecessary list passed to tuple()",
                                line_number=node.lineno,
                                column=node.col_offset,
                                severity=RuleSeverity.LOW,
                                category=RuleCategory.REFACTOR,
                                fix_suggestion="Replace tuple([...]) with (...)",
                                file_path=self.file_path,
                            )
                        )

                elif func_name == "sorted":
                    # C413: Unnecessary list/reversed call around sorted()
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        if arg.func.id in ("reversed", "list"):
                            self.violations.append(
                                RuleViolation(
                                    rule_id="C413",
                                    message=f"Unnecessary {arg.func.id}() around sorted()",
                                    line_number=node.lineno,
                                    column=node.col_offset,
                                    severity=RuleSeverity.LOW,
                                    category=RuleCategory.REFACTOR,
                                    fix_suggestion="Use reverse=True parameter in sorted()",
                                    file_path=self.file_path,
                                )
                            )

                # C414: Unnecessary list/reversed/sorted call inside set/sorted/list/tuple
                if func_name in ("set", "sorted", "list", "tuple"):
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        inner_func = arg.func.id
                        # Avoid duplicate C411 (list(sorted())) and C413 (sorted(list/reversed()))
                        if inner_func in ("list", "reversed", "sorted", "tuple"):
                            if not (func_name == "list" and inner_func == "sorted"):  # Skip C411
                                if not (
                                    func_name == "sorted" and inner_func in ("list", "reversed")
                                ):  # Skip C413
                                    self.violations.append(
                                        RuleViolation(
                                            rule_id="C414",
                                            message=f"Unnecessary {inner_func}() call inside {func_name}()",
                                            line_number=node.lineno,
                                            column=node.col_offset,
                                            severity=RuleSeverity.LOW,
                                            category=RuleCategory.REFACTOR,
                                            fix_suggestion=f"Remove redundant {inner_func}() call",
                                            file_path=self.file_path,
                                        )
                                    )

            # C408: Unnecessary dict/list/tuple call (no arguments)
            elif func_name in ("dict", "list", "tuple") and not node.args and not node.keywords:
                suggestion = {
                    "dict": "{}",
                    "list": "[]",
                    "tuple": "()",
                }[func_name]
                self.violations.append(
                    RuleViolation(
                        rule_id="C408",
                        message=f"Unnecessary {func_name}() call - use literal",
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.REFACTOR,
                        fix_suggestion=f"Replace {func_name}() with {suggestion}",
                        file_path=self.file_path,
                    )
                )

        self.generic_visit(node)


class ComprehensionChecker:
    """Main checker for comprehension opportunities."""

    def __init__(self):
        self.rules = self._create_rules()

    def _create_rules(self) -> list[Rule]:
        """Create comprehension rules."""
        return [
            Rule(
                rule_id="C400",
                name="unnecessary-generator-list",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary generator - use list comprehension",
                description="list(generator) can be replaced with [comprehension]",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C401",
                name="unnecessary-generator-set",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary generator - use set comprehension",
                description="set(generator) can be replaced with {comprehension}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C402",
                name="unnecessary-generator-dict",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary generator - use dict comprehension",
                description="dict(generator) can be replaced with {k: v for ...}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C403",
                name="unnecessary-list-comprehension-set",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list comprehension - use set comprehension",
                description="set([...]) can be replaced with {...}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C404",
                name="unnecessary-list-comprehension-dict",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list comprehension - use dict comprehension",
                description="dict([...]) can be replaced with {k: v for ...}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C405",
                name="unnecessary-literal-set",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list literal - use set literal",
                description="set([...]) can be replaced with {...}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C406",
                name="unnecessary-literal-dict",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list literal - use dict literal",
                description="dict([...]) can be replaced with {...}",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C408",
                name="unnecessary-collection-call",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary collection call - use literal",
                description="Use {} instead of dict(), [] instead of list(), () instead of tuple()",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C409",
                name="unnecessary-literal-within-tuple-call",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list passed to tuple()",
                description="tuple([...]) can be replaced with (...)",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C410",
                name="unnecessary-literal-within-list-call",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list passed to list()",
                description="list([...]) is redundant",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C411",
                name="unnecessary-list-call",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary list() around sorted()",
                description="sorted() already returns a list",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C413",
                name="unnecessary-call-around-sorted",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary call around sorted()",
                description="Use reverse=True parameter instead",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C414",
                name="unnecessary-double-cast-or-process",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary inner call to collection constructor",
                description="Remove redundant nested collection calls",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
            Rule(
                rule_id="C416",
                name="unnecessary-comprehension",
                category=RuleCategory.REFACTOR,
                severity=RuleSeverity.LOW,
                message_template="Unnecessary comprehension",
                description="Use constructor directly when no transformation is needed",
                fix_applicability=FixApplicability.AUTOMATIC,
            ),
        ]

    def check_code(self, code: str, filename: str = "<string>") -> list[RuleViolation]:
        """
        Check code for comprehension opportunities.

        Args:
            code: Python source code to analyze
            filename: Name of the file being analyzed

        Returns:
            List of RuleViolation objects
        """
        try:
            tree = ast.parse(code)
            visitor = ComprehensionVisitor(file_path=Path(filename))
            visitor.visit(tree)
            return visitor.violations
        except SyntaxError:
            return []

    def get_rules(self) -> list[Rule]:
        """Get all rules defined by this checker."""
        return self.rules
