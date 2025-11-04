"""
Example PyGuard Plugin: Company Standards

This plugin demonstrates how to create custom rules for company-specific
coding standards and best practices.
"""

import ast
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata
from pyguard.lib.custom_rules import CustomRuleEngine


class CompanyStandardsPlugin(PluginInterface):
    """
    Company-specific coding standards plugin.

    Enforces company coding guidelines and best practices.
    """

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="Company Standards Plugin",
            version="1.0.0",
            author="Your Company Security Team",
            description="Enforces company-specific coding standards and security policies",
            plugin_id="company_standards",
        )

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """Register company-specific rules."""

        # Rule 1: Detect missing company copyright header
        # Note: This is a simple example. For real use, check first 10 lines of file
        # and use AST-based check for better accuracy
        engine.add_regex_rule(
            rule_id="COMPANY_001",
            name="Copyright Header Check",
            pattern=r"#\s*Copyright[^\r\n]*Your Company",
            severity="LOW",
            category="Company Standards",
            description="Verify file has company copyright header in first few lines",
            suggestion="Add copyright header: # Copyright (c) 2024 Your Company. All rights reserved.",
        )

        # Rule 2: Detect usage of deprecated internal APIs
        engine.add_regex_rule(
            rule_id="COMPANY_002",
            name="Deprecated Internal API",
            pattern=r"\b(old_api|legacy_module|deprecated_function)\b",
            severity="MEDIUM",
            category="Company Standards",
            description="Usage of deprecated internal API detected",
            suggestion="Migrate to the new API as documented in the migration guide",
        )

        # Rule 3: Detect simple (non-structured) logging
        # This detects logger calls without structured data (no f-strings, no extra=)
        engine.add_regex_rule(
            rule_id="COMPANY_003",
            name="Non-Structured Logging",
            pattern=r'logger\.(info|debug|warning|error)\(["\'][^"\']*["\']\s*\)',
            severity="LOW",
            category="Company Standards",
            description="Logging statement uses simple strings instead of structured logging",
            suggestion="Use structured logging: logger.info('message', extra={'key': 'value'})",
        )

        # Rule 4: AST-based check for missing docstrings on public functions
        def check_missing_docstrings(tree: ast.AST) -> list[int]:
            """Check for public functions without docstrings."""
            lines = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Check if function is public (doesn't start with _)
                    if not node.name.startswith("_"):
                        # Check if it has a docstring
                        has_docstring = (
                            len(node.body) > 0
                            and isinstance(node.body[0], ast.Expr)
                            and isinstance(node.body[0].value, ast.Constant)
                            and isinstance(node.body[0].value.value, str)
                        )
                        if not has_docstring:
                            lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="COMPANY_004",
            name="Missing Function Docstring",
            checker=check_missing_docstrings,
            severity="LOW",
            category="Company Standards",
            description="Public function is missing a docstring",
            suggestion="Add a docstring describing the function's purpose, parameters, and return value",
        )

        # Rule 5: Check for functions that are too long
        def check_function_length(tree: ast.AST) -> list[int]:
            """Check for functions exceeding company length limit."""
            lines = []
            max_lines = 50  # Company standard
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.end_lineno and node.lineno:
                        func_length = node.end_lineno - node.lineno
                        if func_length > max_lines:
                            lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="COMPANY_005",
            name="Function Too Long",
            checker=check_function_length,
            severity="LOW",
            category="Company Standards",
            description=f"Function exceeds company standard of 50 lines",
            suggestion="Consider breaking this function into smaller, more focused functions",
        )

        # Rule 6: Detect hardcoded environment-specific values
        engine.add_regex_rule(
            rule_id="COMPANY_006",
            name="Hardcoded Environment Value",
            pattern=r'(prod|staging|dev)\.example\.com',
            severity="MEDIUM",
            category="Company Standards",
            description="Hardcoded environment-specific hostname detected",
            suggestion="Use configuration or environment variables for environment-specific values",
        )

        # Rule 7: Check for TODO/FIXME comments in production code
        engine.add_regex_rule(
            rule_id="COMPANY_007",
            name="TODO/FIXME Comment",
            pattern=r"#\s*(TODO|FIXME|HACK|XXX)",
            severity="LOW",
            category="Company Standards",
            description="TODO/FIXME comment found in code",
            suggestion="Create a ticket for this item and link it in the comment",
        )

        # Rule 8: Require type hints on public functions
        def check_missing_type_hints(tree: ast.AST) -> list[int]:
            """Check for public functions without type hints."""
            lines = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Skip private functions and __init__
                    if node.name.startswith("_") and node.name != "__init__":
                        continue

                    # Check if function has return type annotation
                    has_return_type = node.returns is not None

                    # Check if parameters have type annotations
                    has_param_types = all(
                        arg.annotation is not None
                        for arg in node.args.args
                        if arg.arg != "self" and arg.arg != "cls"
                    )

                    if not (has_return_type and has_param_types):
                        lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="COMPANY_008",
            name="Missing Type Hints",
            checker=check_missing_type_hints,
            severity="LOW",
            category="Company Standards",
            description="Function is missing type hints",
            suggestion="Add type hints for all parameters and return value per PEP 484",
        )

    def on_enable(self) -> None:
        """Called when plugin is enabled."""
        print("[Company Standards Plugin] Enabled - enforcing company coding standards")

    def on_disable(self) -> None:
        """Called when plugin is disabled."""
        print("[Company Standards Plugin] Disabled")

    def on_file_analyzed(self, file_path, violations) -> None:
        """Called after each file is analyzed."""
        # Count company-specific violations
        company_violations = [v for v in violations if v.rule_id.startswith("COMPANY_")]
        if company_violations:
            print(
                f"[Company Standards] {file_path}: {len(company_violations)} standard violations"
            )
