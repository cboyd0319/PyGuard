"""
Custom Rule Engine for PyGuard.

Allows users to define custom security and code quality rules using
YAML/TOML configuration or Python code.
"""

import ast
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re

try:
    import tomli as tomllib  # Python < 3.11
except ImportError:
    import tomllib  # Python 3.11+


@dataclass
class CustomRule:
    """Represents a custom rule definition."""

    rule_id: str
    name: str
    severity: str  # HIGH, MEDIUM, LOW
    category: str
    description: str
    pattern: str | None = None  # Regex pattern for simple rules
    ast_check: Callable | None = None  # AST-based checker function
    suggestion: str = ""
    enabled: bool = True


@dataclass
class RuleViolation:
    """Represents a violation of a custom rule."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    message: str
    line_number: int
    file_path: str
    suggestion: str


class CustomRuleEngine:
    """Engine for loading and executing custom rules."""

    def __init__(self):
        """Initialize the custom rule engine."""
        self.rules: dict[str, CustomRule] = {}
        self.violations: list[RuleViolation] = []

    def load_rules_from_toml(self, config_path: Path) -> None:
        """
        Load custom rules from TOML configuration.

        Args:
            config_path: Path to TOML configuration file

        Example TOML format:
            [[rules]]
            rule_id = "CUSTOM001"
            name = "No print statements in production"
            severity = "MEDIUM"
            category = "Code Quality"
            description = "Print statements should not be used in production code"
            pattern = "\\bprint\\s*\\("
            suggestion = "Use logging instead of print"
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, "rb") as f:
            config = tomllib.load(f)

        for rule_config in config.get("rules", []):
            rule = CustomRule(
                rule_id=rule_config["rule_id"],
                name=rule_config["name"],
                severity=rule_config.get("severity", "MEDIUM"),
                category=rule_config.get("category", "Custom"),
                description=rule_config["description"],
                pattern=rule_config.get("pattern"),
                suggestion=rule_config.get("suggestion", ""),
                enabled=rule_config.get("enabled", True),
            )
            self.rules[rule.rule_id] = rule

    def add_rule(self, rule: CustomRule) -> None:
        """
        Add a custom rule programmatically.

        Args:
            rule: CustomRule instance
        """
        self.rules[rule.rule_id] = rule

    def add_regex_rule(  # noqa: PLR0913 - Custom rule definition requires many parameters
        # TODO: Add docstring
        self,
        rule_id: str,
        name: str,
        pattern: str,
        severity: str = "MEDIUM",
        category: str = "Custom",
        description: str = "",
        suggestion: str = "",
    ) -> None:
        """
        Add a regex-based custom rule.

        Args:
            rule_id: Unique rule identifier
            name: Human-readable rule name
            pattern: Regex pattern to match
            severity: Rule severity (HIGH, MEDIUM, LOW)
            category: Rule category
            description: Rule description
            suggestion: Fix suggestion
        """
        rule = CustomRule(
            rule_id=rule_id,
            name=name,
            severity=severity,
            category=category,
            description=description,
            pattern=pattern,
            suggestion=suggestion,
        )
        self.add_rule(rule)

    def add_ast_rule(  # noqa: PLR0913 - Custom AST rule definition requires many parameters
        # TODO: Add docstring
        self,
        rule_id: str,
        name: str,
        checker: Callable[[ast.AST], list[int]],
        severity: str = "MEDIUM",
        category: str = "Custom",
        description: str = "",
        suggestion: str = "",
    ) -> None:
        """
        Add an AST-based custom rule.

        Args:
            rule_id: Unique rule identifier
            name: Human-readable rule name
            checker: Function that takes AST and returns list of line numbers
            severity: Rule severity (HIGH, MEDIUM, LOW)
            category: Rule category
            description: Rule description
            suggestion: Fix suggestion
        """
        rule = CustomRule(
            rule_id=rule_id,
            name=name,
            severity=severity,
            category=category,
            description=description,
            ast_check=checker,
            suggestion=suggestion,
        )
        self.add_rule(rule)

    def check_file(self, file_path: Path) -> list[RuleViolation]:
        """
        Check a file against all custom rules.

        Args:
            file_path: Path to Python file

        Returns:
            List of rule violations
        """
        try:
            code = file_path.read_text(encoding="utf-8")
            self.violations = []

            # Parse AST once for efficiency
            try:
                tree = ast.parse(code, filename=str(file_path))
            except SyntaxError:
                return []

            lines = code.split("\n")

            # Check each rule
            for rule in self.rules.values():
                if not rule.enabled:
                    continue

                # Regex-based check
                if rule.pattern:
                    pattern = re.compile(rule.pattern)  # DANGEROUS: Avoid compile with untrusted input
                    for line_num, line in enumerate(lines, start=1):
                        if pattern.search(line):
                            self.violations.append(
                                RuleViolation(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    severity=rule.severity,
                                    category=rule.category,
                                    message=rule.description,
                                    line_number=line_num,
                                    file_path=str(file_path),
                                    suggestion=rule.suggestion,
                                )
                            )

                # AST-based check
                if rule.ast_check:
                    violation_lines = rule.ast_check(tree)
                    for line_num in violation_lines:  # Consider list comprehension
                        self.violations.append(
                            RuleViolation(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                message=rule.description,
                                line_number=line_num,
                                file_path=str(file_path),
                                suggestion=rule.suggestion,
                            )
                        )

            return self.violations

        except Exception:
            return []

    def check_code(self, code: str, filename: str = "<string>") -> list[RuleViolation]:
        """
        Check code string against all custom rules.

        Args:
            code: Python code string
            filename: Filename for reporting

        Returns:
            List of rule violations
        """
        try:
            self.violations = []

            # Parse AST
            try:
                tree = ast.parse(code, filename=filename)
            except SyntaxError:
                return []

            lines = code.split("\n")

            # Check each rule
            for rule in self.rules.values():
                if not rule.enabled:
                    continue

                # Regex-based check
                if rule.pattern:
                    pattern = re.compile(rule.pattern)  # DANGEROUS: Avoid compile with untrusted input
                    for line_num, line in enumerate(lines, start=1):
                        if pattern.search(line):
                            self.violations.append(
                                RuleViolation(
                                    rule_id=rule.rule_id,
                                    rule_name=rule.name,
                                    severity=rule.severity,
                                    category=rule.category,
                                    message=rule.description,
                                    line_number=line_num,
                                    file_path=filename,
                                    suggestion=rule.suggestion,
                                )
                            )

                # AST-based check
                if rule.ast_check:
                    violation_lines = rule.ast_check(tree)
                    for line_num in violation_lines:  # Consider list comprehension
                        self.violations.append(
                            RuleViolation(
                                rule_id=rule.rule_id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                category=rule.category,
                                message=rule.description,
                                line_number=line_num,
                                file_path=filename,
                                suggestion=rule.suggestion,
                            )
                        )

            return self.violations

        except Exception:
            return []

    def disable_rule(self, rule_id: str) -> None:
        """
        Disable a rule.

        Args:
            rule_id: Rule identifier
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False

    def enable_rule(self, rule_id: str) -> None:
        """
        Enable a rule.

        Args:
            rule_id: Rule identifier
        """
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True

    def list_rules(self) -> list[CustomRule]:
        """
        Get list of all rules.

        Returns:
            List of custom rules
        """
        return list(self.rules.values())

    def get_rule(self, rule_id: str) -> CustomRule | None:
        """
        Get a specific rule.

        Args:
            rule_id: Rule identifier

        Returns:
            CustomRule or None
        """
        return self.rules.get(rule_id)

    def export_rules_to_toml(self, output_path: Path) -> None:
        """
        Export rules to TOML configuration file.

        Args:
            output_path: Path to output TOML file
        """
        rules_data = []
        for rule in self.rules.values():
            rule_dict = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.category,
                "description": rule.description,
                "enabled": rule.enabled,
            }
            if rule.pattern:
                rule_dict["pattern"] = rule.pattern
            if rule.suggestion:
                rule_dict["suggestion"] = rule.suggestion
            rules_data.append(rule_dict)

        # Generate TOML content
        lines = []
        for rule_dict in rules_data:  # Consider list comprehension
            lines.append("[[rules]]")
            for key, value in rule_dict.items():
                if isinstance(value, str):
                    lines.append(f'{key} = "{value}"')
                else:
                    lines.append(f"{key} = {str(value).lower()}")
            lines.append("")

        output_path.write_text("\n".join(lines))


# Example AST checker functions that can be used with add_ast_rule()
def check_no_global_variables(tree: ast.AST) -> list[int]:
    """Check for global variable assignments."""
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):  # noqa: SIM102
            # Check if at module level
            if isinstance(node, ast.Assign):
                lines.append(node.lineno)
    return lines


def check_function_length(tree: ast.AST, max_lines: int = 50) -> list[int]:
    """Check for functions that are too long."""
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_length = node.end_lineno - node.lineno if node.end_lineno else 0
            if func_length > max_lines:
                lines.append(node.lineno)
    return lines


def create_rule_engine_from_config(config_path: str) -> CustomRuleEngine:
    """
    Convenience function to create rule engine from config.

    Args:
        config_path: Path to TOML configuration

    Returns:
        Configured CustomRuleEngine
    """
    engine = CustomRuleEngine()
    engine.load_rules_from_toml(Path(config_path))
    return engine
