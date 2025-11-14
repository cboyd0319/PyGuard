"""
Rule engine framework for PyGuard.

Provides a unified rule system for detection and auto-fix capabilities across all
linters, formatters, and security scanners. This enables PyGuard to replace
multiple tools (Ruff, Pylint, Flake8, Black, etc.) with a single integrated solution.
"""

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pyguard.lib.core import PyGuardLogger


class RuleCategory(Enum):
    """Rule categories aligned with industry standards."""

    SECURITY = "security"  # Security vulnerabilities
    ERROR = "error"  # Probable bugs
    WARNING = "warning"  # Suspicious constructs
    STYLE = "style"  # Code style and formatting
    CONVENTION = "convention"  # Coding conventions
    REFACTOR = "refactor"  # Refactoring suggestions
    SIMPLIFICATION = "simplification"  # Code simplification opportunities
    MODERNIZATION = "modernization"  # Code modernization opportunities
    PERFORMANCE = "performance"  # Performance issues
    TYPE = "type"  # Type checking issues
    IMPORT = "import"  # Import-related issues
    DOCUMENTATION = "documentation"  # Documentation issues
    DESIGN = "design"  # Design and architecture
    DUPLICATION = "duplication"  # Code duplication
    COMPLEXITY = "complexity"  # Complexity metrics


class RuleSeverity(Enum):
    """Rule severity levels."""

    CRITICAL = "CRITICAL"  # Must fix immediately
    HIGH = "HIGH"  # Should fix soon
    MEDIUM = "MEDIUM"  # Should fix eventually
    LOW = "LOW"  # Nice to fix
    INFO = "INFO"  # Informational only


class FixApplicability(Enum):
    """Whether and how a fix can be applied."""

    AUTOMATIC = "automatic"  # Safe to apply automatically
    SAFE = "safe"  # Alias for AUTOMATIC - safe to apply automatically
    SUGGESTED = "suggested"  # User should review before applying
    MANUAL = "manual"  # Requires manual intervention
    UNSAFE = "unsafe"  # Fix available but unsafe to auto-apply (requires careful review)
    NONE = "none"  # No automated fix available


@dataclass
class RuleViolation:
    """Represents a single rule violation in code."""

    rule_id: str  # e.g., "E501", "S102", "PL001"
    category: RuleCategory
    severity: RuleSeverity
    message: str
    file_path: Path
    line_number: int
    column: int = 0
    end_line_number: int | None = None
    end_column: int | None = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    fix_applicability: FixApplicability = FixApplicability.NONE
    fix_data: dict[str, Any] | None = None
    owasp_id: str | None = None
    cwe_id: str | None = None
    source_tool: str = "pyguard"  # Which tool/module detected this


@dataclass
class Rule:
    """Base class for all PyGuard rules."""

    rule_id: str  # Unique identifier (e.g., "PG001", "E501")
    name: str  # Human-readable name
    category: RuleCategory
    severity: RuleSeverity
    message_template: str  # Message with placeholders: "Line too long ({length} > {limit})"
    description: str  # Detailed description
    explanation: str = ""  # Why this rule matters
    fix_applicability: FixApplicability = FixApplicability.NONE
    enabled: bool = True
    tags: set[str] = field(default_factory=set)
    references: list[str] = field(default_factory=list)  # URLs to documentation
    owasp_mapping: str | None = None
    cwe_mapping: str | None = None

    def detect(
        # TODO: Add docstring
        self, code: str, file_path: Path, tree: ast.AST | None = None
    ) -> list[RuleViolation]:
        """
        Detect violations of this rule in code.

        Args:
            code: Source code to analyze
            file_path: Path to the file
            tree: Parsed AST (optional, will be parsed if not provided)

        Returns:
            List of violations found
        """
        raise NotImplementedError("Subclasses must implement detect()")

    def fix(self, _code: str, _violation: RuleViolation) -> str | None:
        """
        Apply automatic fix for a violation.

        Args:
            _code: Original source code (reserved)
            _violation: The violation to fix (reserved)

        Returns:
            Fixed code, or None if fix not applicable
        """
        return None  # Base implementation returns None (no fix)

    def format_message(self, **kwargs) -> str:
        """Format the message template with provided values."""
        try:
            return self.message_template.format(**kwargs)
        except KeyError:
            return self.message_template

    @property
    def cwe_id(self) -> str | None:
        """Alias for cwe_mapping for backward compatibility."""
        return self.cwe_mapping

    @property
    def owasp_category(self) -> str | None:
        """Alias for owasp_mapping for backward compatibility."""
        return self.owasp_mapping


class RuleRegistry:
    """Central registry for all PyGuard rules."""

    def __init__(self):
        """Initialize rule registry."""
        self.rules: dict[str, Rule] = {}
        self.rules_by_category: dict[RuleCategory, list[Rule]] = {}
        self.logger = PyGuardLogger()

    def register(self, rule: Rule) -> None:
        """
        Register a rule.

        Args:
            rule: Rule to register
        """
        if rule.rule_id in self.rules:
            self.logger.warning(
                f"Overwriting existing rule: {rule.rule_id}",
                category="RuleRegistry",
            )

        self.rules[rule.rule_id] = rule

        # Add to category index
        if rule.category not in self.rules_by_category:
            self.rules_by_category[rule.category] = []
        self.rules_by_category[rule.category].append(rule)

    def unregister(self, rule_id: str) -> bool:
        """
        Unregister a rule.

        Args:
            rule_id: Rule ID to unregister

        Returns:
            True if rule was found and removed
        """
        if rule_id not in self.rules:
            return False

        rule = self.rules[rule_id]
        del self.rules[rule_id]

        # Remove from category index
        if rule.category in self.rules_by_category:
            self.rules_by_category[rule.category] = [
                r for r in self.rules_by_category[rule.category] if r.rule_id != rule_id
            ]

        return True

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        return self.rules.get(rule_id)

    def get_all_rules(self) -> list[Rule]:
        """Get all registered rules."""
        return list(self.rules.values())

    def get_enabled_rules(self) -> list[Rule]:
        """Get all enabled rules."""
        return [rule for rule in self.rules.values() if rule.enabled]

    def get_rules_by_category(self, category: RuleCategory) -> list[Rule]:
        """Get all rules in a category."""
        return self.rules_by_category.get(category, [])

    def get_fixable_rules(self) -> list[Rule]:
        """Get all rules that have auto-fixes available."""
        return [
            rule
            for rule in self.rules.values()
            if rule.fix_applicability in (FixApplicability.AUTOMATIC, FixApplicability.SUGGESTED)
        ]

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def enable_category(self, category: RuleCategory) -> int:
        """Enable all rules in a category. Returns count of rules enabled."""
        rules = self.get_rules_by_category(category)
        for rule in rules:
            rule.enabled = True
        return len(rules)

    def disable_category(self, category: RuleCategory) -> int:
        """Disable all rules in a category. Returns count of rules disabled."""
        rules = self.get_rules_by_category(category)
        for rule in rules:
            rule.enabled = False
        return len(rules)

    def filter_by_severity(self, rules: list[Rule], min_severity: RuleSeverity) -> list[Rule]:
        """Filter rules by minimum severity level."""
        severity_order = {
            RuleSeverity.INFO: 0,
            RuleSeverity.LOW: 1,
            RuleSeverity.MEDIUM: 2,
            RuleSeverity.HIGH: 3,
            RuleSeverity.CRITICAL: 4,
        }
        min_level = severity_order[min_severity]
        return [rule for rule in rules if severity_order[rule.severity] >= min_level]

    def filter_by_tags(self, rules: list[Rule], tags: set[str]) -> list[Rule]:
        """Filter rules by tags (returns rules that have any of the provided tags)."""
        return [rule for rule in rules if rule.tags & tags]


class RuleExecutor:
    """Executes rules against code and manages violations."""

    def __init__(self, registry: RuleRegistry):
        """Initialize rule executor."""
        self.registry = registry
        self.logger = PyGuardLogger()

    def analyze_file(
        # TODO: Add docstring
        self,
        file_path: Path,
        rules: list[Rule] | None = None,
        tree: ast.AST | None = None,
    ) -> list[RuleViolation]:
        """
        Analyze a file with specified rules.

        Args:
            file_path: Path to file to analyze
            rules: Specific rules to run (None = all enabled rules)
            tree: Pre-parsed AST (optional)

        Returns:
            List of all violations found
        """
        if rules is None:
            rules = self.registry.get_enabled_rules()

        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            self.logger.error(
                f"Failed to read file: {file_path}",
                category="RuleExecutor",
                details={"error": str(e)},
            )
            return []

        all_violations = []

        for rule in rules:
            try:
                violations = rule.detect(code, file_path, tree)
                all_violations.extend(violations)
            except Exception as e:
                self.logger.error(
                    f"Rule {rule.rule_id} failed on {file_path}",
                    category="RuleExecutor",
                    error=str(e),
                )

        return all_violations

    def apply_fixes(
        # TODO: Add docstring
        self, code: str, violations: list[RuleViolation]
    ) -> tuple[str, list[RuleViolation]]:
        """
        Apply fixes for violations.

        Args:
            code: Original code
            violations: List of violations to fix

        Returns:
            Tuple of (fixed code, list of applied fixes)
        """
        fixed_code = code
        applied_fixes = []

        # Sort violations by line number (descending) to avoid offset issues
        sorted_violations = sorted(
            violations, key=lambda v: (v.line_number, v.column), reverse=True
        )

        for violation in sorted_violations:
            if violation.fix_applicability == FixApplicability.AUTOMATIC:
                rule = self.registry.get_rule(violation.rule_id)
                if rule:
                    try:
                        new_code = rule.fix(fixed_code, violation)
                        if new_code and new_code != fixed_code:
                            fixed_code = new_code
                            applied_fixes.append(violation)
                    except Exception as e:
                        self.logger.error(
                            f"Fix failed for {violation.rule_id}",
                            category="RuleExecutor",
                            error=str(e),
                        )

        return fixed_code, applied_fixes


# Global registry instance
_global_registry = RuleRegistry()


def get_global_registry() -> RuleRegistry:
    """Get the global rule registry instance."""
    return _global_registry


def register_rule(rule: Rule) -> None:
    """Register a rule with the global registry."""
    _global_registry.register(rule)


def register_rules(rules: list[Rule]) -> None:
    """Register multiple rules with the global registry."""
    for rule in rules:
        _global_registry.register(rule)
