"""Tests for rule engine framework."""

import ast
from pathlib import Path
from typing import List, Optional

import pytest

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleExecutor,
    RuleRegistry,
    RuleSeverity,
    RuleViolation,
)


class TestRuleDataClasses:
    """Test rule data classes."""

    def test_rule_violation_creation(self):
        """Test creating a rule violation."""
        violation = RuleViolation(
            rule_id="TEST001",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message="Test violation",
            file_path=Path("test.py"),
            line_number=10,
            column=5,
        )

        assert violation.rule_id == "TEST001"
        assert violation.category == RuleCategory.STYLE
        assert violation.severity == RuleSeverity.LOW
        assert violation.line_number == 10

    def test_rule_creation(self):
        """Test creating a rule."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test message: {value}",
            description="Test description",
        )

        assert rule.rule_id == "TEST001"
        assert rule.category == RuleCategory.SECURITY
        assert rule.enabled is True

    def test_rule_message_formatting(self):
        """Test rule message formatting."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Line too long: {length} > {limit}",
            description="Test",
        )

        message = rule.format_message(length=100, limit=80)
        assert message == "Line too long: 100 > 80"


class TestRuleRegistry:
    """Test rule registry."""

    def test_register_rule(self):
        """Test registering a rule."""
        registry = RuleRegistry()
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        registry.register(rule)
        assert registry.get_rule("TEST001") == rule

    def test_unregister_rule(self):
        """Test unregistering a rule."""
        registry = RuleRegistry()
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        registry.register(rule)
        assert registry.unregister("TEST001") is True
        assert registry.get_rule("TEST001") is None

    def test_get_enabled_rules(self):
        """Test getting enabled rules."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-rule-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
            enabled=True,
        )

        rule2 = Rule(
            rule_id="TEST002",
            name="test-rule-2",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test",
            description="Test",
            enabled=False,
        )

        registry.register(rule1)
        registry.register(rule2)

        enabled = registry.get_enabled_rules()
        assert len(enabled) == 1
        assert enabled[0].rule_id == "TEST001"

    def test_get_rules_by_category(self):
        """Test getting rules by category."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-rule-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        rule2 = Rule(
            rule_id="TEST002",
            name="test-rule-2",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test",
            description="Test",
        )

        registry.register(rule1)
        registry.register(rule2)

        style_rules = registry.get_rules_by_category(RuleCategory.STYLE)
        assert len(style_rules) == 1
        assert style_rules[0].rule_id == "TEST001"

    def test_enable_disable_rule(self):
        """Test enabling and disabling rules."""
        registry = RuleRegistry()
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
            enabled=True,
        )

        registry.register(rule)

        assert registry.disable_rule("TEST001") is True
        assert rule.enabled is False

        assert registry.enable_rule("TEST001") is True
        assert rule.enabled is True

    def test_enable_disable_category(self):
        """Test enabling and disabling categories."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-rule-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        rule2 = Rule(
            rule_id="TEST002",
            name="test-rule-2",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.MEDIUM,
            message_template="Test",
            description="Test",
        )

        registry.register(rule1)
        registry.register(rule2)

        count = registry.disable_category(RuleCategory.STYLE)
        assert count == 2
        assert rule1.enabled is False
        assert rule2.enabled is False

        count = registry.enable_category(RuleCategory.STYLE)
        assert count == 2
        assert rule1.enabled is True
        assert rule2.enabled is True

    def test_filter_by_severity(self):
        """Test filtering rules by severity."""
        registry = RuleRegistry()

        rules = [
            Rule(
                rule_id="TEST001",
                name="test-1",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST002",
                name="test-2",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST003",
                name="test-3",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.HIGH,
                message_template="Test",
                description="Test",
            ),
        ]

        for rule in rules:
            registry.register(rule)

        filtered = registry.filter_by_severity(rules, RuleSeverity.MEDIUM)
        assert len(filtered) == 2  # MEDIUM and HIGH

    def test_filter_by_tags(self):
        """Test filtering rules by tags."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
            tags={"pep8", "style"},
        )

        rule2 = Rule(
            rule_id="TEST002",
            name="test-2",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test",
            description="Test",
            tags={"security", "owasp"},
        )

        registry.register(rule1)
        registry.register(rule2)

        filtered = registry.filter_by_tags([rule1, rule2], {"security"})
        assert len(filtered) == 1
        assert filtered[0].rule_id == "TEST002"


class TestRuleExecution:
    """Test rule execution."""

    def test_simple_rule_execution(self, tmp_path):
        """Test executing a simple rule."""

        # Create a test rule
        class TestRule(Rule):
            def detect(
                self, code: str, file_path: Path, tree: Optional[ast.AST] = None
            ) -> List[RuleViolation]:
                # Simple test: flag any line with "bad_practice"
                violations = []
                for i, line in enumerate(code.split("\n"), 1):
                    if "bad_practice" in line:
                        violations.append(
                            RuleViolation(
                                rule_id=self.rule_id,
                                category=self.category,
                                severity=self.severity,
                                message=self.message_template,
                                file_path=file_path,
                                line_number=i,
                            )
                        )
                return violations

        rule = TestRule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Bad practice detected",
            description="Test",
        )

        registry = RuleRegistry()
        registry.register(rule)

        executor = RuleExecutor(registry)

        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("# This is bad_practice\nprint('hello')\n")

        violations = executor.analyze_file(test_file, [rule])

        assert len(violations) == 1
        assert violations[0].rule_id == "TEST001"
        assert violations[0].line_number == 1
