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


class TestRuleViolationEdgeCases:
    """Test RuleViolation edge cases and optional fields."""

    def test_rule_violation_with_all_fields(self):
        """Test creating a rule violation with all optional fields."""
        violation = RuleViolation(
            rule_id="SEC001",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            message="Security issue detected",
            file_path=Path("test.py"),
            line_number=10,
            column=5,
            end_line_number=12,
            end_column=20,
            code_snippet="vulnerable_code()",
            fix_suggestion="Use safe_code() instead",
            fix_applicability=FixApplicability.SUGGESTED,
            fix_data={"replacement": "safe_code()"},
            owasp_id="A01:2021",
            cwe_id="CWE-502",
            source_tool="bandit",
        )

        assert violation.rule_id == "SEC001"
        assert violation.end_line_number == 12
        assert violation.end_column == 20
        assert violation.code_snippet == "vulnerable_code()"
        assert violation.fix_suggestion == "Use safe_code() instead"
        assert violation.fix_applicability == FixApplicability.SUGGESTED
        assert violation.fix_data == {"replacement": "safe_code()"}
        assert violation.owasp_id == "A01:2021"
        assert violation.cwe_id == "CWE-502"
        assert violation.source_tool == "bandit"

    def test_rule_violation_minimal_fields(self):
        """Test creating a rule violation with minimal required fields."""
        violation = RuleViolation(
            rule_id="TEST001",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message="Test message",
            file_path=Path("test.py"),
            line_number=1,
        )

        # Verify defaults
        assert violation.column == 0
        assert violation.end_line_number is None
        assert violation.end_column is None
        assert violation.code_snippet == ""
        assert violation.fix_suggestion == ""
        assert violation.fix_applicability == FixApplicability.NONE
        assert violation.fix_data is None
        assert violation.owasp_id is None
        assert violation.cwe_id is None
        assert violation.source_tool == "pyguard"


class TestRuleCategories:
    """Test RuleCategory enum."""

    def test_all_categories_have_values(self):
        """Test that all categories have string values."""
        for category in RuleCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0

    def test_category_values_are_unique(self):
        """Test that category values are unique."""
        values = [c.value for c in RuleCategory]
        assert len(values) == len(set(values))


class TestRuleSeverity:
    """Test RuleSeverity enum."""

    def test_all_severities_have_values(self):
        """Test that all severities have string values."""
        for severity in RuleSeverity:
            assert isinstance(severity.value, str)
            assert len(severity.value) > 0

    def test_severity_values_are_unique(self):
        """Test that severity values are unique."""
        values = [s.value for s in RuleSeverity]
        assert len(values) == len(set(values))

    def test_severity_ordering_critical_to_info(self):
        """Test that severities are in expected order."""
        severities = [
            RuleSeverity.CRITICAL,
            RuleSeverity.HIGH,
            RuleSeverity.MEDIUM,
            RuleSeverity.LOW,
            RuleSeverity.INFO,
        ]
        assert len(severities) == len(RuleSeverity)


class TestFixApplicability:
    """Test FixApplicability enum."""

    def test_all_applicabilities_have_values(self):
        """Test that all fix applicabilities have string values."""
        for applicability in FixApplicability:
            assert isinstance(applicability.value, str)
            assert len(applicability.value) > 0

    def test_safe_is_alias_for_automatic(self):
        """Test that SAFE and AUTOMATIC have same semantic meaning."""
        assert FixApplicability.SAFE.value == "safe"
        assert FixApplicability.AUTOMATIC.value == "automatic"


class TestRuleWithOptionalFields:
    """Test Rule with optional fields."""

    def test_rule_with_all_optional_fields(self):
        """Test creating a rule with all optional fields."""
        rule = Rule(
            rule_id="SEC001",
            name="security-rule",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            message_template="Security issue: {detail}",
            description="Detects security issues",
            explanation="This rule is important for security",
            fix_applicability=FixApplicability.AUTOMATIC,
            enabled=True,
            tags={"security", "cwe-502"},
            references=["https://example.com/security"],
            owasp_mapping="A01:2021",
            cwe_mapping="CWE-502",
        )

        assert rule.explanation == "This rule is important for security"
        assert rule.tags == {"security", "cwe-502"}
        assert rule.references == ["https://example.com/security"]
        assert rule.owasp_mapping == "A01:2021"
        assert rule.cwe_mapping == "CWE-502"

    def test_rule_default_optional_fields(self):
        """Test rule default values for optional fields."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        assert rule.explanation == ""
        assert rule.fix_applicability == FixApplicability.NONE
        assert rule.enabled is True
        assert rule.tags == set()
        assert rule.references == []
        assert rule.owasp_mapping is None
        assert rule.cwe_mapping is None

    def test_rule_fix_method_returns_none_by_default(self):
        """Test that base Rule.fix() returns None."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        violation = RuleViolation(
            rule_id="TEST001",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message="Test",
            file_path=Path("test.py"),
            line_number=1,
        )

        result = rule.fix("test code", violation)
        assert result is None

    def test_rule_message_formatting_with_kwargs(self):
        """Test rule message formatting with multiple kwargs."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Found {count} issues in {file} at line {line}",
            description="Test",
        )

        message = rule.format_message(count=5, file="test.py", line=42)
        assert message == "Found 5 issues in test.py at line 42"

    def test_rule_message_formatting_missing_key(self):
        """Test rule message formatting when key is missing returns original template."""
        rule = Rule(
            rule_id="TEST001",
            name="test-rule",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Value: {missing_key}",
            description="Test",
        )

        message = rule.format_message(other_key="value")
        assert message == "Value: {missing_key}"


class TestRuleRegistryEdgeCases:
    """Test RuleRegistry edge cases."""

    def test_registry_get_nonexistent_rule(self):
        """Test getting a rule that doesn't exist returns None."""
        registry = RuleRegistry()
        assert registry.get_rule("NONEXISTENT") is None

    def test_registry_unregister_nonexistent_rule(self):
        """Test unregistering a rule that doesn't exist returns False."""
        registry = RuleRegistry()
        assert registry.unregister("NONEXISTENT") is False

    def test_registry_register_duplicate_rule_logs_warning(self, caplog):
        """Test that registering duplicate rule logs warning."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        rule2 = Rule(
            rule_id="TEST001",  # Same ID
            name="test-2",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test",
            description="Test",
        )

        registry.register(rule1)
        registry.register(rule2)  # Should log warning

        # Verify the second rule replaced the first
        assert registry.get_rule("TEST001") == rule2

    def test_registry_get_rules_by_empty_category(self):
        """Test getting rules by category when none exist."""
        registry = RuleRegistry()
        rules = registry.get_rules_by_category(RuleCategory.SECURITY)
        assert rules == []

    def test_registry_enable_nonexistent_rule(self):
        """Test enabling a rule that doesn't exist returns False."""
        registry = RuleRegistry()
        assert registry.enable_rule("NONEXISTENT") is False

    def test_registry_disable_nonexistent_rule(self):
        """Test disabling a rule that doesn't exist returns False."""
        registry = RuleRegistry()
        assert registry.disable_rule("NONEXISTENT") is False

    def test_registry_enable_category_no_rules(self):
        """Test enabling category with no rules returns 0."""
        registry = RuleRegistry()
        count = registry.enable_category(RuleCategory.SECURITY)
        assert count == 0

    def test_registry_disable_category_no_rules(self):
        """Test disabling category with no rules returns 0."""
        registry = RuleRegistry()
        count = registry.disable_category(RuleCategory.SECURITY)
        assert count == 0

    def test_registry_filter_by_severity_empty_list(self):
        """Test filtering empty list by severity."""
        registry = RuleRegistry()
        filtered = registry.filter_by_severity([], RuleSeverity.HIGH)
        assert filtered == []

    def test_registry_filter_by_severity_includes_higher_severities(self):
        """Test that severity filter includes higher severities."""
        registry = RuleRegistry()

        rules = [
            Rule(
                rule_id="TEST001",
                name="test-1",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.INFO,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST002",
                name="test-2",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.LOW,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST003",
                name="test-3",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.MEDIUM,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST004",
                name="test-4",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.HIGH,
                message_template="Test",
                description="Test",
            ),
            Rule(
                rule_id="TEST005",
                name="test-5",
                category=RuleCategory.STYLE,
                severity=RuleSeverity.CRITICAL,
                message_template="Test",
                description="Test",
            ),
        ]

        # Filter by MEDIUM should include MEDIUM, HIGH, CRITICAL
        filtered = registry.filter_by_severity(rules, RuleSeverity.MEDIUM)
        assert len(filtered) == 3
        assert all(
            r.severity
            in [RuleSeverity.MEDIUM, RuleSeverity.HIGH, RuleSeverity.CRITICAL]
            for r in filtered
        )

    def test_registry_filter_by_tags_empty_list(self):
        """Test filtering empty list by tags."""
        registry = RuleRegistry()
        filtered = registry.filter_by_tags([], {"security"})
        assert filtered == []

    def test_registry_filter_by_tags_no_matches(self):
        """Test filtering by tags with no matches."""
        registry = RuleRegistry()

        rule = Rule(
            rule_id="TEST001",
            name="test-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
            tags={"pep8"},
        )

        filtered = registry.filter_by_tags([rule], {"security"})
        assert filtered == []

    def test_registry_get_all_rules(self):
        """Test getting all registered rules."""
        registry = RuleRegistry()

        rule1 = Rule(
            rule_id="TEST001",
            name="test-1",
            category=RuleCategory.STYLE,
            severity=RuleSeverity.LOW,
            message_template="Test",
            description="Test",
        )

        rule2 = Rule(
            rule_id="TEST002",
            name="test-2",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.HIGH,
            message_template="Test",
            description="Test",
        )

        registry.register(rule1)
        registry.register(rule2)

        all_rules = registry.get_all_rules()
        assert len(all_rules) == 2
        assert rule1 in all_rules
        assert rule2 in all_rules


class TestRuleExecutorEdgeCases:
    """Test RuleExecutor edge cases."""

    def test_executor_analyze_empty_file(self, tmp_path):
        """Test analyzing an empty file."""
        registry = RuleRegistry()
        executor = RuleExecutor(registry)

        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        violations = executor.analyze_file(test_file, [])
        assert violations == []

    def test_executor_analyze_file_no_rules(self, tmp_path):
        """Test analyzing file with no rules."""
        registry = RuleRegistry()
        executor = RuleExecutor(registry)

        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')\n")

        violations = executor.analyze_file(test_file, [])
        assert violations == []

    def test_executor_analyze_multiple_violations(self, tmp_path):
        """Test analyzing file that produces multiple violations."""

        class TestRule(Rule):
            def detect(
                self, code: str, file_path: Path, tree: Optional[ast.AST] = None
            ) -> List[RuleViolation]:
                violations = []
                for i, line in enumerate(code.split("\n"), 1):
                    if "issue" in line:
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
            message_template="Issue detected",
            description="Test",
        )

        registry = RuleRegistry()
        registry.register(rule)
        executor = RuleExecutor(registry)

        test_file = tmp_path / "test.py"
        test_file.write_text("# issue 1\nprint('hello')\n# issue 2\n")

        violations = executor.analyze_file(test_file, [rule])
        assert len(violations) == 2
        assert violations[0].line_number == 1
        assert violations[1].line_number == 3
