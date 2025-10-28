"""Tests for custom rules engine."""

from pathlib import Path

import pytest

from pyguard.lib.custom_rules import (
    CustomRule,
    CustomRuleEngine,
    check_function_length,
    check_no_global_variables,
    create_rule_engine_from_config,
)


class TestCustomRule:
    """Test CustomRule dataclass."""

    def test_create_rule(self):
        """Test creating a custom rule."""
        rule = CustomRule(
            rule_id="TEST001",
            name="Test Rule",
            severity="HIGH",
            category="Test",
            description="Test description",
        )

        assert rule.rule_id == "TEST001"
        assert rule.name == "Test Rule"
        assert rule.severity == "HIGH"
        assert rule.enabled is True


class TestCustomRuleEngine:
    """Test custom rule engine."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = CustomRuleEngine()
        assert engine is not None
        assert len(engine.rules) == 0

    def test_add_rule(self):
        """Test adding a rule."""
        engine = CustomRuleEngine()
        rule = CustomRule(
            rule_id="TEST001",
            name="Test Rule",
            severity="HIGH",
            category="Test",
            description="Test description",
        )

        engine.add_rule(rule)

        assert "TEST001" in engine.rules
        assert engine.rules["TEST001"] == rule

    def test_add_regex_rule(self):
        """Test adding a regex-based rule."""
        engine = CustomRuleEngine()

        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
            severity="MEDIUM",
            description="Avoid print statements",
            suggestion="Use logging instead",
        )

        assert "PRINT001" in engine.rules
        assert engine.rules["PRINT001"].pattern is not None

    def test_add_ast_rule(self):
        """Test adding an AST-based rule."""

        def checker(tree):
            return [1, 2, 3]

        engine = CustomRuleEngine()
        engine.add_ast_rule(
            rule_id="AST001",
            name="AST Test",
            checker=checker,
            severity="HIGH",
            description="Test AST rule",
        )

        assert "AST001" in engine.rules
        assert engine.rules["AST001"].ast_check is not None

    def test_check_code_with_regex_rule(self):
        """Test checking code with regex rule."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
            severity="MEDIUM",
            description="Avoid print statements",
        )

        code = """
print("Hello world")
x = 1 + 2
"""

        violations = engine.check_code(code)

        assert len(violations) == 1
        assert violations[0].rule_id == "PRINT001"
        assert violations[0].line_number == 2

    def test_check_code_no_violations(self):
        """Test checking code with no violations."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
            severity="MEDIUM",
            description="Avoid print statements",
        )

        code = """
x = 1 + 2
y = x * 3
"""

        violations = engine.check_code(code)

        assert len(violations) == 0

    def test_check_file(self, tmp_path):
        """Test checking a file."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            """
print("test")
x = 1
"""
        )

        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
            severity="MEDIUM",
            description="Avoid print statements",
        )

        violations = engine.check_file(test_file)

        assert len(violations) == 1

    def test_disable_rule(self):
        """Test disabling a rule."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
        )

        engine.disable_rule("PRINT001")

        assert not engine.rules["PRINT001"].enabled

    def test_enable_rule(self):
        """Test enabling a rule."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
        )

        engine.disable_rule("PRINT001")
        engine.enable_rule("PRINT001")

        assert engine.rules["PRINT001"].enabled

    def test_disabled_rule_not_checked(self):
        """Test that disabled rules are not checked."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="PRINT001",
            name="No print statements",
            pattern=r"\bprint\s*\(",
        )

        engine.disable_rule("PRINT001")

        code = 'print("test")'
        violations = engine.check_code(code)

        assert len(violations) == 0

    def test_list_rules(self):
        """Test listing all rules."""
        engine = CustomRuleEngine()
        engine.add_regex_rule("RULE1", "Rule 1", r"pattern1")
        engine.add_regex_rule("RULE2", "Rule 2", r"pattern2")

        rules = engine.list_rules()

        assert len(rules) == 2
        assert any(r.rule_id == "RULE1" for r in rules)

    def test_get_rule(self):
        """Test getting a specific rule."""
        engine = CustomRuleEngine()
        engine.add_regex_rule("TEST001", "Test", r"pattern")

        rule = engine.get_rule("TEST001")

        assert rule is not None
        assert rule.rule_id == "TEST001"

    def test_get_nonexistent_rule(self):
        """Test getting non-existent rule."""
        engine = CustomRuleEngine()
        rule = engine.get_rule("NONEXISTENT")

        assert rule is None

    def test_load_rules_from_toml(self, tmp_path):
        """Test loading rules from TOML file."""
        config_file = tmp_path / "rules.toml"
        config_file.write_text(
            """
[[rules]]
rule_id = "CUSTOM001"
name = "No print statements"
severity = "MEDIUM"
category = "Code Quality"
description = "Avoid print statements"
pattern = "\\\\bprint\\\\s*\\\\("
suggestion = "Use logging"
enabled = true
"""
        )

        engine = CustomRuleEngine()
        engine.load_rules_from_toml(config_file)

        assert "CUSTOM001" in engine.rules
        assert engine.rules["CUSTOM001"].name == "No print statements"

    def test_load_rules_file_not_found(self):
        """Test loading from non-existent file."""
        engine = CustomRuleEngine()

        with pytest.raises(FileNotFoundError):
            engine.load_rules_from_toml(Path("/nonexistent/file.toml"))

    def test_export_rules_to_toml(self, tmp_path):
        """Test exporting rules to TOML file."""
        engine = CustomRuleEngine()
        engine.add_regex_rule(
            rule_id="TEST001",
            name="Test Rule",
            pattern=r"test",
            severity="HIGH",
            description="Test",
            suggestion="Fix it",
        )

        output_file = tmp_path / "output.toml"
        engine.export_rules_to_toml(output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "TEST001" in content
        assert "Test Rule" in content

    def test_check_code_with_ast_rule(self):
        """Test checking code with AST rule."""

        def simple_checker(tree):
            # Return line 1 always
            return [1]

        engine = CustomRuleEngine()
        engine.add_ast_rule(
            rule_id="AST001",
            name="AST Test",
            checker=simple_checker,
            description="Test",
        )

        code = "x = 1"
        violations = engine.check_code(code)

        assert len(violations) == 1
        assert violations[0].line_number == 1

    def test_check_code_with_syntax_error(self):
        """Test checking code with syntax error."""
        engine = CustomRuleEngine()
        engine.add_regex_rule("TEST", "Test", r"test")

        code = "def broken("
        violations = engine.check_code(code)

        assert len(violations) == 0  # Should handle gracefully


class TestASTCheckerFunctions:
    """Test built-in AST checker functions."""

    def test_check_no_global_variables(self):
        """Test global variable checker."""
        code = """
x = 1
y = 2
"""
        import ast

        tree = ast.parse(code)
        lines = check_no_global_variables(tree)

        # Should detect global assignments
        assert len(lines) > 0

    def test_check_function_length(self):
        """Test function length checker."""
        # Create a very long function
        code = "def long_func():\n" + "    x = 1\n" * 60

        import ast

        tree = ast.parse(code)
        lines = check_function_length(tree, max_lines=50)

        assert len(lines) > 0


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_create_rule_engine_from_config(self, tmp_path):
        """Test creating engine from config file."""
        config_file = tmp_path / "rules.toml"
        config_file.write_text(
            """
[[rules]]
rule_id = "TEST001"
name = "Test"
severity = "HIGH"
category = "Test"
description = "Test rule"
"""
        )

        engine = create_rule_engine_from_config(str(config_file))

        assert isinstance(engine, CustomRuleEngine)
        assert len(engine.rules) > 0
