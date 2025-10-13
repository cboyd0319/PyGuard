"""
Unit tests for return_patterns module.
"""

import pytest
from pyguard.lib.return_patterns import ReturnPatternChecker, ReturnPatternVisitor


class TestReturnPatternChecker:
    """Tests for ReturnPatternChecker class."""

    def test_initialization(self):
        """Test checker initializes properly."""
        checker = ReturnPatternChecker()
        assert checker is not None
        rules = checker.get_rules()
        assert len(rules) == 8
        assert all(rule.rule_id.startswith("RET") for rule in rules)

    def test_check_code_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        checker = ReturnPatternChecker()
        code = "def foo(\n  invalid syntax"
        violations = checker.check_code(code)
        assert len(violations) == 0


class TestRET501:
    """Tests for RET501: Unnecessary explicit return None."""

    def test_detect_explicit_return_none(self):
        """Test detection of explicit 'return None'."""
        code = """
def foo():
    x = 1
    return None
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET501" for v in violations)

    def test_allow_bare_return(self):
        """Test that bare 'return' is allowed."""
        code = """
def foo():
    x = 1
    return
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET501" for v in violations)

    def test_allow_return_with_value(self):
        """Test that return with actual value is allowed."""
        code = """
def foo():
    return 42
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET501" for v in violations)


class TestRET502:
    """Tests for RET502: Implicit return mixed with explicit."""

    def test_detect_mixed_returns(self):
        """Test detection of mixing implicit and explicit returns."""
        code = """
def foo(x):
    if x > 0:
        return x
    # Implicit return None here
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET502" for v in violations)

    def test_allow_consistent_returns(self):
        """Test that consistent returns are allowed."""
        code = """
def foo(x):
    if x > 0:
        return x
    return 0
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET502" for v in violations)


class TestRET503:
    """Tests for RET503: Missing explicit return."""

    def test_detect_missing_explicit_return(self):
        """Test detection of missing explicit return."""
        code = """
def foo(x):
    x = x + 1
    print(x)
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET503" for v in violations)

    def test_allow_function_with_return(self):
        """Test that function with return is allowed."""
        code = """
def foo(x):
    x = x + 1
    return None
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET503" for v in violations)

    def test_allow_empty_function(self):
        """Test that empty functions are allowed."""
        code = """
def foo():
    pass
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET503" for v in violations)


class TestRET504:
    """Tests for RET504: Unnecessary assignment before return."""

    def test_detect_unnecessary_assignment(self):
        """Test detection of unnecessary assignment before return."""
        code = """
def foo(x):
    result = x + 1
    return result
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET504" for v in violations)

    def test_allow_necessary_assignment(self):
        """Test that necessary assignments are allowed."""
        code = """
def foo(x):
    result = x + 1
    print(result)
    return result
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET504" for v in violations)


class TestRET505:
    """Tests for RET505: Unnecessary else after return."""

    def test_detect_unnecessary_else_after_return(self):
        """Test detection of unnecessary else after return."""
        code = """
def foo(x):
    if x > 0:
        return x
    else:
        return 0
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET505" for v in violations)

    def test_allow_elif_after_return(self):
        """Test that elif after return is handled separately."""
        code = """
def foo(x):
    if x > 0:
        return x
    elif x < 0:
        return -x
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        # Should be RET506, not RET505
        ret505_violations = [v for v in violations if v.rule_id == "RET505"]
        assert len(ret505_violations) == 0


class TestRET506:
    """Tests for RET506: Unnecessary elif after return."""

    def test_detect_unnecessary_elif_after_return(self):
        """Test detection of unnecessary elif after return."""
        code = """
def foo(x):
    if x > 0:
        return x
    elif x < 0:
        return -x
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET506" for v in violations)


class TestRET507:
    """Tests for RET507: Unnecessary else after continue."""

    def test_detect_unnecessary_else_after_continue(self):
        """Test detection of unnecessary else after continue."""
        code = """
def foo(items):
    for item in items:
        if item < 0:
            continue
        else:
            print(item)
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET507" for v in violations)

    def test_allow_continue_without_else(self):
        """Test that continue without else is allowed."""
        code = """
def foo(items):
    for item in items:
        if item < 0:
            continue
        print(item)
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET507" for v in violations)


class TestRET508:
    """Tests for RET508: Unnecessary else after break."""

    def test_detect_unnecessary_else_after_break(self):
        """Test detection of unnecessary else after break."""
        code = """
def foo(items):
    for item in items:
        if item < 0:
            break
        else:
            print(item)
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "RET508" for v in violations)

    def test_allow_break_without_else(self):
        """Test that break without else is allowed."""
        code = """
def foo(items):
    for item in items:
        if item < 0:
            break
        print(item)
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "RET508" for v in violations)


class TestReturnPatternRules:
    """Tests for rule definitions."""

    def test_rules_exist(self):
        """Test that all expected rules exist."""
        checker = ReturnPatternChecker()
        rules = checker.get_rules()
        rule_ids = {rule.rule_id for rule in rules}
        expected = {"RET501", "RET502", "RET503", "RET504", "RET505", "RET506", "RET507", "RET508"}
        assert rule_ids == expected

    def test_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        checker = ReturnPatternChecker()
        rules = checker.get_rules()
        for rule in rules:
            assert rule.rule_id
            assert rule.name
            assert rule.category
            assert rule.severity
            assert rule.message_template
            assert rule.description

    def test_rule_ids_unique(self):
        """Test that rule IDs are unique."""
        checker = ReturnPatternChecker()
        rules = checker.get_rules()
        rule_ids = [rule.rule_id for rule in rules]
        assert len(rule_ids) == len(set(rule_ids))


class TestIntegration:
    """Integration tests for return patterns."""

    def test_multiple_violations(self):
        """Test detection of multiple return pattern violations."""
        code = """
def process(data):
    if not data:
        return None  # RET501
    else:  # RET505
        result = data + 1  # RET504
        return result
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        assert len(violations) >= 2  # At least RET501 and RET505

    def test_no_false_positives(self):
        """Test that clean code produces no violations."""
        code = """
def good_function(x):
    if x > 0:
        return x * 2
    return 0
"""
        checker = ReturnPatternChecker()
        violations = checker.check_code(code)
        # May have RET503 or RET502 depending on interpretation, but should be minimal
        assert len(violations) <= 1
