"""
Unit tests for comprehensions module.
"""

import pytest
from pyguard.lib.comprehensions import ComprehensionChecker, ComprehensionVisitor


class TestComprehensionChecker:
    """Tests for ComprehensionChecker class."""

    def test_initialization(self):
        """Test checker initializes properly."""
        checker = ComprehensionChecker()
        assert checker is not None
        rules = checker.get_rules()
        assert len(rules) == 14
        assert all(rule.rule_id.startswith("C4") for rule in rules)

    def test_check_code_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        checker = ComprehensionChecker()
        code = "def foo(\n  invalid syntax"
        violations = checker.check_code(code)
        assert len(violations) == 0


class TestC400:
    """Tests for C400: Unnecessary generator - use list comprehension."""

    def test_detect_list_generator(self):
        """Test detection of list(generator)."""
        code = "result = list(x for x in range(10))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C400" for v in violations)

    def test_allow_list_comprehension(self):
        """Test that list comprehension is allowed."""
        code = "result = [x for x in range(10)]"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C400" for v in violations)


class TestC401:
    """Tests for C401: Unnecessary generator - use set comprehension."""

    def test_detect_set_generator(self):
        """Test detection of set(generator)."""
        code = "result = set(x for x in range(10))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C401" for v in violations)

    def test_allow_set_comprehension(self):
        """Test that set comprehension is allowed."""
        code = "result = {x for x in range(10)}"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C401" for v in violations)


class TestC402:
    """Tests for C402: Unnecessary generator - use dict comprehension."""

    def test_detect_dict_generator(self):
        """Test detection of dict(generator)."""
        code = "result = dict((k, v) for k, v in items)"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C402" for v in violations)


class TestC403:
    """Tests for C403: Unnecessary list comprehension - use set comprehension."""

    def test_detect_set_list_comprehension(self):
        """Test detection of set([...])."""
        code = "result = set([x for x in range(10)])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C403" for v in violations)


class TestC404:
    """Tests for C404: Unnecessary list comprehension - use dict comprehension."""

    def test_detect_dict_list_comprehension(self):
        """Test detection of dict([...])."""
        code = "result = dict([(k, v) for k, v in items])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C404" for v in violations)


class TestC405:
    """Tests for C405: Unnecessary list literal - use set literal."""

    def test_detect_set_list_literal(self):
        """Test detection of set([...])."""
        code = "result = set([1, 2, 3, 4])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C405" for v in violations)

    def test_allow_set_literal(self):
        """Test that set literal is allowed."""
        code = "result = {1, 2, 3, 4}"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C405" for v in violations)


class TestC406:
    """Tests for C406: Unnecessary list literal - use dict literal."""

    def test_detect_dict_list_literal(self):
        """Test detection of dict([...])."""
        code = "result = dict([('a', 1), ('b', 2)])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C406" for v in violations)


class TestC408:
    """Tests for C408: Unnecessary collection call - use literal."""

    def test_detect_empty_dict_call(self):
        """Test detection of dict()."""
        code = "result = dict()"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C408" for v in violations)

    def test_detect_empty_list_call(self):
        """Test detection of list()."""
        code = "result = list()"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C408" for v in violations)

    def test_detect_empty_tuple_call(self):
        """Test detection of tuple()."""
        code = "result = tuple()"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C408" for v in violations)

    def test_allow_dict_with_args(self):
        """Test that dict() with arguments is allowed."""
        code = "result = dict(a=1, b=2)"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C408" for v in violations)


class TestC409:
    """Tests for C409: Unnecessary list passed to tuple()."""

    def test_detect_tuple_list(self):
        """Test detection of tuple([...])."""
        code = "result = tuple([1, 2, 3])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C409" for v in violations)

    def test_allow_tuple_literal(self):
        """Test that tuple literal is allowed."""
        code = "result = (1, 2, 3)"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C409" for v in violations)


class TestC410:
    """Tests for C410: Unnecessary list passed to list()."""

    def test_detect_list_list(self):
        """Test detection of list([...])."""
        code = "result = list([1, 2, 3])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C410" for v in violations)


class TestC411:
    """Tests for C411: Unnecessary list() around sorted()."""

    def test_detect_list_sorted(self):
        """Test detection of list(sorted(...))."""
        code = "result = list(sorted(items))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C411" for v in violations)

    def test_allow_sorted_directly(self):
        """Test that sorted() without list() is allowed."""
        code = "result = sorted(items)"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert not any(v.rule_id == "C411" for v in violations)


class TestC413:
    """Tests for C413: Unnecessary call around sorted()."""

    def test_detect_sorted_reversed(self):
        """Test detection of sorted(reversed(...))."""
        code = "result = sorted(reversed(items))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C413" for v in violations)

    def test_detect_sorted_list(self):
        """Test detection of sorted(list(...))."""
        code = "result = sorted(list(items))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C413" for v in violations)


class TestC414:
    """Tests for C414: Unnecessary inner call."""

    def test_detect_set_list(self):
        """Test detection of set(list(...))."""
        code = "result = set(list(items))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C414" for v in violations)

    def test_detect_sorted_sorted(self):
        """Test detection of sorted(sorted(...))."""
        code = "result = sorted(sorted(items))"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C414" for v in violations)


class TestC416:
    """Tests for C416: Unnecessary comprehension."""

    def test_detect_unnecessary_list_comprehension(self):
        """Test detection of list([x for x in ...])."""
        code = "result = list([x for x in items])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert any(v.rule_id == "C416" for v in violations)

    def test_allow_transformation_comprehension(self):
        """Test that comprehension with transformation is allowed."""
        code = "result = list([x * 2 for x in items])"
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        # Should not trigger C416 because there's transformation
        c416_violations = [v for v in violations if v.rule_id == "C416"]
        assert len(c416_violations) == 0


class TestComprehensionRules:
    """Tests for rule definitions."""

    def test_rules_exist(self):
        """Test that all expected rules exist."""
        checker = ComprehensionChecker()
        rules = checker.get_rules()
        rule_ids = {rule.rule_id for rule in rules}
        expected = {
            "C400",
            "C401",
            "C402",
            "C403",
            "C404",
            "C405",
            "C406",
            "C408",
            "C409",
            "C410",
            "C411",
            "C413",
            "C414",
            "C416",
        }
        assert rule_ids == expected

    def test_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        checker = ComprehensionChecker()
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
        checker = ComprehensionChecker()
        rules = checker.get_rules()
        rule_ids = [rule.rule_id for rule in rules]
        assert len(rule_ids) == len(set(rule_ids))


class TestIntegration:
    """Integration tests for comprehensions."""

    def test_multiple_violations(self):
        """Test detection of multiple comprehension violations."""
        code = """
# C400
result1 = list(x for x in range(10))
# C408
result2 = dict()
# C410
result3 = list([1, 2, 3])
"""
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert len(violations) >= 3

    def test_no_false_positives(self):
        """Test that clean code produces no violations."""
        code = """
# Good comprehensions
result1 = [x for x in range(10)]
result2 = {x for x in range(10)}
result3 = {k: v for k, v in items.items()}
result4 = {}
result5 = []
"""
        checker = ComprehensionChecker()
        violations = checker.check_code(code)
        assert len(violations) == 0
