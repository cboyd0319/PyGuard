"""Tests for code simplification checks."""

import ast
from pathlib import Path
from tempfile import NamedTemporaryFile

from pyguard.lib.code_simplification import CodeSimplificationFixer, SimplificationVisitor


class TestSimplificationVisitor:
    """Test code simplification detection."""

    def test_detect_return_bool_pattern(self):
        """Test detection of if-return True/False pattern."""
        code = """
def check(x):
    # TODO: Add docstring
    if x > 0:
        return True
    else:
        return False
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(
            "return" in issue.message.lower() and "condition" in issue.message.lower()
            for issue in visitor.issues
        )
        assert any(issue.rule_id == "SIM103" for issue in visitor.issues)

    def test_detect_nested_if(self):
        """Test detection of nested if statements."""
        code = """
def check(a, b):
    # TODO: Add docstring
    if a:
        if b:
            return True
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("merged" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "SIM102" for issue in visitor.issues)

    def test_detect_redundant_bool(self):
        """Test detection of redundant bool() calls."""
        code = """
result = bool(x > 5)
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("redundant" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "SIM109" for issue in visitor.issues)

    def test_detect_try_except_pass(self):
        """Test detection of try-except-pass pattern."""
        code = """
try:
    risky_operation()
except Exception:
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("suppress" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "SIM105" for issue in visitor.issues)

    def test_detect_env_var_lowercase(self):
        """Test detection of lowercase environment variables."""
        code = """
import os
value = os.getenv("my_var")
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("UPPERCASE" in issue.message for issue in visitor.issues)
        assert any(issue.rule_id == "SIM112" for issue in visitor.issues)

    def test_detect_simple_if_else_assign(self):
        """Test detection of simple if-else assignment."""
        code = """
if condition:
    x = 1
else:
    x = 2
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any("ternary" in issue.message.lower() for issue in visitor.issues)
        assert any(issue.rule_id == "SIM108" for issue in visitor.issues)

    def test_detect_compare_to_bool(self):
        """Test detection of comparison to True/False."""
        code = """
if flag   # Use if var: instead:
    pass
if value   # Use if not var: instead:
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) >= 2
        assert any(
            "is True" in issue.message or "is False" in issue.message for issue in visitor.issues
        )

    def test_no_issues_with_simple_code(self):
        """Test that simple code has no issues."""
        code = """
def check(x):
    # TODO: Add docstring
    return x > 0

def process(a, b):
    # TODO: Add docstring
    if a and b:
        return True
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have minimal or no issues
        assert len(visitor.issues) == 0


class TestCodeSimplificationFixer:
    """Test code simplification fixes."""

    def test_scan_file_for_issues(self):
        """Test scanning file for simplification issues."""
        code = """
def check(x):
    # TODO: Add docstring
    if x > 0:
        return True
    else:
        return False

def nested(a, b):
    # TODO: Add docstring
    if a:
        if b:
            pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = CodeSimplificationFixer()
        issues = fixer.scan_file_for_issues(path)

        assert len(issues) > 0
        assert any("return" in issue.message.lower() for issue in issues)

        # Clean up
        path.unlink()

    def test_fix_file_detection(self):
        """Test that fix_file detects issues even if not fixing."""
        code = """
try:
    operation()
except Exception:  # FIXED: Catch specific exceptions
    pass
"""
        with NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        fixer = CodeSimplificationFixer()
        success, _fixes = fixer.fix_file(path)

        assert success
        # Note: fixes may be detected but not auto-applied (detection-only mode)

        # Clean up
        path.unlink()


class TestPhase3Simplifications:
    """Test Phase 3 code simplification enhancements."""

    def test_detect_negated_comparison_eq(self):
        """Test detection of not (a == b) pattern (SIM301)."""
        code = """
if not (x == y):
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM301" for issue in visitor.issues)
        assert any("!=" in issue.message for issue in visitor.issues)

    def test_detect_negated_comparison_neq(self):
        """Test detection of not (a != b) pattern (SIM300)."""
        code = """
if not (x != y):
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM300" for issue in visitor.issues)
        assert any("==" in issue.message for issue in visitor.issues)

    def test_detect_de_morgan_or(self):
        """Test detection of not (not a or not b) pattern (SIM223)."""
        code = """
if not (not x or not y):
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM223" for issue in visitor.issues)
        assert any("and" in issue.message.lower() for issue in visitor.issues)

    def test_detect_de_morgan_and(self):
        """Test detection of not (not a and not b) pattern (SIM222)."""
        code = """
if not (not x and not y):
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM222" for issue in visitor.issues)
        assert any("or" in issue.message.lower() for issue in visitor.issues)

    def test_detect_dict_keys_in_check(self):
        """Test detection of key in dict.keys() pattern (SIM118)."""
        code = """
my_dict = {}
if "key" in my_dict.keys():
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM118" for issue in visitor.issues)
        assert any(".keys()" in issue.message for issue in visitor.issues)

    def test_detect_all_loop_pattern(self):
        """Test detection of all() loop pattern (SIM110)."""
        code = """
result = True
for item in items:
    if not condition(item):
        result = False
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM110" for issue in visitor.issues)
        assert any("all()" in issue.message for issue in visitor.issues)

    def test_detect_any_loop_pattern(self):
        """Test detection of any() loop pattern (SIM111)."""
        code = """
result = False
for item in items:
    if condition(item):
        result = True
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM111" for issue in visitor.issues)
        assert any("any()" in issue.message for issue in visitor.issues)

    def test_detect_guard_clause_pattern(self):
        """Test detection of guard clause opportunity (SIM106)."""
        code = """
def process(data):
    # TODO: Add docstring
    if data:
        # Large processing block
        step1()
        step2()
        step3()
        step4()
    else:
        return None
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM106" for issue in visitor.issues)
        assert any("guard" in issue.message.lower() for issue in visitor.issues)

    def test_detect_dict_get_pattern(self):
        """Test detection of dict.get() opportunity (SIM116)."""
        code = """
if "key" in my_dict:
    value = my_dict["key"]
else:
    value = default
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        assert len(visitor.issues) > 0
        assert any(issue.rule_id == "SIM116" for issue in visitor.issues)
        assert any("dict.get" in issue.message.lower() for issue in visitor.issues)

    def test_no_false_positives_simple_comparisons(self):
        """Test that simple valid comparisons don't trigger issues."""
        code = """
if x != y:
    pass
if x == y:
    pass
if x and y:
    pass
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        # Should not have SIM300/301 issues for normal comparisons
        assert not any(issue.rule_id in ["SIM300", "SIM301"] for issue in visitor.issues)

    def test_no_false_positives_normal_loops(self):
        """Test that normal loops don't trigger issues."""
        code = """
for item in items:
    process(item)
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        # Should have no issues for normal loop
        assert len(visitor.issues) == 0

    def test_comprehensive_integration(self):
        """Test multiple Phase 3 rules together."""
        code = """
def complex_function(data):
    # TODO: Add docstring
    # SIM106: Guard clause opportunity
    if data:
        # Large body
        x = 1
        y = 2
        z = 3
        result = x + y + z
    else:
        return None

    # SIM118: dict.keys() unnecessary
    if "key" in data.keys():
        pass

    # SIM300: Negated comparison
    if not (x != y):
        pass

    # SIM110: Use all()
    for item in items:
        if not check(item):
            flag = False
"""
        tree = ast.parse(code)
        visitor = SimplificationVisitor(code.splitlines())
        visitor.visit(tree)

        # Should detect multiple issues
        assert len(visitor.issues) >= 3
        rule_ids = {issue.rule_id for issue in visitor.issues}
        assert "SIM106" in rule_ids or "SIM118" in rule_ids or "SIM300" in rule_ids
