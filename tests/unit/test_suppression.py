"""
Tests for suppression comment support in PyGuard.
"""

import ast

from pyguard.lib.ast_analyzer import CodeQualityVisitor, SecurityVisitor


def test_security_visitor_suppression_generic():
    """Test that generic # pyguard: disable suppresses all issues."""
    code = """eval("1 + 1")  # pyguard: disable  # DANGEROUS: Avoid eval with untrusted input
exec("pass")   # noqa  # DANGEROUS: Avoid exec with untrusted input
compile("pass", "<string>", "exec")  # DANGEROUS: Avoid compile with untrusted input
"""

    source_lines = code.split("\n")
    tree = ast.parse(code)
    visitor = SecurityVisitor(source_lines)
    visitor.visit(tree)

    # First two should be suppressed, third should be detected
    assert len(visitor.issues) == 1
    assert "compile" in visitor.issues[0].message.lower()


def test_security_visitor_suppression_specific():
    """Test that specific rule suppression works."""
    code = """eval("1 + 1")  # pyguard: disable=CWE-95  # DANGEROUS: Avoid eval with untrusted input
exec("pass")   # noqa: CWE-95  # DANGEROUS: Avoid exec with untrusted input
compile("pass", "<string>", "exec")  # DANGEROUS: Avoid compile with untrusted input
"""

    source_lines = code.split("\n")
    tree = ast.parse(code)
    visitor = SecurityVisitor(source_lines)
    visitor.visit(tree)

    # First two should be suppressed, third should be detected
    assert len(visitor.issues) == 1
    assert "compile" in visitor.issues[0].message.lower()


def test_security_visitor_no_suppression():
    """Test that issues are detected when no suppression comment."""
    code = """eval("1 + 1")  # DANGEROUS: Avoid eval with untrusted input
exec("pass")  # DANGEROUS: Avoid exec with untrusted input
"""

    source_lines = code.split("\n")
    tree = ast.parse(code)
    visitor = SecurityVisitor(source_lines)
    visitor.visit(tree)

    # Both should be detected
    assert len(visitor.issues) == 2


def test_code_quality_visitor_suppression():
    """Test that code quality visitor respects suppression comments."""
    code = """def test_function():  # pyguard: disable=DOCUMENTATION
    pass

def another_function():  # noqa
    # TODO: Add docstring
    pass

def third_function():
    # TODO: Add docstring
    pass
"""

    source_lines = code.split("\n")
    tree = ast.parse(code)
    visitor = CodeQualityVisitor(source_lines)
    visitor.visit(tree)

    # Only third function should have documentation issue
    doc_issues = [i for i in visitor.issues if i.category == "Documentation"]
    assert len(doc_issues) == 1
    assert "third_function" in doc_issues[0].message


def test_suppression_wrong_rule():
    """Test that suppressing wrong rule doesn't suppress the actual issue."""
    code = """eval("1 + 1")  # pyguard: disable=CWE-89  # DANGEROUS: Avoid eval with untrusted input
"""

    source_lines = code.split("\n")
    tree = ast.parse(code)
    visitor = SecurityVisitor(source_lines)
    visitor.visit(tree)

    # Should still be detected (CWE-95, not CWE-89)
    assert len(visitor.issues) == 1
    assert visitor.issues[0].cwe_id == "CWE-95"
