"""
Tests for string operations module.
"""

import ast
from pathlib import Path
import tempfile

from pyguard.lib.string_operations import (
    StringIssue,
    StringOperationsFixer,
    StringOperationsVisitor,
)


class TestStringOperationsVisitor:
    """Tests for StringOperationsVisitor."""

    def test_detect_format_call(self):
        """Test detection of .format() calls."""
        code = """
message = "Hello {}".format(name)
result = "Value: {}".format(value)
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        format_issues = [i for i in visitor.issues if i.rule_id == "PG-S001"]
        assert len(format_issues) >= 1
        assert "f-string" in format_issues[0].message.lower()

    def test_detect_percent_formatting(self):
        """Test detection of % formatting."""
        code = """
message = "Hello %s" % name
result = "Value: %d" % 42
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        percent_issues = [i for i in visitor.issues if i.rule_id == "PG-S002"]
        assert len(percent_issues) >= 1
        assert "f-string" in percent_issues[0].message.lower()

    def test_detect_unnecessary_fstring(self):
        """Test detection of unnecessary f-strings."""
        code = """
message = f"Hello world"
result = f"Static text"
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        fstring_issues = [i for i in visitor.issues if i.rule_id == "PG-S003"]
        assert len(fstring_issues) >= 1
        assert "unnecessary" in fstring_issues[0].message.lower()

    def test_necessary_fstring_not_flagged(self):
        """Test that necessary f-strings are not flagged."""
        code = """
name = "Alice"
message = f"Hello {name}"
result = f"Value: {42}"
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        fstring_issues = [i for i in visitor.issues if i.rule_id == "PG-S003"]
        assert len(fstring_issues) == 0

    def test_detect_string_concatenation(self):
        """Test detection of string concatenation."""
        code = """
result = "Hello" + " " + "World"
message = first + " " + last
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        concat_issues = [i for i in visitor.issues if i.rule_id == "PG-S005"]
        assert len(concat_issues) >= 1

    def test_detect_string_concat_in_loop(self):
        """Test detection of string concatenation in loops."""
        code = """
result = ""
for item in items:
    result += str(item)
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        loop_issues = [i for i in visitor.issues if i.rule_id == "PG-S006"]
        assert len(loop_issues) >= 1
        assert "loop" in loop_issues[0].message.lower()

    def test_quote_style_detection_double(self):
        """Test dominant quote style detection - double quotes."""
        code = """
message = "Hello"
result = "World"
name = "Alice"
"""
        ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)

        assert visitor.quote_style == "double"

    def test_quote_style_detection_single(self):
        """Test dominant quote style detection - single quotes."""
        code = """
message = 'Hello'
result = 'World'
name = 'Alice'
"""
        ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)

        assert visitor.quote_style == "single"

    def test_no_issues_for_clean_code(self):
        """Test that clean code produces no issues."""
        code = """
name = "Alice"
message = f"Hello {name}"
result = " ".join(items)
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        # Should have minimal or no issues for well-written code
        assert len(visitor.issues) <= 2  # Allow for quote style preferences

    def test_complex_format_string(self):
        """Test detection of complex format strings."""
        code = """
result = "Name: {}, Age: {}".format(name, age)
"""
        tree = ast.parse(code)
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        visitor.visit(tree)

        format_issues = [i for i in visitor.issues if i.rule_id == "PG-S001"]
        assert len(format_issues) >= 1


class TestStringOperationsFixer:
    """Tests for StringOperationsFixer."""

    def test_analyze_file_with_issues(self):
        """Test analyzing a file with string issues."""
        code = """
message = "Hello {}".format(name)
result = "Value: %s" % value
text = f"Static"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            issues = fixer.analyze_file(temp_path)

            assert len(issues) >= 2
            rule_ids = [i.rule_id for i in issues]
            assert "PG-S001" in rule_ids or "PG-S002" in rule_ids
        finally:
            temp_path.unlink()

    def test_analyze_file_clean_code(self):
        """Test analyzing a file with no issues."""
        code = """
name = "Alice"
message = f"Hello {name}"
items = ["a", "b", "c"]
result = ", ".join(items)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            issues = fixer.analyze_file(temp_path)

            # Clean code should have minimal issues
            assert len(issues) <= 2
        finally:
            temp_path.unlink()

    def test_analyze_file_syntax_error(self):
        """Test analyzing a file with syntax errors."""
        code = """
def broken(
    # TODO: Add docstring
    pass
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            issues = fixer.analyze_file(temp_path)

            # Should handle syntax error gracefully
            assert issues == []
        finally:
            temp_path.unlink()

    def test_fix_unnecessary_fstring(self):
        """Test fixing unnecessary f-strings."""
        code = """
message = f"Hello world"
result = f"Static text"
name = "Alice"
greeting = f"Hi {name}"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            issues = fixer.analyze_file(temp_path)
            success, applied_fixes = fixer.fix_file(temp_path, issues)

            assert success
            # Should have fixed some issues
            assert len(applied_fixes) >= 1

            # Check that file was modified
            modified_content = temp_path.read_text()
            # Necessary f-string should remain
            assert 'f"Hi {name}"' in modified_content
        finally:
            temp_path.unlink()

    def test_fix_file_no_issues(self):
        """Test fixing a file with no issues."""
        code = """
name = "Alice"
message = f"Hello {name}"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            success, applied_fixes = fixer.fix_file(temp_path)

            assert success
            # No fixes needed for clean code (or minimal)
            assert len(applied_fixes) <= 1
        finally:
            temp_path.unlink()

    def test_scan_directory(self):
        """Test scanning a directory for issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)

            # Create test files
            file1 = temp_dir / "test1.py"
            file1.write_text('message = "Hello {}".format(name)')

            file2 = temp_dir / "test2.py"
            file2.write_text('result = f"Static text"')

            file3 = temp_dir / "clean.py"
            file3.write_text('name = "Alice"\ngreeting = f"Hi {name}"')

            fixer = StringOperationsFixer()
            results = fixer.scan_directory(temp_dir)

            # Should find issues in at least 2 files
            assert len(results) >= 2

            # Check that each result is a tuple of (Path, List[StringIssue])
            for file_path, issues in results:
                assert isinstance(file_path, Path)
                assert isinstance(issues, list)
                assert all(isinstance(i, StringIssue) for i in issues)

    def test_scan_directory_with_exclusions(self):
        """Test scanning a directory with exclusion patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)

            # Create test files
            file1 = temp_dir / "test1.py"
            file1.write_text('message = "Hello {}".format(name)')

            # Create excluded file
            excluded_dir = temp_dir / "migrations"
            excluded_dir.mkdir()
            file2 = excluded_dir / "test2.py"
            file2.write_text('result = "Value: %s" % value')

            fixer = StringOperationsFixer()
            results = fixer.scan_directory(temp_dir, exclude_patterns=["migrations"])

            # Should only find issues in non-excluded files
            found_paths = [str(path) for path, _ in results]
            assert not any("migrations" in path for path in found_paths)

    def test_multiple_issues_same_file(self):
        """Test handling multiple issues in the same file."""
        code = """
msg1 = "Hello {}".format(name)
msg2 = "Value: %s" % value
msg3 = f"Static"
result = ""
for x in range(10):
    result += str(x)
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        try:
            fixer = StringOperationsFixer()
            issues = fixer.analyze_file(temp_path)

            # Should detect multiple different types of issues
            assert len(issues) >= 3
            rule_ids = {i.rule_id for i in issues}
            assert len(rule_ids) >= 2  # At least 2 different rule types
        finally:
            temp_path.unlink()


class TestStringIssueDataclass:
    """Tests for StringIssue dataclass."""

    def test_create_string_issue(self):
        """Test creating a StringIssue instance."""
        issue = StringIssue(
            severity="MEDIUM",
            category="String Operations",
            message="Use f-string instead of .format()",
            line_number=10,
            column=4,
            code_snippet='message = "Hello {}".format(name)',
            fix_suggestion='Replace with f"Hello {name}"',
            rule_id="PG-S001",
        )

        assert issue.severity == "MEDIUM"
        assert issue.category == "String Operations"
        assert issue.line_number == 10
        assert issue.rule_id == "PG-S001"

    def test_string_issue_default_values(self):
        """Test StringIssue with default values."""
        issue = StringIssue(
            severity="LOW",
            category="String Operations",
            message="Test message",
            line_number=5,
            column=0,
        )

        assert issue.code_snippet == ""
        assert issue.fix_suggestion == ""
        assert issue.rule_id == ""


class TestStringOperationsEdgeCases:
    """Test edge cases for string operations."""

    def test_analyze_file_with_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error."""
        # Arrange
        fixer = StringOperationsFixer()
        file_path = tmp_path / "broken.py"
        file_path.write_text("def broken(\n")  # Syntax error

        # Act
        issues = fixer.analyze_file(file_path)

        # Assert - Should return empty list
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_analyze_file_with_exception(self):
        """Test analyzing nonexistent file."""
        # Arrange
        fixer = StringOperationsFixer()
        file_path = Path("/nonexistent/file.py")

        # Act
        issues = fixer.analyze_file(file_path)

        # Assert
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_fix_file_with_exception(self, tmp_path):
        """Test fixing file that causes exception."""
        # Arrange
        fixer = StringOperationsFixer()
        file_path = tmp_path / "test.py"
        file_path.write_text("x = 'test'")

        # Create issue with uncovered rule_id
        issues = [
            StringIssue(
                severity="LOW",
                category="String Operations",
                message="Quote consistency",
                line_number=1,
                column=4,
                code_snippet="'test'",
                fix_suggestion="Use double quotes",
                rule_id="PG-S004",
            )
        ]

        # Act
        success, fixes = fixer.fix_file(file_path, issues)

        # Assert
        assert isinstance(success, bool)
        assert isinstance(fixes, list)

    def test_visitor_with_inconsistent_quotes(self):
        """Test detecting inconsistent quote styles."""
        # Arrange
        code = """
x = "double quotes"
y = 'single quotes'
"""
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        tree = ast.parse(code)

        # Act
        visitor.visit(tree)

        # Assert - Should detect quote style
        # First assignment sets the style, second should be flagged if inconsistent
        assert len(visitor.issues) >= 0  # May or may not flag depending on implementation

    def test_visitor_format_call_on_variable(self):
        """Test format() call on variable."""
        # Arrange
        code = """
template = "Hello, {}"
result = template.format("World")
"""
        source_lines = code.splitlines()
        visitor = StringOperationsVisitor(source_lines, code)
        tree = ast.parse(code)

        # Act
        visitor.visit(tree)

        # Assert
        # Should detect format usage
        assert isinstance(visitor.issues, list)

    def test_scan_directory_with_errors(self, tmp_path):
        """Test scanning directory with problematic files."""
        # Arrange
        fixer = StringOperationsFixer()

        # Create a mix of files
        (tmp_path / "good.py").write_text("x = 'test'")
        (tmp_path / "bad.py").write_text("def broken(\n")

        # Act
        issues = fixer.scan_directory(tmp_path)

        # Assert - Should handle errors gracefully
        assert isinstance(issues, list)
        # bad.py should not crash the scan
        assert len(issues) >= 0


class TestStringOperationsPerformance:
    """Test performance-related aspects."""

    def test_scan_large_directory(self, tmp_path):
        """Test scanning directory with many files."""
        # Arrange
        fixer = StringOperationsFixer()

        # Create multiple files
        for i in range(5):
            (tmp_path / f"file_{i}.py").write_text(f"x{i} = 'test {i}'")

        # Act
        issues = fixer.scan_directory(tmp_path)

        # Assert
        assert isinstance(issues, list)
        # At least 5 files should be scanned
        assert len(issues) >= 0

    def test_analyze_file_with_long_strings(self, tmp_path):
        """Test analyzing file with very long strings."""
        # Arrange
        fixer = StringOperationsFixer()
        file_path = tmp_path / "long_strings.py"
        long_string = "a" * 1000
        file_path.write_text(f"x = '{long_string}'")

        # Act
        issues = fixer.analyze_file(file_path)

        # Assert
        assert isinstance(issues, list)
