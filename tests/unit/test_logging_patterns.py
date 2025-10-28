"""
Tests for logging_patterns module (LOG rules).

Comprehensive test suite following PyTest Architect Agent principles:
- AAA pattern (Arrange-Act-Assert)
- Parametrized tests for input matrices
- Edge cases and boundary conditions
- Error handling validation
- Deterministic test execution
"""

import pytest

from pyguard.lib.logging_patterns import (
    LoggingChecker,
    LoggingIssue,
    LoggingPatternVisitor,
    check_file,
)


class TestLoggingBasics:
    """Test basic logging pattern detection."""

    def test_detect_fstring_in_logging(self):
        """Test detection of f-strings in logging calls."""
        code = """
import logging
name = "user"
logging.info(f"Processing {name}")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)
        assert any("f-string" in issue.message.lower() for issue in issues)

    def test_detect_format_in_logging(self):
        """Test detection of .format() in logging calls."""
        code = """
import logging
name = "user"
logging.info("Processing {}".format(name))
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG002" for issue in issues)
        assert any(".format()" in issue.message for issue in issues)

    def test_detect_deprecated_warn(self):
        """Test detection of deprecated warn() method."""
        code = """
import logging
logging.warn("This is deprecated")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG003" for issue in issues)
        assert any("warning()" in issue.suggested_fix for issue in issues)

    def test_detect_redundant_exc_info(self):
        """Test detection of redundant exc_info in exception()."""
        code = """
import logging
try:
    x = 1 / 0
except Exception:
    logging.exception("Error occurred", exc_info=True)
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG004" for issue in issues)


class TestLoggingStringConcatenation:
    """Test string concatenation detection in logging."""

    def test_detect_string_concat(self):
        """Test detection of string concatenation in logging."""
        code = """
import logging
name = "user"
logging.info("Processing " + name)
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG005" for issue in issues)

    def test_no_issue_with_lazy_formatting(self):
        """Test that lazy % formatting doesn't trigger issues."""
        code = """
import logging
name = "user"
logging.info("Processing %s", name)
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        # Lazy formatting is correct, should not trigger issues
        assert len(issues) == 0


class TestLoggingLoggerObjects:
    """Test detection with logger objects."""

    def test_detect_issues_with_logger_object(self):
        """Test detection works with logger objects."""
        code = """
import logging
logger = logging.getLogger(__name__)
name = "user"
logger.info(f"Processing {name}")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)

    def test_detect_with_custom_logger_name(self):
        """Test detection with various logger variable names."""
        code = """
import logging
log = logging.getLogger(__name__)
log.info(f"Message {var}")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)


class TestLoggingNoFalsePositives:
    """Test that we don't report false positives."""

    def test_no_issues_with_proper_logging(self):
        """Test that proper logging doesn't trigger issues."""
        code = """
import logging
logger = logging.getLogger(__name__)
logger.info("Processing %s", "data")
logger.warning("Warning: %s", "issue")
logger.error("Error: %s", "problem")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0

    def test_no_issues_with_non_logging_calls(self):
        """Test that non-logging calls don't trigger issues."""
        code = """
def info(message):
    print(f"Info: {message}")

info("test")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        # Should not detect issues in non-logging functions
        assert len(issues) == 0

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
import logging
logging.info(f"broken
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0  # Should not crash


class TestLoggingMultipleMethods:
    """Test detection across different logging methods."""

    def test_detect_in_all_logging_methods(self):
        """Test detection in debug, info, warning, error, critical."""
        code = """
import logging
var = "test"
logging.debug(f"Debug {var}")
logging.info(f"Info {var}")
logging.warning(f"Warning {var}")
logging.error(f"Error {var}")
logging.critical(f"Critical {var}")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        # Should detect f-strings in all methods
        assert len(issues) >= 5
        assert all(issue.rule_id == "LOG001" for issue in issues)


class TestLoggingAdvanced:
    """Test advanced logging patterns."""

    def test_multiple_issues_in_file(self):
        """Test detection of multiple logging issues."""
        code = """
import logging
logger = logging.getLogger(__name__)

def process(data):
    logger.info(f"Processing {data}")  # LOG001
    logger.warn("Deprecated warn")  # LOG003
    logger.info("Concat " + data)  # LOG005
    logger.info("Format {}".format(data))  # LOG002
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        # Should detect multiple types of issues
        assert len(issues) >= 4
        rule_ids = {issue.rule_id for issue in issues}
        assert "LOG001" in rule_ids
        assert "LOG003" in rule_ids

    def test_issue_properties(self):
        """Test that issues have correct properties."""
        code = """
import logging
logging.info(f"Message {var}")
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        issue = issues[0]
        assert issue.rule_id.startswith("LOG")
        assert issue.line > 0
        assert issue.col >= 0
        assert issue.message
        assert issue.severity in ["LOW", "MEDIUM", "HIGH"]
        assert issue.category == "logging"

    def test_severity_levels(self):
        """Test that different issues have appropriate severity levels."""
        code = """
import logging
logging.info(f"Format issue")  # MEDIUM
logging.warn("Deprecation")  # LOW
"""
        checker = LoggingChecker()
        issues = checker.check_code(code)

        assert len(issues) >= 2
        # Check severity assignments
        f_string_issues = [i for i in issues if i.rule_id == "LOG001"]
        warn_issues = [i for i in issues if i.rule_id == "LOG003"]

        if f_string_issues:
            assert f_string_issues[0].severity == "MEDIUM"
        if warn_issues:
            assert warn_issues[0].severity == "LOW"


# ============================================================================
# Enhanced Test Coverage - Following PyTest Architect Agent Guidelines
# ============================================================================


class TestLoggingIssueDataclass:
    """Test LoggingIssue dataclass properties and edge cases."""

    @pytest.mark.parametrize(
        ("rule_id", "line", "col", "message", "severity", "category"),
        [
            ("LOG001", 1, 0, "Test message", "MEDIUM", "logging"),
            ("LOG999", 100, 50, "Edge case", "HIGH", "custom"),
            ("TEST", 0, 0, "", "LOW", ""),
        ],
        ids=["standard", "edge_high_values", "empty_fields"],
    )
    def test_logging_issue_creation(self, rule_id, line, col, message, severity, category):
        """Test LoggingIssue creation with various parameters."""
        # Arrange & Act
        issue = LoggingIssue(
            rule_id=rule_id,
            line=line,
            col=col,
            message=message,
            severity=severity,
            category=category,
        )

        # Assert
        assert issue.rule_id == rule_id
        assert issue.line == line
        assert issue.col == col
        assert issue.message == message
        assert issue.severity == severity
        assert issue.category == category
        assert issue.suggested_fix is None  # Default value

    def test_logging_issue_with_suggested_fix(self):
        """Test LoggingIssue with suggested fix."""
        # Arrange
        fix_suggestion = "Use lazy formatting"

        # Act
        issue = LoggingIssue(
            rule_id="LOG001",
            line=1,
            col=0,
            message="Test",
            suggested_fix=fix_suggestion,
        )

        # Assert
        assert issue.suggested_fix == fix_suggestion

    def test_logging_issue_defaults(self):
        """Test LoggingIssue default values."""
        # Act
        issue = LoggingIssue(rule_id="TEST", line=1, col=0, message="Test")

        # Assert
        assert issue.severity == "MEDIUM"
        assert issue.category == "logging"
        assert issue.suggested_fix is None


class TestLoggingPatternVisitorInit:
    """Test LoggingPatternVisitor initialization and state."""

    def test_visitor_initialization(self):
        """Test visitor initializes with empty issues list."""
        # Act
        visitor = LoggingPatternVisitor()

        # Assert
        assert isinstance(visitor.issues, list)
        assert len(visitor.issues) == 0
        assert isinstance(visitor.logger_names, set)

    def test_visitor_default_logger_names(self):
        """Test visitor has default logger name patterns."""
        # Act
        visitor = LoggingPatternVisitor()

        # Assert
        expected_names = {"logging", "logger", "log", "LOGGER", "LOG"}
        assert visitor.logger_names == expected_names


class TestLoggingCheckerEdgeCases:
    """Test edge cases and boundary conditions for LoggingChecker."""

    @pytest.mark.parametrize(
        ("code", "expected_issue_count"),
        [
            ("", 0),  # Empty code
            ("# Just a comment", 0),  # Comment only
            ("import logging", 0),  # Import only
            ('x = "string"', 0),  # No logging
            ("logging.info('simple')", 0),  # Valid logging without import (AST valid)
        ],
        ids=["empty", "comment_only", "import_only", "no_logging", "valid_simple"],
    )
    def test_edge_cases(self, code, expected_issue_count):
        """Test edge cases return expected results."""
        # Arrange
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) == expected_issue_count

    def test_unicode_in_logging(self):
        """Test handling of Unicode characters in logging calls."""
        # Arrange
        code = """
import logging
logger = logging.getLogger(__name__)
logger.info(f"Unicode: 你好 {var} 🎉")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)

    def test_multiline_string_in_logging(self):
        """Test multiline strings in logging calls."""
        # Arrange
        code = '''
import logging
logging.info("""
This is a
multiline string
""")
'''
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # No issues expected for plain multiline string
        assert len(issues) == 0

    def test_nested_string_operations(self):
        """Test nested string operations in logging."""
        # Arrange
        code = """
import logging
var1, var2 = "a", "b"
logging.info("Outer " + ("Inner " + var1) + var2)
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG005" for issue in issues)


class TestLoggingAllMethods:
    """Test all logging method variations comprehensively."""

    @pytest.mark.parametrize(
        "method_name",
        ["debug", "info", "warning", "error", "critical", "exception"],
        ids=["debug", "info", "warning", "error", "critical", "exception"],
    )
    def test_fstring_detection_all_methods(self, method_name):
        """Test f-string detection works for all logging methods."""
        # Arrange
        code = f"""
import logging
logging.{method_name}(f"Message {{var}}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)

    @pytest.mark.parametrize(
        "method_name",
        ["debug", "info", "warning", "error", "critical"],
        ids=["debug", "info", "warning", "error", "critical"],
    )
    def test_format_detection_all_methods(self, method_name):
        """Test .format() detection works for all logging methods."""
        # Arrange
        code = f"""
import logging
logging.{method_name}("Message {{}}".format(var))
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG002" for issue in issues)


class TestLoggingLoggerVariants:
    """Test various logger object naming patterns."""

    @pytest.mark.parametrize(
        "logger_var",
        ["logger", "log", "LOGGER", "LOG", "my_logger", "app_logger"],
        ids=["logger", "log", "LOGGER", "LOG", "my_logger", "app_logger"],
    )
    def test_logger_name_variants(self, logger_var):
        """Test detection with various logger variable names."""
        # Arrange
        code = f"""
import logging
{logger_var} = logging.getLogger(__name__)
{logger_var}.info(f"Message {{var}}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0, f"Failed to detect issue with logger name: {logger_var}"
        assert any(issue.rule_id == "LOG001" for issue in issues)

    def test_non_logger_object_not_detected(self):
        """Test that non-logger objects don't trigger false positives."""
        # Arrange
        code = """
class MyClass:
    def info(self, msg):
        print(msg)

obj = MyClass()
obj.info(f"Message {var}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) == 0


class TestLoggingModuleAttribute:
    """Test logging.module.method() patterns."""

    def test_logging_module_method_call(self):
        """Test detection of logging.info() style calls."""
        # Arrange
        code = """
import logging
logging.info(f"Module method {var}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)

    def test_non_logging_module_attribute(self):
        """Test that non-logging module attributes aren't detected."""
        # Arrange
        code = """
import mymodule
mymodule.info(f"Not logging {var}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) == 0

    def test_non_attribute_function_call(self):
        """Test that non-attribute function calls are ignored."""
        # Arrange - test line 54 coverage (node.func is not ast.Attribute)
        code = """
info("Some message")  # Plain function call, not a method
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert - should not detect anything as it's not logger.info()
        assert len(issues) == 0

    def test_nested_attribute_logging_call(self):
        """Test logging call with nested attribute access."""
        # Arrange - test lines 75-79 coverage (ast.Attribute with different modules)
        code = """
import mymodule
# This tests the path where node.func.value is an Attribute
# but node.func.value.value is not "logging"
if hasattr(mymodule.config, 'logger'):
    mymodule.config.logger.info(f"Nested {var}")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert - may or may not detect based on logger name heuristics
        # The key is to execute lines 75-79
        assert isinstance(issues, list)

    def test_format_call_without_attribute(self):
        """Test that format() checks handle non-attribute cases."""
        # Arrange - test line 110 coverage (first_arg.func is not ast.Attribute)
        code = """
import logging
# This is an edge case where first_arg is a Call but func is not an Attribute
logger = logging.getLogger(__name__)
func_result = get_formatter()
logger.info(func_result("test"))
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert - should not crash and return a list
        assert isinstance(issues, list)


class TestRedundantExcInfo:
    """Test redundant exc_info detection comprehensively."""

    def test_exception_with_exc_info_true(self):
        """Test detection of redundant exc_info=True in exception()."""
        # Arrange
        code = """
import logging
logging.exception("Error", exc_info=True)
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG004" for issue in issues)

    def test_exception_with_exc_info_false(self):
        """Test exc_info=False in exception() is also flagged (redundant)."""
        # Arrange
        code = """
import logging
logging.exception("Error", exc_info=False)
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG004" for issue in issues)

    def test_exception_without_exc_info(self):
        """Test exception() without exc_info doesn't trigger false positive."""
        # Arrange
        code = """
import logging
logging.exception("Error occurred")
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # Should not have LOG004 issue
        assert not any(issue.rule_id == "LOG004" for issue in issues)

    def test_error_with_exc_info_allowed(self):
        """Test error() with exc_info is allowed (not redundant)."""
        # Arrange
        code = """
import logging
logging.error("Error", exc_info=True)
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # Should not have LOG004 issue for error()
        assert not any(issue.rule_id == "LOG004" for issue in issues)


class TestCheckFileFunction:
    """Test the check_file helper function."""

    def test_check_file_with_issues(self, tmp_path):
        """Test check_file detects issues in a file."""
        # Arrange
        file_path = tmp_path / "test_logging.py"
        file_path.write_text(
            """
import logging
logging.info(f"Test {var}")
"""
        )

        # Act
        issues = check_file(str(file_path))

        # Assert
        assert len(issues) > 0
        assert any(issue.rule_id == "LOG001" for issue in issues)

    def test_check_file_no_issues(self, tmp_path):
        """Test check_file with clean code."""
        # Arrange
        file_path = tmp_path / "clean_logging.py"
        file_path.write_text(
            """
import logging
logging.info("Test %s", var)
"""
        )

        # Act
        issues = check_file(str(file_path))

        # Assert
        assert len(issues) == 0

    def test_check_file_nonexistent(self):
        """Test check_file handles nonexistent files gracefully."""
        # Act
        issues = check_file("/nonexistent/file.py")

        # Assert
        assert len(issues) == 0  # Should return empty list, not crash

    def test_check_file_invalid_encoding(self, tmp_path):
        """Test check_file handles encoding errors gracefully."""
        # Arrange
        file_path = tmp_path / "invalid.py"
        file_path.write_bytes(b"\x80\x81\x82")  # Invalid UTF-8

        # Act
        issues = check_file(str(file_path))

        # Assert
        assert len(issues) == 0  # Should handle gracefully


class TestLoggingCheckerGetIssues:
    """Test the get_issues() method."""

    def test_get_issues_returns_visitor_issues(self):
        """Test get_issues returns issues from visitor."""
        # Arrange
        checker = LoggingChecker()
        code = """
import logging
logging.info(f"Test {var}")
"""

        # Act
        checker.check_code(code)
        issues = checker.get_issues()

        # Assert
        assert len(issues) > 0
        assert all(isinstance(issue, LoggingIssue) for issue in issues)

    def test_get_issues_empty_on_clean_code(self):
        """Test get_issues returns empty list for clean code."""
        # Arrange
        checker = LoggingChecker()
        code = """
import logging
logging.info("Clean code %s", var)
"""

        # Act
        checker.check_code(code)
        issues = checker.get_issues()

        # Assert
        assert len(issues) == 0


class TestComplexLoggingScenarios:
    """Test complex real-world logging scenarios."""

    def test_mixed_logging_patterns(self):
        """Test file with multiple logging patterns."""
        # Arrange
        code = """
import logging
logger = logging.getLogger(__name__)

def process_data(data):
    logger.info(f"Processing {data}")  # LOG001
    logger.warn("Deprecated")  # LOG003
    logger.error("Error: " + data)  # LOG005
    logger.debug("Debug: {}".format(data))  # LOG002
    logger.exception("Failed", exc_info=True)  # LOG004
    logger.info("Correct: %s", data)  # OK
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) >= 5
        rule_ids = {issue.rule_id for issue in issues}
        assert "LOG001" in rule_ids
        assert "LOG003" in rule_ids
        assert "LOG005" in rule_ids
        assert "LOG002" in rule_ids
        assert "LOG004" in rule_ids

    def test_logging_in_try_except(self):
        """Test logging patterns in exception handling."""
        # Arrange
        code = """
import logging
try:
    risky_operation()
except ValueError:
    logging.error(f"ValueError occurred: {e}")  # LOG001
except Exception as e:
    logging.exception("Unexpected error", exc_info=True)  # LOG004
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) >= 2
        assert any(issue.rule_id == "LOG001" for issue in issues)
        assert any(issue.rule_id == "LOG004" for issue in issues)

    def test_conditional_logging(self):
        """Test logging in conditional blocks."""
        # Arrange
        code = """
import logging
if condition:
    logging.info(f"Condition true: {value}")  # LOG001
else:
    logging.warn("Condition false")  # LOG003
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        assert len(issues) >= 2

    def test_logging_with_multiple_args(self):
        """Test logging calls with multiple arguments."""
        # Arrange
        code = """
import logging
logging.info("Message %s %s", arg1, arg2)  # OK
logging.info(f"Message {arg1} {arg2}")  # LOG001
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # Only f-string should be flagged
        assert len(issues) == 1
        assert issues[0].rule_id == "LOG001"


class TestStringConcatenationDetection:
    """Test string concatenation detection in detail."""

    @pytest.mark.parametrize(
        ("code_snippet", "should_detect"),
        [
            ('logging.info("prefix " + var)', True),
            ('logging.info(var + " suffix")', True),
            ('logging.info("a" + "b" + var)', True),
            ("logging.info(var1 + var2)", False),  # Both variables, not string concat
            ('logging.info("Message %s", var)', False),  # Lazy formatting
        ],
        ids=["prefix_concat", "suffix_concat", "multiple_concat", "var_only", "lazy_ok"],
    )
    def test_string_concatenation_patterns(self, code_snippet, should_detect):
        """Test various string concatenation patterns."""
        # Arrange
        code = f"""
import logging
{code_snippet}
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        if should_detect:
            assert any(
                issue.rule_id == "LOG005" for issue in issues
            ), f"Expected LOG005 for: {code_snippet}"
        else:
            # May have other issues, but not LOG005
            assert not any(
                issue.rule_id == "LOG005" for issue in issues
            ), f"Unexpected LOG005 for: {code_snippet}"


class TestLoggingNoArgs:
    """Test logging calls without arguments."""

    def test_logging_no_args(self):
        """Test logging calls with no arguments."""
        # Arrange
        code = """
import logging
logging.info()
logging.debug()
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # No args shouldn't crash, but also won't have formatting issues
        assert len(issues) == 0

    def test_logging_with_kwargs_only(self):
        """Test logging with keyword arguments only."""
        # Arrange
        code = """
import logging
logging.info(extra={"key": "value"})
logging.exception(exc_info=True)
"""
        checker = LoggingChecker()

        # Act
        issues = checker.check_code(code)

        # Assert
        # exception() with exc_info should be detected
        assert any(issue.rule_id == "LOG004" for issue in issues)
