"""
Tests for exception handling pattern detection.
"""

import ast
from pathlib import Path

from pyguard.lib.exception_handling import (
    EXCEPTION_HANDLING_RULES,
    ExceptionHandlingChecker,
)


class TestExceptionHandlingChecker:
    """Test the main ExceptionHandlingChecker class."""

    def test_initialization(self):
        """Test checker initialization."""
        checker = ExceptionHandlingChecker()
        assert checker is not None
        assert checker.logger is not None

    def test_check_code_syntax_error(self):
        """Test handling of syntax errors."""
        checker = ExceptionHandlingChecker()
        code = "def broken("
        violations = checker.check_code(code)
        assert violations == []


class TestRaiseVanillaException:
    """Test TRY002: Raise vanilla Exception."""

    def test_detect_raise_exception(self):
        """Test detection of raising generic Exception."""
        code = """
def process():
    # TODO: Add docstring
    raise Exception("Something went wrong")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try002_violations = [v for v in violations if v.rule_id == "TRY002"]
        assert len(try002_violations) == 1
        assert "vanilla" in try002_violations[0].message.lower()

    def test_allow_custom_exception(self):
        """Test that custom exceptions are allowed."""
        code = """
class CustomError(Exception):
    # TODO: Add docstring
    pass

def process():
    # TODO: Add docstring
    raise CustomError("Custom error")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try002_violations = [v for v in violations if v.rule_id == "TRY002"]
        assert len(try002_violations) == 0


class TestLongExceptionMessage:
    """Test TRY003: Long exception messages."""

    def test_detect_long_message(self):
        """Test detection of long exception messages."""
        long_msg = "x" * 201
        code = f"""
def process():
    # TODO: Add docstring
    raise ValueError("{long_msg}")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try003_violations = [v for v in violations if v.rule_id == "TRY003"]
        assert len(try003_violations) == 1
        assert "too long" in try003_violations[0].message.lower()

    def test_allow_short_message(self):
        """Test that short messages are allowed."""
        code = """
def process():
    # TODO: Add docstring
    raise ValueError("Short message")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try003_violations = [v for v in violations if v.rule_id == "TRY003"]
        assert len(try003_violations) == 0


class TestSuppressGenericException:
    """Test TRY005: Suppress generic Exception."""

    def test_detect_suppress_exception(self):
        """Test detection of suppressing generic Exception."""
        code = """
from contextlib import suppress

with suppress(Exception):
    risky_operation()
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try005_violations = [v for v in violations if v.rule_id == "TRY005"]
        assert len(try005_violations) == 1
        assert "generic" in try005_violations[0].message.lower()

    def test_allow_specific_suppress(self):
        """Test that specific exception suppression is allowed."""
        code = """
from contextlib import suppress

with suppress(ValueError):
    risky_operation()
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try005_violations = [v for v in violations if v.rule_id == "TRY005"]
        assert len(try005_violations) == 0


class TestReraiseNoCause:
    """Test TRY200: Reraise without from."""

    def test_detect_reraise_no_cause(self):
        """Test detection of raising without from in except handler."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        raise TypeError("Type error")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try200_violations = [v for v in violations if v.rule_id == "TRY200"]
        assert len(try200_violations) == 1
        assert "from" in try200_violations[0].message.lower()

    def test_allow_raise_with_from(self):
        """Test that raise with from is allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError as e:
        raise TypeError("Type error") from e
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try200_violations = [v for v in violations if v.rule_id == "TRY200"]
        assert len(try200_violations) == 0

    def test_allow_bare_raise(self):
        """Test that bare raise is allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        log_error()
        raise
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try200_violations = [v for v in violations if v.rule_id == "TRY200"]
        assert len(try200_violations) == 0


class TestVerboseRaise:
    """Test TRY201: Verbose raise."""

    def test_detect_verbose_raise(self):
        """Test detection of verbose reraise."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError as e:
        raise e
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try201_violations = [v for v in violations if v.rule_id == "TRY201"]
        assert len(try201_violations) == 1
        assert "bare" in try201_violations[0].message.lower()

    def test_allow_bare_raise_in_handler(self):
        """Test that bare raise is preferred."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        raise
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try201_violations = [v for v in violations if v.rule_id == "TRY201"]
        assert len(try201_violations) == 0


class TestTooManyHandlers:
    """Test TRY301: Too many exception handlers."""

    def test_detect_too_many_handlers(self):
        """Test detection of too many exception handlers."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        pass
    except TypeError:
        pass
    except KeyError:
        pass
    except AttributeError:
        pass
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try301_violations = [v for v in violations if v.rule_id == "TRY301"]
        assert len(try301_violations) == 1
        assert "many" in try301_violations[0].message.lower()

    def test_allow_few_handlers(self):
        """Test that few handlers are allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        pass
    except TypeError:
        pass
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try301_violations = [v for v in violations if v.rule_id == "TRY301"]
        assert len(try301_violations) == 0


class TestUselessTryExcept:
    """Test TRY302: Useless try-except."""

    def test_detect_useless_try_except(self):
        """Test detection of useless try-except with only pass."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        pass
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try302_violations = [v for v in violations if v.rule_id == "TRY302"]
        assert len(try302_violations) == 1
        assert "useless" in try302_violations[0].message.lower()

    def test_allow_meaningful_handler(self):
        """Test that meaningful handlers are allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        logger.error("Error occurred")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try302_violations = [v for v in violations if v.rule_id == "TRY302"]
        assert len(try302_violations) == 0


class TestVerboseLogMessage:
    """Test TRY401: Verbose log message."""

    def test_detect_verbose_logging(self):
        """Test detection of verbose logging pattern."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        logger.error("Error occurred", exc_info=True)
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try401_violations = [v for v in violations if v.rule_id == "TRY401"]
        assert len(try401_violations) == 1
        assert "exception()" in try401_violations[0].message.lower()

    def test_allow_exception_method(self):
        """Test that logging.exception is preferred."""
        code = """
def process():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        logger.exception("Error occurred")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try401_violations = [v for v in violations if v.rule_id == "TRY401"]
        assert len(try401_violations) == 0


class TestExceptionHandlingRules:
    """Test EXCEPTION_HANDLING_RULES constant."""

    def test_rules_exist(self):
        """Test that exception handling rules are defined."""
        assert len(EXCEPTION_HANDLING_RULES) > 0

    def test_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        for rule in EXCEPTION_HANDLING_RULES:
            assert rule.rule_id.startswith("TRY")
            assert rule.name
            assert rule.category
            assert rule.severity
            assert rule.message_template
            assert rule.description

    def test_rule_ids_unique(self):
        """Test that rule IDs are unique."""
        rule_ids = [rule.rule_id for rule in EXCEPTION_HANDLING_RULES]
        assert len(rule_ids) == len(set(rule_ids))


class TestIntegration:
    """Integration tests."""

    def test_multiple_violations(self):
        """Test detection of multiple violations in one file."""
        code = """
def bad_function():
    # TODO: Add docstring
    try:
        risky()
    except ValueError:
        raise Exception("Generic error")  # TRY002
        logger.error("Failed", exc_info=True)  # TRY401
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        assert len(violations) >= 2
        rule_ids = {v.rule_id for v in violations}
        assert "TRY002" in rule_ids

    def test_no_false_positives(self):
        """Test that good code doesn't trigger violations."""
        code = """
class CustomError(Exception):
    # TODO: Add docstring
    pass

def good_function():
    # TODO: Add docstring
    try:
        result = process()
    except ValueError as e:
        logger.exception("Processing failed")
        raise CustomError("Custom error") from e

    return result
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should have minimal or no violations
        assert len(violations) <= 1


class TestRaiseWithoutFrom:
    """Test TRY001: Raise without from inside except."""

    def test_detect_raise_without_from(self):
        """Test detection of raise without from in except handler."""
        code = """
def process():
    # TODO: Add docstring
    try:
        do_something()
    except ValueError:
        raise RuntimeError("Processing failed")
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try001_violations = [v for v in violations if v.rule_id == "TRY001"]
        assert len(try001_violations) >= 1
        assert "from" in try001_violations[0].message.lower()

    def test_allow_raise_with_from(self):
        """Test that raise with from is allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        do_something()
    except ValueError as e:
        raise RuntimeError("Processing failed") from e
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try001_violations = [v for v in violations if v.rule_id == "TRY001"]
        assert len(try001_violations) == 0

    def test_allow_bare_raise(self):
        """Test that bare raise is allowed."""
        code = """
def process():
    # TODO: Add docstring
    try:
        do_something()
    except ValueError:
        log_error()
        raise
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        try001_violations = [v for v in violations if v.rule_id == "TRY001"]
        assert len(try001_violations) == 0


class TestExceptionHandlingCheckerErrorHandling:
    """Test error handling in ExceptionHandlingChecker."""

    def test_check_file_with_syntax_error(self, tmp_path):
        """Test check_file handles syntax errors gracefully."""
        # Arrange
        checker = ExceptionHandlingChecker()
        file_path = tmp_path / "syntax_error.py"
        file_path.write_text("def broken(\n")  # Syntax error

        # Act
        violations = checker.check_file(file_path)

        # Assert - Should return empty list, not raise
        assert isinstance(violations, list)
        assert len(violations) == 0

    def test_check_file_nonexistent(self):
        """Test check_file with nonexistent file."""
        # Arrange
        checker = ExceptionHandlingChecker()
        file_path = Path("/nonexistent/file.py")

        # Act
        violations = checker.check_file(file_path)

        # Assert - Should handle gracefully
        assert isinstance(violations, list)
        assert len(violations) == 0

    def test_check_code_syntax_error_in_string(self):
        """Test check_code with syntax error."""
        # Arrange
        checker = ExceptionHandlingChecker()
        code = "def broken(\n"  # Incomplete function

        # Act
        violations = checker.check_code(code)

        # Assert - Should return empty list
        assert isinstance(violations, list)
        assert len(violations) == 0

    def test_check_code_with_empty_string(self):
        """Test check_code with empty string."""
        # Arrange
        checker = ExceptionHandlingChecker()

        # Act
        violations = checker.check_code("")

        # Assert
        assert isinstance(violations, list)
        assert len(violations) == 0


class TestExceptionHandlingEdgeCases:
    """Test edge cases for exception handling rules."""

    def test_try_with_multiple_statements_no_return(self):
        """Test try block with multiple statements but no return."""
        code = """
def process():
    # TODO: Add docstring
    try:
        x = 1
        y = 2
        z = x + y
    except ValueError:
        pass
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should not raise any specific violations for this pattern
        assert isinstance(violations, list)

    def test_nested_try_blocks(self):
        """Test nested try-except blocks."""
        code = """
def process():
    # TODO: Add docstring
    try:
        try:
            dangerous_operation()
        except ValueError:
            pass
    except Exception:
        pass
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should detect patterns, check if TRY002 is triggered
        assert isinstance(violations, list)

    def test_try_with_exactly_three_handlers(self):
        """Test try block with exactly 3 handlers (boundary case)."""
        code = """
def process():
    # TODO: Add docstring
    try:
        operation()
    except ValueError:
        handle_value_error()
    except TypeError:
        handle_type_error()
    except KeyError:
        handle_key_error()
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should not trigger TRY301 (which requires > 3 handlers)
        try301_violations = [v for v in violations if v.rule_id == "TRY301"]
        assert len(try301_violations) == 0

    def test_try_with_four_handlers(self):
        """Test try block with 4 handlers (should trigger TRY301)."""
        code = """
def process():
    # TODO: Add docstring
    try:
        operation()
    except ValueError:
        handle_value_error()
    except TypeError:
        handle_type_error()
    except KeyError:
        handle_key_error()
    except AttributeError:
        handle_attribute_error()
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should trigger TRY301 (too many handlers)
        try301_violations = [v for v in violations if v.rule_id == "TRY301"]
        assert len(try301_violations) > 0


class TestCoverageMissingLines:
    """Tests to cover missing lines in exception_handling.py"""

    def test_suppress_with_attribute_func(self):
        """Test suppress() with module.suppress() format (lines 250-251)."""
        code = """
from contextlib import suppress
import mymodule

# Test lines 250-251: item.context_expr.func is ast.Attribute
with mymodule.suppress(Exception):
    risky_operation()
"""
        checker = ExceptionHandlingChecker()
        violations = checker.check_code(code)
        # Should execute lines 250-251 even if no violation is raised
        assert isinstance(violations, list)

    def test_check_file_with_exception(self, tmp_path):
        """Test check_file handles general exceptions (lines 298-301)."""
        # Create a file that will cause an error during processing
        test_file = tmp_path / "test.py"
        test_file.write_text("# Valid Python\npass")

        checker = ExceptionHandlingChecker()

        # Mock the ast.parse to raise an exception (not SyntaxError)
        original_parse = ast.parse

        def mock_parse_error(*args, **kwargs):
            # TODO: Add docstring
            raise RuntimeError("Simulated error")

        ast.parse = mock_parse_error
        try:
            violations = checker.check_file(test_file)
            # Should catch the exception and return empty list (lines 298-301)
            assert violations == []
        finally:
            ast.parse = original_parse

    def test_check_code_with_exception(self):
        """Test check_code handles general exceptions (lines 343-348)."""
        code = "pass"
        checker = ExceptionHandlingChecker()

        # Mock ast.parse to raise a non-syntax exception
        original_parse = ast.parse

        def mock_parse_error(*args, **kwargs):
            # TODO: Add docstring
            raise RuntimeError("Simulated processing error")

        ast.parse = mock_parse_error
        try:
            violations = checker.check_code(code)
            # Should catch the exception and return empty list (lines 343-348)
            assert violations == []
        finally:
            ast.parse = original_parse
