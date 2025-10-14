"""
Tests for logging_patterns module (LOG rules).
"""

import pytest
from pyguard.lib.logging_patterns import LoggingChecker, LoggingIssue


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
