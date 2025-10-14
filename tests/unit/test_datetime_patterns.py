"""
Tests for datetime_patterns module (DTZ rules).
"""

import pytest
from pyguard.lib.datetime_patterns import DatetimeChecker, DatetimeIssue


class TestDatetimeBasics:
    """Test basic datetime pattern detection."""

    def test_detect_naive_now(self):
        """Test detection of datetime.now() without timezone."""
        code = """
from datetime import datetime
now = datetime.now()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ001" for issue in issues)
        assert any("timezone" in issue.message.lower() for issue in issues)

    def test_detect_utcnow_deprecated(self):
        """Test detection of deprecated datetime.utcnow()."""
        code = """
from datetime import datetime
now = datetime.utcnow()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ003" for issue in issues)
        assert any("deprecated" in issue.message.lower() for issue in issues)

    def test_detect_naive_fromtimestamp(self):
        """Test detection of fromtimestamp() without timezone."""
        code = """
from datetime import datetime
dt = datetime.fromtimestamp(1234567890)
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ005" for issue in issues)

    def test_detect_utcfromtimestamp_deprecated(self):
        """Test detection of deprecated utcfromtimestamp()."""
        code = """
from datetime import datetime
dt = datetime.utcfromtimestamp(1234567890)
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ004" for issue in issues)


class TestDatetimeDateMethods:
    """Test date method detection."""

    def test_detect_date_today(self):
        """Test detection of date.today() via datetime module."""
        code = """
import datetime
today = datetime.date.today()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ002" for issue in issues)

    def test_detect_datetime_today(self):
        """Test detection of datetime.today()."""
        code = """
from datetime import datetime
today = datetime.today()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ002" for issue in issues)


class TestDatetimeStrptime:
    """Test strptime detection."""

    def test_detect_naive_strptime(self):
        """Test detection of strptime (returns naive datetime)."""
        code = """
from datetime import datetime
dt = datetime.strptime("2024-01-01", "%Y-%m-%d")
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ007" for issue in issues)


class TestDatetimeNoFalsePositives:
    """Test that we don't report false positives."""

    def test_no_issue_with_timezone_aware(self):
        """Test that timezone-aware datetime doesn't trigger issues."""
        code = """
from datetime import datetime, timezone
now = datetime.now(tz=timezone.utc)
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        # Should not detect DTZ001 when tz parameter is provided
        assert not any(issue.rule_id == "DTZ001" for issue in issues)

    def test_no_issue_with_fromtimestamp_tz(self):
        """Test that fromtimestamp with tz doesn't trigger issues."""
        code = """
from datetime import datetime, timezone
dt = datetime.fromtimestamp(1234567890, tz=timezone.utc)
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        # Should not detect DTZ005 when tz is provided
        assert not any(issue.rule_id == "DTZ005" for issue in issues)

    def test_no_issue_with_non_datetime_now(self):
        """Test that non-datetime now() calls don't trigger issues."""
        code = """
class MyClass:
    def now(self):
        return "now"

obj = MyClass()
result = obj.now()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        # Should not detect datetime issues in non-datetime code
        assert len(issues) == 0

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
from datetime import datetime
dt = datetime.now(
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) == 0  # Should not crash


class TestDatetimeModuleName:
    """Test detection with different import styles."""

    def test_detect_with_import_datetime(self):
        """Test detection with 'import datetime'."""
        code = """
import datetime
now = datetime.datetime.now()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ001" for issue in issues)

    def test_detect_with_from_import(self):
        """Test detection with 'from datetime import datetime'."""
        code = """
from datetime import datetime
now = datetime.now()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        assert any(issue.rule_id == "DTZ001" for issue in issues)


class TestDatetimeAdvanced:
    """Test advanced datetime patterns."""

    def test_multiple_issues_in_file(self):
        """Test detection of multiple datetime issues."""
        code = """
from datetime import datetime
import datetime as dt
now1 = datetime.now()  # DTZ001
now2 = datetime.utcnow()  # DTZ003
ts = datetime.fromtimestamp(123)  # DTZ005
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        # Should detect multiple issues
        assert len(issues) >= 3
        rule_ids = {issue.rule_id for issue in issues}
        assert "DTZ001" in rule_ids
        assert "DTZ003" in rule_ids
        assert "DTZ005" in rule_ids

    def test_issue_properties(self):
        """Test that issues have correct properties."""
        code = """
from datetime import datetime
dt = datetime.now()
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) > 0
        issue = issues[0]
        assert issue.rule_id.startswith("DTZ")
        assert issue.line > 0
        assert issue.col >= 0
        assert issue.message
        assert issue.severity in ["LOW", "MEDIUM", "HIGH"]
        assert issue.category == "datetime"
        assert issue.suggested_fix

    def test_severity_levels(self):
        """Test that different issues have appropriate severity levels."""
        code = """
from datetime import datetime
dt1 = datetime.now()  # MEDIUM
dt2 = datetime.utcnow()  # HIGH
dt3 = datetime.utcfromtimestamp(123)  # HIGH
"""
        checker = DatetimeChecker()
        issues = checker.check_code(code)
        
        assert len(issues) >= 3
        
        # utcnow and utcfromtimestamp should be HIGH (deprecated)
        high_issues = [i for i in issues if i.severity == "HIGH"]
        assert len(high_issues) >= 2
        
        # now() without tz should be MEDIUM
        medium_issues = [i for i in issues if i.severity == "MEDIUM"]
        assert len(medium_issues) >= 1
