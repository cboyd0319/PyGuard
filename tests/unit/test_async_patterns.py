"""
Tests for async_patterns module (ASYNC rules).
"""

import pytest
from pyguard.lib.async_patterns import AsyncChecker, AsyncIssue


class TestAsyncBasics:
    """Test basic async pattern detection."""

    def test_detect_blocking_open(self):
        """Test detection of open() in async function."""
        code = """
async def read_file():
    with open("file.txt") as f:
        return f.read()
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "ASYNC105" for issue in issues)

    def test_detect_time_sleep(self):
        """Test detection of time.sleep() in async function."""
        code = """
import time

async def slow_function():
    time.sleep(1)
    return "done"
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "ASYNC101" for issue in issues)
        assert any("asyncio.sleep()" in issue.suggested_fix for issue in issues)

    def test_detect_async_function_no_await(self):
        """Test detection of async function with no await."""
        code = """
async def not_really_async():
    x = 1 + 1
    return x
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "ASYNC102" for issue in issues)

    def test_detect_sync_requests(self):
        """Test detection of synchronous HTTP requests in async function."""
        code = """
import requests

async def fetch_data():
    response = requests.get("https://api.example.com")
    return response.json()
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        assert any(issue.rule_id == "ASYNC106" for issue in issues)
        assert any("aiohttp" in issue.suggested_fix for issue in issues)


class TestAsyncContextManagers:
    """Test async context manager detection."""

    def test_detect_sync_with_in_async(self):
        """Test detection of sync context manager in async function."""
        code = """
async def process():
    with open("file.txt") as f:
        content = f.read()
    return content
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should detect both open() call and sync with
        assert len(issues) >= 1
        assert any(issue.rule_id in ["ASYNC105", "ASYNC107"] for issue in issues)

    def test_no_issue_with_async_with(self):
        """Test that async with doesn't trigger issues."""
        code = """
import aiofiles

async def read_async():
    async with aiofiles.open("file.txt") as f:
        content = await f.read()
    return content
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should not trigger context manager issues
        assert not any(issue.rule_id == "ASYNC107" for issue in issues)


class TestAsyncIteration:
    """Test async iteration pattern detection."""

    def test_detect_sync_for_in_async(self):
        """Test detection of potential async iteration."""
        code = """
async def process_items():
    items = []
    for item in fetch_items():
        items.append(item)
    return items

def fetch_items():
    return [1, 2, 3]
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should suggest async for when iterating over fetch call
        assert any(issue.rule_id == "ASYNC108" for issue in issues)


class TestAsyncNoFalsePositives:
    """Test that we don't report false positives."""

    def test_no_issues_in_sync_function(self):
        """Test that sync functions don't trigger async issues."""
        code = """
import time

def sync_function():
    time.sleep(1)
    with open("file.txt") as f:
        return f.read()
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Sync functions should not trigger async-specific issues
        assert len(issues) == 0

    def test_no_issues_with_proper_async(self):
        """Test that proper async code doesn't trigger issues."""
        code = """
import asyncio

async def proper_async():
    await asyncio.sleep(1)
    result = await fetch_data()
    return result

async def fetch_data():
    await asyncio.sleep(0)  # Has await now
    return "data"
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Proper async should not trigger issues
        assert len(issues) == 0

    def test_handle_syntax_error(self):
        """Test that syntax errors are handled gracefully."""
        code = """
async def broken(
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) == 0  # Should not crash


class TestAsyncAdvanced:
    """Test advanced async patterns."""

    def test_multiple_blocking_calls(self):
        """Test detection of multiple blocking calls."""
        code = """
import time
import requests

async def bad_async():
    time.sleep(1)
    response = requests.get("https://api.example.com")
    with open("file.txt") as f:
        data = f.read()
    return data
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should detect multiple issues
        assert len(issues) >= 3
        rule_ids = {issue.rule_id for issue in issues}
        assert "ASYNC101" in rule_ids  # time.sleep
        assert "ASYNC106" in rule_ids  # requests.get
        assert "ASYNC105" in rule_ids  # open()

    def test_nested_async_functions(self):
        """Test detection in nested async functions."""
        code = """
import time

async def outer():
    async def inner():
        time.sleep(1)
    await inner()
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should detect time.sleep in inner function
        assert len(issues) > 0
        assert any(issue.rule_id == "ASYNC101" for issue in issues)


class TestAsyncIssueProperties:
    """Test issue properties and metadata."""

    def test_issue_has_correct_properties(self):
        """Test that issues have all required properties."""
        code = """
import time

async def test_func():
    time.sleep(1)
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        issue = issues[0]
        assert issue.rule_id.startswith("ASYNC")
        assert issue.line > 0
        assert issue.col >= 0
        assert issue.message
        assert issue.severity in ["LOW", "MEDIUM", "HIGH"]
        assert issue.category == "async"

    def test_severity_levels(self):
        """Test that different issues have appropriate severity levels."""
        code = """
import time
import requests

async def test_func():
    time.sleep(1)  # HIGH
    requests.get("url")  # HIGH
    for item in fetch():  # LOW
        pass
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        assert len(issues) > 0
        # High severity for blocking I/O
        assert any(
            issue.rule_id in ["ASYNC101", "ASYNC106"] and issue.severity == "HIGH"
            for issue in issues
        )


class TestAsyncHTTPPatterns:
    """Test HTTP-specific async patterns."""

    def test_detect_all_requests_methods(self):
        """Test detection of various requests methods."""
        code = """
import requests

async def test_http():
    requests.get("url")
    requests.post("url")
    requests.put("url")
    requests.delete("url")
    requests.patch("url")
"""
        checker = AsyncChecker()
        issues = checker.check_code(code)

        # Should detect all HTTP method calls (at least get, post, put, delete, patch)
        # Plus one for async function with no await
        assert len(issues) >= 5
        http_issues = [issue for issue in issues if issue.rule_id == "ASYNC106"]
        assert len(http_issues) >= 5
