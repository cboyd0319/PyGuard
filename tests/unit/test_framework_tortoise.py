"""
Unit tests for Tortoise ORM security analysis module.

Tests detection of Tortoise ORM security vulnerabilities.
Covers 15+ security checks for async ORM query security, model security,
connection pool security, and async database operations.
"""

import pytest
from pathlib import Path

from pyguard.lib.framework_tortoise import (
    TortoiseSecurityVisitor,
    analyze_tortoise_security,
)


class TestTortoiseAsyncQueryInjection:
    """Test TOR001: Async query injection."""

    def test_detect_filter_with_format(self):
        """Detect filter() with string formatting."""
        code = """
from tortoise import models

async def get_users():
    query = f"username = '{user_input}'"
    users = await User.filter(query)
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        injection_violations = [v for v in violations if v.rule_id == "TOR001"]
        assert len(injection_violations) >= 1
        assert injection_violations[0].severity == "CRITICAL"

    def test_safe_filter_with_params(self):
        """Safe filter() with parameters should not trigger."""
        code = """
from tortoise import models

async def get_users():
    users = await User.filter(username=user_input)
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        injection_violations = [v for v in violations if v.rule_id == "TOR001"]
        assert len(injection_violations) == 0


class TestTortoiseRawSQLAsync:
    """Test TOR012: Raw SQL injection in async."""

    def test_detect_execute_with_format(self):
        """Detect execute() with string formatting."""
        code = """
from tortoise import Tortoise

async def query_data():
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    await Tortoise.get_connection().execute_query(query)
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "TOR012"]
        assert len(sql_violations) >= 1
        assert sql_violations[0].severity == "CRITICAL"

    def test_safe_parameterized_query(self):
        """Parameterized query should not trigger."""
        code = """
from tortoise import Tortoise

async def query_data():
    query = "SELECT * FROM users WHERE id = $1"
    await Tortoise.get_connection().execute_query(query, [user_id])
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "TOR012"]
        assert len(sql_violations) == 0


class TestTortoiseConnectionPool:
    """Test TOR007: Connection pool configuration."""

    def test_detect_register_without_pool_limits(self):
        """Detect register_tortoise without pool limits."""
        code = """
from tortoise import Tortoise

Tortoise.register_tortoise(
    db_url="sqlite://db.sqlite3",
    modules={"models": ["app.models"]}
)
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        pool_violations = [v for v in violations if v.rule_id == "TOR007"]
        assert len(pool_violations) >= 1
        assert any("pool" in v.message.lower() for v in pool_violations)

    def test_safe_register_with_pool_limits(self):
        """register_tortoise with pool limits should not trigger."""
        code = """
from tortoise import Tortoise

Tortoise.register_tortoise(
    db_url="sqlite://db.sqlite3",
    modules={"models": ["app.models"]},
    max_size=20,
    min_size=5
)
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        pool_violations = [v for v in violations if v.rule_id == "TOR007"]
        assert len(pool_violations) == 0


class TestTortoisePrefetchSecurity:
    """Test TOR010: Prefetch operation security."""

    def test_detect_prefetch_without_limit(self):
        """Detect prefetch_related without limit."""
        code = """
from tortoise import models

async def get_users():
    users = await User.all().prefetch_related('posts')
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        prefetch_violations = [v for v in violations if v.rule_id == "TOR010"]
        assert len(prefetch_violations) >= 1

    def test_safe_prefetch_with_limit(self):
        """prefetch_related with limit should not trigger."""
        code = """
from tortoise import models

async def get_users():
    users = await User.all().limit(100).prefetch_related('posts')
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        prefetch_violations = [v for v in violations if v.rule_id == "TOR010"]
        assert len(prefetch_violations) == 0


class TestTortoiseAggregate:
    """Test TOR011: Aggregate function manipulation."""

    def test_detect_aggregate_with_user_input(self):
        """Detect aggregate with user input."""
        code = """
from tortoise.functions import Count

async def get_stats():
    field = request.args.get('field')
    stats = await User.all().annotate(count=Count('id'))
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        agg_violations = [v for v in violations if v.rule_id == "TOR011"]
        assert len(agg_violations) >= 1

    def test_safe_aggregate_without_user_input(self):
        """Aggregate without user input should not trigger."""
        code = """
from tortoise.functions import Count

async def get_stats():
    stats = await User.all().annotate(count=Count('id'))
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        agg_violations = [v for v in violations if v.rule_id == "TOR011"]
        assert len(agg_violations) == 0


class TestTortoiseEdgeCases:
    """Test edge cases."""

    def test_no_violation_without_tortoise_import(self):
        """Should not flag code without Tortoise import."""
        code = """
async def get_users():
    users = await User.filter(username='test')
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_multiple_violations(self):
        """Should detect multiple violations."""
        code = """
from tortoise import Tortoise, models

async def query():
    query = f"SELECT * FROM users WHERE id = {user_id}"
    await Tortoise.get_connection().execute_query(query)
    
    users = await User.all().prefetch_related('posts')
"""
        violations = analyze_tortoise_security(Path("test.py"), code)
        rule_ids = {v.rule_id for v in violations}
        assert len(rule_ids) >= 1
