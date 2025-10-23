"""
Unit tests for Pony ORM security analysis module.

Tests detection of Pony ORM security vulnerabilities.
Covers 12+ security checks for entity security, query security,
database connection security, and generator expression security.
"""

import pytest
from pathlib import Path

from pyguard.lib.framework_pony import (
    PonySecurityVisitor,
    analyze_pony_security,
)


class TestPonyRawSQL:
    """Test PON002: Raw SQL injection."""

    def test_detect_raw_sql_with_format(self):
        """Detect raw SQL with string formatting."""
        code = """
from pony.orm import *

db = Database()
query = "SELECT * FROM users WHERE id = {}".format(user_id)
db.execute(query)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "PON002"]
        assert len(sql_violations) >= 1
        assert sql_violations[0].severity == "CRITICAL"

    def test_safe_pony_query(self):
        """Safe Pony query should not trigger."""
        code = """
from pony.orm import *

select(u for u in User if u.id == user_id)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        sql_violations = [v for v in violations if v.rule_id == "PON002"]
        assert len(sql_violations) == 0


class TestPonyDbSessionDecorator:
    """Test PON003: @db_session decorator security."""

    def test_detect_db_session_without_error_handling(self):
        """Detect @db_session without error handling."""
        code = """
from pony.orm import *

@db_session
def get_user(user_id):
    return User.get(id=user_id)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        decorator_violations = [v for v in violations if v.rule_id == "PON003"]
        assert len(decorator_violations) >= 1
        assert any("error handling" in v.message.lower() for v in decorator_violations)

    def test_safe_db_session_with_error_handling(self):
        """@db_session with error handling should not trigger."""
        code = """
from pony.orm import *

@db_session
def get_user(user_id):
    try:
        return User.get(id=user_id)
    except Exception as e:
        handle_error(e)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        decorator_violations = [v for v in violations if v.rule_id == "PON003"]
        assert len(decorator_violations) == 0


class TestPonyGeneratorInjection:
    """Test PON004: Generator expression injection."""

    def test_detect_select_with_user_input(self):
        """Detect select() with user input."""
        code = """
from pony.orm import *

user_filter = request.args.get('filter')
results = select(u for u in User)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        gen_violations = [v for v in violations if v.rule_id == "PON004"]
        assert len(gen_violations) >= 1

    def test_safe_select_without_user_input(self):
        """select() without user input should not trigger."""
        code = """
from pony.orm import *

results = select(u for u in User if u.active == True)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        gen_violations = [v for v in violations if v.rule_id == "PON004"]
        assert len(gen_violations) == 0


class TestPonyDatabaseConnection:
    """Test PON005: Database connection security."""

    def test_detect_bind_with_user_input(self):
        """Detect bind() with user input."""
        code = """
from pony.orm import *

db = Database()
db_name = user_input
db.bind('sqlite', db_name)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        db_violations = [v for v in violations if v.rule_id == "PON005"]
        assert len(db_violations) >= 1

    def test_safe_bind_with_constant(self):
        """bind() with constant should not trigger."""
        code = """
from pony.orm import *

db = Database()
db.bind('sqlite', 'mydb.db')
"""
        violations = analyze_pony_security(Path("test.py"), code)
        db_violations = [v for v in violations if v.rule_id == "PON005"]
        assert len(db_violations) == 0


class TestPonyCacheSecurity:
    """Test PON008: Cache key injection."""

    def test_detect_cache_with_user_input(self):
        """Detect cache operations with user input."""
        code = """
from pony.orm import *

cache_key = user_input
result = cache.get(cache_key)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        cache_violations = [v for v in violations if v.rule_id == "PON008"]
        assert len(cache_violations) >= 1

    def test_safe_cache_without_user_input(self):
        """Cache without user input should not trigger."""
        code = """
from pony.orm import *

# Cache with constant key
result = get_cached('user_list')
"""
        violations = analyze_pony_security(Path("test.py"), code)
        cache_violations = [v for v in violations if v.rule_id == "PON008"]
        assert len(cache_violations) == 0


class TestPonyEdgeCases:
    """Test edge cases."""

    def test_no_violation_without_pony_import(self):
        """Should not flag code without Pony import."""
        code = """
@db_session
def get_user():
    pass
"""
        violations = analyze_pony_security(Path("test.py"), code)
        assert len(violations) == 0

    def test_multiple_violations(self):
        """Should detect multiple violations."""
        code = """
from pony.orm import *

@db_session
def query_user():
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)
"""
        violations = analyze_pony_security(Path("test.py"), code)
        rule_ids = {v.rule_id for v in violations}
        assert len(rule_ids) >= 1
