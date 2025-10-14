"""Tests for Django framework rules module."""

from pathlib import Path

import pytest

from pyguard.lib.framework_django import DJANGO_RULES, DjangoRulesChecker


class TestDjangoRulesDetection:
    """Test detection of Django-specific issues."""

    def test_detect_raw_sql_injection(self, tmp_path):
        """Test detection of SQL injection in raw queries."""
        code = '''
from django.db import models

class MyModel(models.Model):
    pass

def get_data(user_id):
    return MyModel.objects.raw(f"SELECT * FROM table WHERE id={user_id}")
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DjangoRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "DJ001" for v in violations)

    def test_detect_model_without_str(self, tmp_path):
        """Test detection of model without __str__ method."""
        code = '''
from django.db import models

class Product(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DjangoRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "DJ006" for v in violations)

    def test_detect_hardcoded_secret_key(self, tmp_path):
        """Test detection of hardcoded SECRET_KEY."""
        code = '''
import django

SECRET_KEY = "super-secret-key-123"
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DjangoRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "DJ010" for v in violations)

    def test_detect_debug_true(self, tmp_path):
        """Test detection of DEBUG = True."""
        code = '''
from django.conf import settings

DEBUG = True
'''
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = DjangoRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "DJ013" for v in violations)

    def test_rules_registered(self):
        """Test that all Django rules are registered."""
        assert len(DJANGO_RULES) >= 7
        rule_ids = [rule.rule_id for rule in DJANGO_RULES]
        assert "DJ001" in rule_ids
        assert "DJ006" in rule_ids
        assert "DJ010" in rule_ids
        assert "DJ013" in rule_ids
