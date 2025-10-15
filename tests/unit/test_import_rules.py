"""Tests for import rules module."""

from pathlib import Path

import pytest

from pyguard.lib.import_rules import IMPORT_RULES, ImportRulesChecker


class TestImportRulesDetection:
    """Test detection of import-related issues."""

    def test_detect_banned_imports(self, tmp_path):
        """Test detection of banned imports."""
        code = """
import os.path
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = ImportRulesChecker()
        violations = checker.check_file(file_path)

        assert len(violations) > 0
        assert any(v.rule_id == "TID001" for v in violations)

    def test_detect_future_imports_position(self, tmp_path):
        """Test detection of __future__ imports not at top."""
        code = """
import sys
import os
# Some comment
# Another comment
# More code
# Even more
# Getting further
# Line 10
# Line 11
from __future__ import annotations
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = ImportRulesChecker()
        violations = checker.check_file(file_path)

        # Should detect __future__ import not at top
        assert any(v.rule_id == "TID004" for v in violations)

    def test_detect_unsorted_imports(self, tmp_path):
        """Test detection of unsorted imports."""
        code = """
import third_party
import sys
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = ImportRulesChecker()
        violations = checker.check_file(file_path)

        # Should detect import order issue
        assert any(v.rule_id == "I001" for v in violations)

    def test_detect_type_checking_imports(self, tmp_path):
        """Test detection of type-only imports."""
        code = """
from typing import Protocol

class MyClass:
    pass
"""
        file_path = tmp_path / "test.py"
        file_path.write_text(code)

        checker = ImportRulesChecker()
        violations = checker.check_file(file_path)

        # Should suggest moving to TYPE_CHECKING block
        assert any(v.rule_id == "TCH001" for v in violations)

    def test_rules_registered(self):
        """Test that all import rules are registered."""
        assert len(IMPORT_RULES) >= 8
        rule_ids = [rule.rule_id for rule in IMPORT_RULES]
        assert "TID001" in rule_ids
        assert "TID002" in rule_ids
        assert "TCH001" in rule_ids
        assert "I001" in rule_ids
