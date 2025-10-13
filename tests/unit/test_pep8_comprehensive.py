"""Tests for PEP 8 comprehensive checking and fixing."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules
from pyguard.lib.rule_engine import RuleCategory, RuleSeverity


class TestPEP8Checker:
    """Test PEP8Checker class."""
    
    def test_initialization(self):
        """Test checker initialization."""
        checker = PEP8Checker()
        assert checker.max_line_length == 79
        assert checker.violations == []
        
        checker = PEP8Checker(max_line_length=100)
        assert checker.max_line_length == 100


class TestIndentationChecks:
    """Test indentation checks (E1xx)."""
    
    def test_e101_mixed_spaces_tabs(self):
        """Test E101: Mixed spaces and tabs."""
        code = "def foo():\n\t    pass  # Mixed tab and spaces\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            # Should detect mixed spaces/tabs
            e101_violations = [v for v in violations if v.rule_id == 'E101']
            assert len(e101_violations) > 0
        finally:
            path.unlink()
    
    def test_e111_indentation_not_multiple_of_four(self):
        """Test E111: Indentation not multiple of 4."""
        code = "def foo():\n  pass  # 2 spaces\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            # Should detect incorrect indentation
            e111_violations = [v for v in violations if v.rule_id == 'E111']
            assert len(e111_violations) > 0
        finally:
            path.unlink()
    
    def test_fix_mixed_tabs(self):
        """Test fixing mixed tabs and spaces."""
        code = "def foo():\n\t    pass  # Mixed\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            # Read fixed content
            with open(path, 'r') as f:
                fixed = f.read()
            
            # Should not contain tabs in indentation
            assert '\t' not in fixed or '\t' not in fixed.split('\n')[1][:10]
        finally:
            path.unlink()


class TestWhitespaceChecks:
    """Test whitespace checks (E2xx)."""
    
    def test_e201_whitespace_after_paren(self):
        """Test E201: Whitespace after '('."""
        code = "func( arg)\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e201_violations = [v for v in violations if v.rule_id == 'E201']
            assert len(e201_violations) > 0
        finally:
            path.unlink()
    
    def test_e202_whitespace_before_paren(self):
        """Test E202: Whitespace before ')'."""
        code = "func(arg )\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e202_violations = [v for v in violations if v.rule_id == 'E202']
            assert len(e202_violations) > 0
        finally:
            path.unlink()
    
    def test_e231_missing_whitespace_after_comma(self):
        """Test E231: Missing whitespace after comma."""
        code = "items = [1,2,3]\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e231_violations = [v for v in violations if v.rule_id == 'E231']
            assert len(e231_violations) > 0
        finally:
            path.unlink()
    
    def test_fix_whitespace_issues(self):
        """Test fixing whitespace issues."""
        code = "func( arg )\nitems = [1,2,3]\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            with open(path, 'r') as f:
                fixed = f.read()
            
            # Should fix whitespace
            assert 'func(arg)' in fixed
            assert '[1, 2, 3]' in fixed
        finally:
            path.unlink()


class TestBlankLineChecks:
    """Test blank line checks (E3xx)."""
    
    def test_e301_expected_one_blank_line(self):
        """Test E301: Expected 1 blank line."""
        code = """class Foo:
    def method1(self):
        pass
    def method2(self):
        pass
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e301_violations = [v for v in violations if v.rule_id == 'E301']
            assert len(e301_violations) > 0
        finally:
            path.unlink()
    
    def test_e302_expected_two_blank_lines(self):
        """Test E302: Expected 2 blank lines."""
        code = """import os
def foo():
    pass
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e302_violations = [v for v in violations if v.rule_id == 'E302']
            assert len(e302_violations) > 0
        finally:
            path.unlink()


class TestImportChecks:
    """Test import checks (E4xx)."""
    
    def test_e401_multiple_imports(self):
        """Test E401: Multiple imports on one line."""
        code = "import os, sys\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e401_violations = [v for v in violations if v.rule_id == 'E401']
            assert len(e401_violations) > 0
        finally:
            path.unlink()
    
    def test_e402_import_not_at_top(self):
        """Test E402: Import not at top of file."""
        code = """x = 5
import os
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e402_violations = [v for v in violations if v.rule_id == 'E402']
            assert len(e402_violations) > 0
        finally:
            path.unlink()


class TestLineLengthChecks:
    """Test line length checks (E5xx)."""
    
    def test_e501_line_too_long(self):
        """Test E501: Line too long."""
        code = "x = " + "a" * 100 + "\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker(max_line_length=79)
            violations = checker.check_file(path)
            
            e501_violations = [v for v in violations if v.rule_id == 'E501']
            assert len(e501_violations) > 0
        finally:
            path.unlink()
    
    def test_custom_line_length(self):
        """Test custom line length."""
        code = "x = " + "a" * 90 + "\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            # Should not violate with max_line_length=100
            checker = PEP8Checker(max_line_length=100)
            violations = checker.check_file(path)
            
            e501_violations = [v for v in violations if v.rule_id == 'E501']
            assert len(e501_violations) == 0
        finally:
            path.unlink()


class TestStatementChecks:
    """Test statement checks (E7xx)."""
    
    def test_e702_multiple_statements_semicolon(self):
        """Test E702: Multiple statements on one line (semicolon)."""
        code = "x = 1; y = 2\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e702_violations = [v for v in violations if v.rule_id == 'E702']
            assert len(e702_violations) > 0
        finally:
            path.unlink()
    
    def test_e703_trailing_semicolon(self):
        """Test E703: Statement ends with unnecessary semicolon."""
        code = "x = 1;\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            e703_violations = [v for v in violations if v.rule_id == 'E703']
            assert len(e703_violations) > 0
        finally:
            path.unlink()
    
    def test_fix_trailing_semicolon(self):
        """Test fixing trailing semicolons."""
        code = "x = 1;\ny = 2;\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            with open(path, 'r') as f:
                fixed = f.read()
            
            # Semicolons should be removed
            assert ';' not in fixed
        finally:
            path.unlink()


class TestWarningChecks:
    """Test warning checks (W codes)."""
    
    def test_w291_trailing_whitespace(self):
        """Test W291: Trailing whitespace."""
        code = "x = 1  \n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            w291_violations = [v for v in violations if v.rule_id == 'W291']
            assert len(w291_violations) > 0
        finally:
            path.unlink()
    
    def test_w292_no_newline_at_eof(self):
        """Test W292: No newline at end of file."""
        code = "x = 1"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            w292_violations = [v for v in violations if v.rule_id == 'W292']
            assert len(w292_violations) > 0
        finally:
            path.unlink()
    
    def test_w293_blank_line_whitespace(self):
        """Test W293: Blank line contains whitespace."""
        code = "x = 1\n  \ny = 2\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            w293_violations = [v for v in violations if v.rule_id == 'W293']
            assert len(w293_violations) > 0
        finally:
            path.unlink()
    
    def test_fix_trailing_whitespace(self):
        """Test fixing trailing whitespace."""
        code = "x = 1  \ny = 2  \n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            with open(path, 'r') as f:
                lines = f.readlines()
            
            # No line should have trailing whitespace (except newline)
            for line in lines:
                assert line.rstrip('\n') == line.rstrip() or line == '\n'
        finally:
            path.unlink()
    
    def test_fix_no_newline_at_eof(self):
        """Test fixing missing newline at end of file."""
        code = "x = 1"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            with open(path, 'r') as f:
                content = f.read()
            
            # Should end with newline
            assert content.endswith('\n')
        finally:
            path.unlink()


class TestIntegration:
    """Test integration of multiple checks."""
    
    def test_multiple_violations(self):
        """Test detecting multiple violation types."""
        code = """import os, sys
x = 1;
func( arg )
y = 2  
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            violations = checker.check_file(path)
            
            # Should detect multiple types
            assert len(violations) > 3
            
            # Check we have different violation types
            violation_codes = {v.rule_id for v in violations}
            assert len(violation_codes) > 2
        finally:
            path.unlink()
    
    def test_comprehensive_fix(self):
        """Test fixing multiple violation types."""
        code = """import os, sys
x = 1;
y = 2  
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker()
            success, fixes = checker.fix_file(path)
            
            assert success
            assert fixes > 0
            
            # Check violations after fix
            violations_after = checker.check_file(path)
            auto_fixable_after = [v for v in violations_after if v.fix_applicability.value == 'automatic']
            
            # Should have fewer auto-fixable violations
            assert len(auto_fixable_after) < 3
        finally:
            path.unlink()
    
    def test_clean_file_no_violations(self):
        """Test that clean code has no violations."""
        code = """import os
import sys


def foo():
    x = 1
    y = 2
    return x + y


class Bar:
    def method(self):
        pass
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            path = Path(f.name)
        
        try:
            checker = PEP8Checker(max_line_length=100)
            violations = checker.check_file(path)
            
            # Clean code should have minimal or no violations
            critical_violations = [v for v in violations if v.severity == RuleSeverity.HIGH]
            assert len(critical_violations) == 0
        finally:
            path.unlink()


class TestPEP8Rules:
    """Test PEP8Rules class."""
    
    def test_get_all_rules(self):
        """Test getting all PEP 8 rules."""
        rules = PEP8Rules.get_all_rules()
        
        # Should have many rules
        assert len(rules) > 15
        
        # All should be style category
        assert all(r.category == RuleCategory.STYLE for r in rules)
        
        # Should have various rule IDs
        rule_ids = {r.rule_id for r in rules}
        assert 'E101' in rule_ids
        assert 'E201' in rule_ids
        assert 'E401' in rule_ids
        assert 'E501' in rule_ids
        assert 'E701' in rule_ids
        assert 'W291' in rule_ids
    
    def test_indentation_rules(self):
        """Test indentation rules."""
        rules = PEP8Rules._get_indentation_rules()
        assert len(rules) >= 2
        assert any(r.rule_id == 'E101' for r in rules)
        assert any(r.rule_id == 'E111' for r in rules)
    
    def test_whitespace_rules(self):
        """Test whitespace rules."""
        rules = PEP8Rules._get_whitespace_rules()
        assert len(rules) >= 5
        assert any(r.rule_id == 'E201' for r in rules)
        assert any(r.rule_id == 'E231' for r in rules)
    
    def test_blank_line_rules(self):
        """Test blank line rules."""
        rules = PEP8Rules._get_blank_line_rules()
        assert len(rules) >= 2
        assert any(r.rule_id == 'E301' for r in rules)
    
    def test_import_rules(self):
        """Test import rules."""
        rules = PEP8Rules._get_import_rules()
        assert len(rules) >= 2
        assert any(r.rule_id == 'E401' for r in rules)
    
    def test_line_length_rules(self):
        """Test line length rules."""
        rules = PEP8Rules._get_line_length_rules()
        assert len(rules) >= 1
        assert any(r.rule_id == 'E501' for r in rules)
    
    def test_statement_rules(self):
        """Test statement rules."""
        rules = PEP8Rules._get_statement_rules()
        assert len(rules) >= 3
        assert any(r.rule_id == 'E701' for r in rules)
        assert any(r.rule_id == 'E703' for r in rules)
    
    def test_warning_rules(self):
        """Test warning rules."""
        rules = PEP8Rules._get_warning_rules()
        assert len(rules) >= 3
        assert any(r.rule_id == 'W291' for r in rules)
        assert any(r.rule_id == 'W292' for r in rules)
