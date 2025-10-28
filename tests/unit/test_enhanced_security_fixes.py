"""Unit tests for enhanced security fixes with real code transformations."""

from pathlib import Path


from pyguard.lib.enhanced_security_fixes import EnhancedSecurityFixer


class TestEnhancedSecurityFixer:
    """Test cases for EnhancedSecurityFixer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer_safe = EnhancedSecurityFixer(allow_unsafe=False)
        self.fixer_unsafe = EnhancedSecurityFixer(allow_unsafe=True)

    # ===== SAFE FIXES TESTS =====

    def test_fix_yaml_safe_load(self):
        """Test yaml.load() → yaml.safe_load() transformation."""
        code = """
import yaml

data = yaml.load(file)
config = yaml.load(stream)
"""

        result = self.fixer_safe._fix_yaml_safe_load(code)

        assert "yaml.safe_load(file)" in result
        assert "yaml.safe_load(stream)" in result
        assert "yaml.load(" not in result
        assert "yaml.load() → yaml.safe_load()" in self.fixer_safe.fixes_applied

    def test_fix_yaml_safe_load_already_safe(self):
        """Test yaml.safe_load() is not modified."""
        code = """
import yaml

data = yaml.safe_load(file)
"""

        result = self.fixer_safe._fix_yaml_safe_load(code)

        assert result == code
        assert len(self.fixer_safe.fixes_applied) == 0

    def test_fix_mktemp_to_mkstemp(self):
        """Test tempfile.mktemp() → tempfile.mkstemp() transformation."""
        code = """
import tempfile

tmp = tempfile.mktemp()
temp_file = tempfile.mktemp(suffix='.txt')
"""

        result = self.fixer_safe._fix_mktemp_to_mkstemp(code)

        assert "_fd, tmp = tempfile.mkstemp()" in result
        assert "_fd, temp_file = tempfile.mkstemp(suffix='.txt')" in result
        assert "tempfile.mktemp()" not in result
        assert "mkstemp()" in " ".join(self.fixer_safe.fixes_applied)

    def test_fix_comparison_to_none_equals(self):
        """Test == None → is None transformation."""
        code = """
if value == None:
    pass
"""

        result = self.fixer_safe._fix_comparison_to_none(code)

        assert "value is None" in result
        assert "== None" not in result
        assert "== None → is None" in self.fixer_safe.fixes_applied

    def test_fix_comparison_to_none_not_equals(self):
        """Test != None → is not None transformation."""
        code = """
if value != None:
    pass
"""

        result = self.fixer_safe._fix_comparison_to_none(code)

        assert "value is not None" in result
        assert "!= None" not in result
        assert "!= None → is not None" in self.fixer_safe.fixes_applied

    def test_fix_insecure_random_adds_secrets_import(self):
        """Test adding secrets import for security contexts."""
        code = """
import random

password = random.randint(1000, 9999)
"""

        result = self.fixer_safe._fix_insecure_random_safe(code)

        assert "import secrets" in result
        assert "# ADDED: Use secrets for cryptographic randomness" in result
        assert "Added secrets import" in " ".join(self.fixer_safe.fixes_applied)

    def test_fix_insecure_random_no_security_context(self):
        """Test secrets import not added without security context."""
        code = """
import random

dice_roll = random.randint(1, 6)
"""

        result = self.fixer_safe._fix_insecure_random_safe(code)

        # Should not add secrets import (no security context)
        assert "import secrets" not in result
        assert len(self.fixer_safe.fixes_applied) == 0

    def test_safe_fixes_applied_to_file(self, tmp_path):
        """Test safe fixes are applied to actual file."""
        test_file = tmp_path / "test_safe.py"
        test_file.write_text(
            """
import yaml
data = yaml.load(file)
if value == None:
    pass
"""
        )

        success, fixes = self.fixer_safe.fix_file(test_file)

        assert success
        assert len(fixes) > 0

        result = test_file.read_text()
        assert "yaml.safe_load" in result
        assert "is None" in result

    # ===== UNSAFE FIXES TESTS =====

    def test_sql_injection_parameterized_concatenation(self):
        """Test SQL injection fix with string concatenation."""
        code = """
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""

        result = self.fixer_unsafe._fix_sql_injection_parameterized(code)

        assert 'cursor.execute("SELECT * FROM users WHERE id = ?"' in result
        assert "(user_id,)" in result
        assert "FIXED: SQL injection" in result
        assert "parameterized query" in " ".join(self.fixer_unsafe.fixes_applied)

    def test_sql_injection_f_string_warning(self):
        """Test SQL injection warning for f-strings."""
        code = """
query = f"SELECT * FROM users WHERE name = '{username}'"
"""

        result = self.fixer_unsafe._fix_sql_injection_parameterized(code)

        assert "SECURITY WARNING: SQL injection via f-string" in result
        assert "UNSAFE FIX: Convert to parameterized query manually" in result
        assert "f-string warning" in " ".join(self.fixer_unsafe.fixes_applied)

    def test_sql_injection_not_applied_without_unsafe_flag(self):
        """Test SQL injection fix not applied without --unsafe-fixes."""
        code = """
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""

        result = self.fixer_safe._fix_sql_injection_parameterized(code)

        # Should not modify code without allow_unsafe
        assert result == code
        assert len(self.fixer_safe.fixes_applied) == 0

    def test_command_injection_os_system_to_subprocess(self):
        """Test os.system() → subprocess.run() transformation."""
        code = """
import os

os.system(cmd)
"""

        result = self.fixer_unsafe._fix_command_injection_subprocess(code)

        assert "subprocess.run(cmd.split(), check=True, shell=False)" in result
        assert "FIXED: command injection" in result
        assert "os.system()" not in result or "subprocess.run" in result
        assert "command injection" in " ".join(self.fixer_unsafe.fixes_applied)

    def test_command_injection_subprocess_import_added(self):
        """Test subprocess import is added if not present."""
        code = """
import os

os.system(cmd)
"""

        result = self.fixer_unsafe._fix_command_injection_subprocess(code)

        assert "import subprocess" in result
        assert "ADDED: for safe command execution" in result

    def test_command_injection_shell_true_disabled(self):
        """Test shell=True → shell=False transformation."""
        code = """
import subprocess

subprocess.run(cmd, shell=True)
"""

        result = self.fixer_unsafe._fix_command_injection_subprocess(code)

        assert "shell=False" in result
        assert "FIXED: command injection" in result
        assert "disabled shell=True" in " ".join(self.fixer_unsafe.fixes_applied)

    def test_command_injection_not_applied_without_unsafe_flag(self):
        """Test command injection fix not applied without --unsafe-fixes."""
        code = """
import os
os.system(cmd)
"""

        result = self.fixer_safe._fix_command_injection_subprocess(code)

        # Should not modify code without allow_unsafe
        assert result == code
        assert len(self.fixer_safe.fixes_applied) == 0

    def test_path_traversal_validation_added(self):
        """Test path traversal validation is added."""
        code = """
import os

file_path = os.path.join(base_dir, user_input)
"""

        result = self.fixer_unsafe._fix_path_traversal_validated(code)

        assert "ADDED: Path traversal protection" in result
        assert "os.path.realpath(file_path)" in result
        assert "Path traversal: added validation" in " ".join(self.fixer_unsafe.fixes_applied)

    def test_path_traversal_no_user_input(self):
        """Test path traversal validation not added without user input."""
        code = """
import os

file_path = os.path.join(base_dir, "config.txt")
"""

        result = self.fixer_unsafe._fix_path_traversal_validated(code)

        # Should not add validation for non-user input
        assert "ADDED: Path traversal protection" not in result
        assert len(self.fixer_unsafe.fixes_applied) == 0

    def test_path_traversal_not_applied_without_unsafe_flag(self):
        """Test path traversal fix not applied without --unsafe-fixes."""
        code = """
import os
file_path = os.path.join(base_dir, user_input)
"""

        result = self.fixer_safe._fix_path_traversal_validated(code)

        # Should not modify code without allow_unsafe
        assert result == code
        assert len(self.fixer_safe.fixes_applied) == 0

    def test_unsafe_fixes_applied_to_file(self, tmp_path):
        """Test unsafe fixes are applied to actual file with flag."""
        test_file = tmp_path / "test_unsafe.py"
        test_file.write_text(
            """
import os
os.system(cmd)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""
        )

        success, fixes = self.fixer_unsafe.fix_file(test_file)

        assert success
        assert len(fixes) > 0

        result = test_file.read_text()
        assert "subprocess.run" in result
        assert "parameterized query" in result.lower() or "?" in result

    def test_unsafe_fixes_not_applied_to_file_without_flag(self, tmp_path):
        """Test unsafe fixes are not applied without --unsafe-fixes flag."""
        test_file = tmp_path / "test_no_unsafe.py"
        test_file.write_text(
            """
import os
os.system(cmd)
"""
        )

        success, fixes = self.fixer_safe.fix_file(test_file)

        # Should succeed but apply no unsafe fixes
        assert success
        assert len(fixes) == 0

        result = test_file.read_text()
        assert "os.system(cmd)" in result
        assert "subprocess.run" not in result

    # ===== INTEGRATION TESTS =====

    def test_mixed_safe_and_unsafe_fixes(self, tmp_path):
        """Test both safe and unsafe fixes together."""
        test_file = tmp_path / "test_mixed.py"
        test_file.write_text(
            """
import yaml
import os

data = yaml.load(file)
os.system(cmd)
if value == None:
    pass
"""
        )

        success, fixes = self.fixer_unsafe.fix_file(test_file)

        assert success
        assert len(fixes) >= 3  # yaml, os.system, == None

        result = test_file.read_text()
        assert "yaml.safe_load" in result
        assert "subprocess.run" in result
        assert "is None" in result

    def test_get_fix_statistics(self):
        """Test fix statistics retrieval."""
        stats = self.fixer_safe.get_fix_statistics()

        assert "total" in stats
        assert "safe" in stats
        assert "unsafe" in stats
        assert "warning_only" in stats
        assert "fixes_applied" in stats
        assert "allow_unsafe" in stats

        assert not stats["allow_unsafe"]

        stats_unsafe = self.fixer_unsafe.get_fix_statistics()
        assert stats_unsafe["allow_unsafe"]

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        success, fixes = self.fixer_safe.fix_file(Path("/nonexistent/file.py"))

        assert not success
        assert len(fixes) == 0

    def test_preserves_indentation(self):
        """Test that fixes preserve original indentation."""
        code = """
def foo():
    if value == None:
        data = yaml.load(file)
"""

        result = self.fixer_safe._fix_comparison_to_none(code)
        result = self.fixer_safe._fix_yaml_safe_load(result)

        # Check indentation is preserved
        assert "    if value is None:" in result
        assert "        data = yaml.safe_load(file)" in result

    def test_multiple_fixes_same_line(self):
        """Test multiple fixes on the same code element."""
        code = """
if x == None and y == None:
    pass
"""

        result = self.fixer_safe._fix_comparison_to_none(code)

        assert "x is None and y is None" in result
        assert "== None" not in result


class TestEnhancedSecurityFixerEdgeCases:
    """Test edge cases for enhanced security fixer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = EnhancedSecurityFixer(allow_unsafe=True)

    def test_yaml_load_in_string_not_modified(self):
        """Test yaml.load() in strings is not modified."""
        code = """
comment = "Use yaml.load() carefully"
"""

        result = self.fixer._fix_yaml_safe_load(code)

        # String should not be modified
        assert code == result

    def test_sql_with_no_variables(self):
        """Test SQL without variables is not flagged."""
        code = """
cursor.execute("SELECT * FROM users")
"""

        result = self.fixer._fix_sql_injection_parameterized(code)

        # No concatenation, should not be modified
        assert "FIXED" not in result

    def test_os_system_in_comment_not_modified(self):
        """Test os.system() in comments is not modified."""
        code = """
# Don't use os.system(cmd) here
subprocess.run(cmd)
"""

        result = self.fixer._fix_command_injection_subprocess(code)

        # Comment should remain unchanged
        assert "# Don't use os.system(cmd) here" in result
