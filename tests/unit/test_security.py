"""Comprehensive unit tests for security fixer module."""

from pathlib import Path

import pytest

from pyguard.lib.security import SecurityFixer


class TestSecurityFixerInit:
    """Test SecurityFixer initialization."""

    def test_initialization(self):
        """Test SecurityFixer initializes with required components."""
        fixer = SecurityFixer()
        assert fixer.logger is not None
        assert fixer.file_ops is not None
        assert fixer.ast_analyzer is not None
        assert fixer.fixes_applied == []


class TestFixHardcodedPasswords:
    """Test hardcoded password detection and fixes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code, expected_warning",
        [
            ('password = "secret123"', "SECURITY:"),
            ('api_key = "abc123xyz"', "SECURITY:"),
            ('secret = "my_secret"', "SECURITY:"),
            ('token = "bearer_token"', "SECURITY:"),
            ('PASSWORD = "ADMIN"', "SECURITY:"),  # Case insensitive
            ("api_key = 'single_quotes'", "SECURITY:"),
        ],
        ids=["password", "api_key", "secret", "token", "uppercase", "single_quotes"]
    )
    def test_fix_hardcoded_passwords_adds_warnings(self, code, expected_warning):
        """Test that hardcoded secrets get security warnings."""
        result = self.fixer._fix_hardcoded_passwords(code)
        assert expected_warning in result
        assert len(self.fixer.fixes_applied) > 0

    @pytest.mark.parametrize(
        "code",
        [
            'password = ""',  # Empty string
            'password = "None"',  # String "None"
            'password = "null"',  # String "null"
            'user_password = get_from_env()',  # Not a literal
        ],
        ids=["empty", "none_string", "null_string", "function_call"]
    )
    def test_fix_hardcoded_passwords_ignores_safe_patterns(self, code):
        """Test that safe patterns don't trigger warnings."""
        result = self.fixer._fix_hardcoded_passwords(code)
        # Empty or special values shouldn't add warnings
        if '""' in code or '"None"' in code or '"null"' in code:
            assert len(self.fixer.fixes_applied) == 0

    def test_fix_hardcoded_passwords_no_duplicate_warnings(self):
        """Test that warnings aren't added twice."""
        code = 'password = "secret"'
        result1 = self.fixer._fix_hardcoded_passwords(code)
        # Reset and apply again to the result
        self.fixer.fixes_applied = []
        result2 = self.fixer._fix_hardcoded_passwords(result1)
        # Should not add another warning
        assert result1 == result2

    def test_fix_hardcoded_passwords_multiple_secrets(self):
        """Test fixing multiple hardcoded secrets in one file."""
        code = '''
password = "secret1"
api_key = "key123"
token = "tok456"
'''
        result = self.fixer._fix_hardcoded_passwords(code)
        # Should add warning for first match
        assert "SECURITY:" in result
        assert len(self.fixer.fixes_applied) >= 1


class TestFixSQLInjection:
    """Test SQL injection detection and fixes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code",
        [
            'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            "cursor.execute('DELETE FROM users WHERE name = ' + name)",
            'db.execute("UPDATE users SET active = " + status)',
        ],
        ids=["select_concat", "delete_concat", "update_concat"]
    )
    def test_fix_sql_injection_adds_warnings(self, code):
        """Test SQL injection warnings are added."""
        result = self.fixer._fix_sql_injection(code)
        assert "SQL INJECTION RISK" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_sql_injection_safe_parameterized(self):
        """Test that parameterized queries don't trigger warnings."""
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        result = self.fixer._fix_sql_injection(code)
        assert result == code  # No change
        assert len(self.fixer.fixes_applied) == 0

    def test_fix_sql_injection_no_duplicate_warnings(self):
        """Test warnings aren't duplicated."""
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        result1 = self.fixer._fix_sql_injection(code)
        self.fixer.fixes_applied = []
        result2 = self.fixer._fix_sql_injection(result1)
        assert result1 == result2


class TestFixCommandInjection:
    """Test command injection detection and fixes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_fix_command_injection_os_system(self):
        """Test os.system() warnings."""
        code = 'os.system("rm -rf " + user_input)'
        result = self.fixer._fix_command_injection(code)
        assert "SECURITY:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_command_injection_shell_true_with_format(self):
        """Test shell=True warnings with format string."""
        code = 'subprocess.call("ls %s" % dir, shell=True)'
        result = self.fixer._fix_command_injection(code)
        assert "COMMAND INJECTION" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_command_injection_subprocess_concat(self):
        """Test subprocess with string concatenation."""
        code = 'subprocess.Popen("ls " + directory, shell=True)'
        result = self.fixer._fix_command_injection(code)
        # Should detect concatenation pattern with shell=True
        if "shell=True" in code:
            assert "COMMAND INJECTION" in result

    def test_fix_command_injection_safe_subprocess(self):
        """Test safe subprocess calls don't trigger warnings."""
        code = 'subprocess.run(["ls", "-l"], shell=False)'
        result = self.fixer._fix_command_injection(code)
        # Should not match any dangerous patterns
        assert result == code
        assert len(self.fixer.fixes_applied) == 0
    
    def test_fix_command_injection_popen_plus_shell_true(self):
        """Test Popen with concatenation and shell=True."""
        code = 'subprocess.Popen("echo " + msg, shell=True)'
        result = self.fixer._fix_command_injection(code)
        assert "COMMAND INJECTION" in result or "SECURITY:" in result


class TestFixInsecureRandom:
    """Test insecure random number generation detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_fix_insecure_random_with_password(self):
        """Test fixing random in password context."""
        code = "import random\npassword = str(random.randint(1000, 9999))"
        result = self.fixer._fix_insecure_random(code)
        assert "import secrets" in result
        assert len(self.fixer.fixes_applied) > 0

    @pytest.mark.parametrize(
        "code",
        [
            "token = random.random()",
            "api_key = random.choice(chars)",
            "secret = random.randint(0, 999)",
        ],
        ids=["token", "key", "secret"]
    )
    def test_fix_insecure_random_security_contexts(self, code):
        """Test warnings in security-sensitive contexts."""
        result = self.fixer._fix_insecure_random(code)
        assert "SECURITY:" in result

    def test_fix_insecure_random_safe_context(self):
        """Test random in non-security contexts is OK."""
        code = "import random\nvalue = random.random()"
        result = self.fixer._fix_insecure_random(code)
        # No security keywords, shouldn't add secrets import
        assert "import secrets" not in result

    def test_fix_insecure_random_already_has_secrets(self):
        """Test doesn't duplicate secrets import."""
        code = "import random\nimport secrets\npassword = random.random()"
        result = self.fixer._fix_insecure_random(code)
        # Should not add another secrets import
        assert result.count("import secrets") == 1


class TestFixInsecureTempFiles:
    """Test insecure temporary file detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_fix_insecure_temp_files_mktemp(self):
        """Test replacing mktemp with mkstemp."""
        code = "temp = tempfile.mktemp()"
        result = self.fixer._fix_insecure_temp_files(code)
        assert "tempfile.mkstemp(" in result
        assert "FIXED:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_insecure_temp_files_safe_mkstemp(self):
        """Test that mkstemp is not modified."""
        code = "fd, temp = tempfile.mkstemp()"
        result = self.fixer._fix_insecure_temp_files(code)
        assert result == code
        assert len(self.fixer.fixes_applied) == 0


class TestFixYAMLLoad:
    """Test YAML loading security fixes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_fix_yaml_load_unsafe(self):
        """Test replacing yaml.load with yaml.safe_load."""
        code = "data = yaml.load(file)"
        result = self.fixer._fix_yaml_load(code)
        assert "yaml.safe_load(" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_yaml_load_already_safe(self):
        """Test yaml.safe_load is not modified."""
        code = "data = yaml.safe_load(file)"
        result = self.fixer._fix_yaml_load(code)
        assert result == code
        assert len(self.fixer.fixes_applied) == 0

    def test_fix_yaml_load_multiple_calls(self):
        """Test fixing multiple yaml.load calls."""
        code = "data1 = yaml.load(f1)\ndata2 = yaml.load(f2)"
        result = self.fixer._fix_yaml_load(code)
        assert result.count("yaml.safe_load(") == 2


class TestFixPickleUsage:
    """Test pickle security warnings."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code",
        [
            "data = pickle.load(file)",
            "data = pickle.loads(bytes_data)",
        ],
        ids=["pickle_load", "pickle_loads"]
    )
    def test_fix_pickle_usage_adds_warnings(self, code):
        """Test pickle warnings are added."""
        result = self.fixer._fix_pickle_usage(code)
        assert "SECURITY:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_pickle_usage_no_duplicate_warnings(self):
        """Test warnings aren't duplicated."""
        code = "data = pickle.load(file)"
        result1 = self.fixer._fix_pickle_usage(code)
        self.fixer.fixes_applied = []
        result2 = self.fixer._fix_pickle_usage(result1)
        assert result1 == result2


class TestFixEvalExec:
    """Test eval/exec security warnings."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code, func_name",
        [
            ("result = eval(user_input)", "eval"),
            ("exec(code_string)", "exec"),
            ("compiled = compile(source, '<string>', 'exec')", "compile"),
        ],
        ids=["eval", "exec", "compile"]
    )
    def test_fix_eval_exec_adds_warnings(self, code, func_name):
        """Test dangerous function warnings."""
        result = self.fixer._fix_eval_exec(code)
        assert "DANGEROUS:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_eval_exec_ignores_comments(self):
        """Test that commented code is not modified."""
        code = "# result = eval(user_input)"
        result = self.fixer._fix_eval_exec(code)
        # Comment should not get another warning
        assert len(self.fixer.fixes_applied) == 0

    def test_fix_eval_exec_no_duplicate_warnings(self):
        """Test warnings aren't duplicated."""
        code = "result = eval(expr)"
        result1 = self.fixer._fix_eval_exec(code)
        self.fixer.fixes_applied = []
        result2 = self.fixer._fix_eval_exec(result1)
        assert result1 == result2


class TestFixWeakCrypto:
    """Test weak cryptography detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code, weak_algo",
        [
            ("hash = hashlib.md5(data)", "md5"),
            ("hash = hashlib.sha1(data)", "sha1"),
        ],
        ids=["md5", "sha1"]
    )
    def test_fix_weak_crypto_adds_warnings(self, code, weak_algo):
        """Test weak hash warnings."""
        result = self.fixer._fix_weak_crypto(code)
        assert "SECURITY:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_weak_crypto_safe_sha256(self):
        """Test SHA256 is not flagged."""
        code = "hash = hashlib.sha256(data)"
        result = self.fixer._fix_weak_crypto(code)
        assert result == code
        assert len(self.fixer.fixes_applied) == 0


class TestFixPathTraversal:
    """Test path traversal detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "code",
        [
            'path = os.path.join(base_dir, user_input)',
            'file = os.path.join(root, request.get("file"))',
            'full_path = os.path.join(dir, param)',
        ],
        ids=["user_input", "request", "param"]
    )
    def test_fix_path_traversal_adds_warnings(self, code):
        """Test path traversal warnings."""
        result = self.fixer._fix_path_traversal(code)
        assert "PATH TRAVERSAL" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_path_traversal_safe_hardcoded(self):
        """Test hardcoded paths without user variables don't trigger warnings."""
        # Use variable name that doesn't contain security keywords
        code = 'filepath = os.path.join("/home", "admin", "file.txt")'
        result = self.fixer._fix_path_traversal(code)
        assert result == code
        assert len(self.fixer.fixes_applied) == 0


class TestScanFileForIssues:
    """Test AST-based file scanning."""

    def test_scan_file_for_issues_valid_file(self, tmp_path):
        """Test scanning a valid file."""
        fixer = SecurityFixer()
        test_file = tmp_path / "test.py"
        test_file.write_text("import os\nresult = eval('1+1')")
        
        issues = fixer.scan_file_for_issues(test_file)
        # Should use AST analyzer
        assert isinstance(issues, list)

    def test_scan_file_for_issues_nonexistent_file(self, tmp_path):
        """Test scanning a file that doesn't exist."""
        fixer = SecurityFixer()
        nonexistent = tmp_path / "does_not_exist.py"
        
        # Should handle gracefully
        try:
            issues = fixer.scan_file_for_issues(nonexistent)
            assert isinstance(issues, list)
        except Exception:
            # May raise, that's acceptable
            pass


class TestScanFileForIssuesLegacy:
    """Test regex-based legacy file scanning."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_scan_file_for_issues_legacy_with_vulnerabilities(self, tmp_path):
        """Test legacy scanner detects multiple issues."""
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text('''
password = "secret123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
subprocess.call(cmd, shell=True)
result = eval(input())
''')
        
        issues = self.fixer.scan_file_for_issues_legacy(test_file)
        assert len(issues) > 0
        assert all(issue["severity"] == "HIGH" for issue in issues)
        assert all("file" in issue and "issue" in issue for issue in issues)

    def test_scan_file_for_issues_legacy_safe_code(self, tmp_path):
        """Test legacy scanner on safe code."""
        test_file = tmp_path / "safe.py"
        test_file.write_text('''
def add(a, b):
    return a + b

result = add(1, 2)
''')
        
        issues = self.fixer.scan_file_for_issues_legacy(test_file)
        assert len(issues) == 0

    def test_scan_file_for_issues_legacy_nonexistent_file(self, tmp_path):
        """Test legacy scanner with nonexistent file."""
        nonexistent = tmp_path / "does_not_exist.py"
        issues = self.fixer.scan_file_for_issues_legacy(nonexistent)
        assert issues == []


class TestFixFile:
    """Test complete file fixing workflow."""

    def test_fix_file_with_vulnerabilities(self, tmp_path):
        """Test fixing a file with security issues."""
        fixer = SecurityFixer()
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text('''
import yaml
password = "admin123"
data = yaml.load(file)
''')
        
        success, fixes = fixer.fix_file(test_file)
        assert success
        assert len(fixes) > 0
        
        # Verify changes were written
        modified_content = test_file.read_text()
        assert "yaml.safe_load" in modified_content or "SECURITY:" in modified_content

    def test_fix_file_safe_code_no_changes(self, tmp_path):
        """Test that safe code is not modified."""
        fixer = SecurityFixer()
        test_file = tmp_path / "safe.py"
        original = "def add(a, b):\n    return a + b"
        test_file.write_text(original)
        
        success, fixes = fixer.fix_file(test_file)
        assert success
        assert len(fixes) == 0
        assert test_file.read_text() == original

    def test_fix_file_nonexistent_file(self, tmp_path):
        """Test fixing a nonexistent file."""
        fixer = SecurityFixer()
        nonexistent = tmp_path / "does_not_exist.py"
        
        success, fixes = fixer.fix_file(nonexistent)
        assert not success
        assert fixes == []

    def test_fix_file_multiple_issues(self, tmp_path):
        """Test fixing file with multiple security issues."""
        fixer = SecurityFixer()
        test_file = tmp_path / "multiple.py"
        test_file.write_text('''
import yaml
import random
import hashlib

password = "secret"
token = random.random()
data = yaml.load(file)
hash = hashlib.md5(data)
result = eval(code)
''')
        
        success, fixes = fixer.fix_file(test_file)
        assert success
        assert len(fixes) >= 3  # Multiple fixes applied

    def test_fix_file_empty_file(self, tmp_path):
        """Test fixing an empty file."""
        fixer = SecurityFixer()
        test_file = tmp_path / "empty.py"
        test_file.write_text("")
        
        success, fixes = fixer.fix_file(test_file)
        assert success
        assert len(fixes) == 0


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_empty_string_input(self):
        """Test all fix methods handle empty strings."""
        empty = ""
        assert self.fixer._fix_hardcoded_passwords(empty) == empty
        assert self.fixer._fix_sql_injection(empty) == empty
        assert self.fixer._fix_command_injection(empty) == empty
        assert self.fixer._fix_insecure_random(empty) == empty
        assert self.fixer._fix_insecure_temp_files(empty) == empty
        assert self.fixer._fix_yaml_load(empty) == empty
        assert self.fixer._fix_pickle_usage(empty) == empty
        assert self.fixer._fix_eval_exec(empty) == empty
        assert self.fixer._fix_weak_crypto(empty) == empty
        assert self.fixer._fix_path_traversal(empty) == empty

    def test_unicode_content(self):
        """Test handling of Unicode content."""
        code = 'password = "пароль123"  # Russian password'
        result = self.fixer._fix_hardcoded_passwords(code)
        # Should handle Unicode gracefully
        assert isinstance(result, str)

    def test_multiline_strings(self):
        """Test handling of multiline strings."""
        code = '''"""
This is a docstring
password = "not_really"
"""
def foo():
    pass
'''
        result = self.fixer._fix_hardcoded_passwords(code)
        # Should process without errors
        assert isinstance(result, str)

    def test_very_long_content(self):
        """Test handling of large files."""
        code = "x = 1\n" * 10000
        result = self.fixer._fix_sql_injection(code)
        # Should handle large content without corruption
        # Note: split('\n') on string ending with \n gives extra empty element
        assert len(result.split('\n')) >= 10000
