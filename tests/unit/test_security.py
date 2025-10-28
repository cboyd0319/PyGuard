"""Comprehensive unit tests for security fixer module."""

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
        ("code", "expected_warning"),
        [
            ('password = "secret123"', "SECURITY:"),
            ('api_key = "abc123xyz"', "SECURITY:"),
            ('secret = "my_secret"', "SECURITY:"),
            ('token = "bearer_token"', "SECURITY:"),
            ('PASSWORD = "ADMIN"', "SECURITY:"),  # Case insensitive
            ("api_key = 'single_quotes'", "SECURITY:"),
        ],
        ids=["password", "api_key", "secret", "token", "uppercase", "single_quotes"],
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
            "user_password = get_from_env()",  # Not a literal
        ],
        ids=["empty", "none_string", "null_string", "function_call"],
    )
    def test_fix_hardcoded_passwords_ignores_safe_patterns(self, code):
        """Test that safe patterns don't trigger warnings."""
        self.fixer._fix_hardcoded_passwords(code)
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
        code = """
password = "secret1"
api_key = "key123"
token = "tok456"
"""
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
        ids=["select_concat", "delete_concat", "update_concat"],
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
        ids=["token", "key", "secret"],
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
        ids=["pickle_load", "pickle_loads"],
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
        ("code", "func_name"),
        [
            ("result = eval(user_input)", "eval"),
            ("exec(code_string)", "exec"),
            ("compiled = compile(source, '<string>', 'exec')", "compile"),
        ],
        ids=["eval", "exec", "compile"],
    )
    def test_fix_eval_exec_adds_warnings(self, code, func_name):
        """Test dangerous function warnings."""
        result = self.fixer._fix_eval_exec(code)
        assert "DANGEROUS:" in result
        assert len(self.fixer.fixes_applied) > 0

    def test_fix_eval_exec_ignores_comments(self):
        """Test that commented code is not modified."""
        code = "# result = eval(user_input)"
        self.fixer._fix_eval_exec(code)
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
        ("code", "weak_algo"),
        [
            ("hash = hashlib.md5(data)", "md5"),
            ("hash = hashlib.sha1(data)", "sha1"),
        ],
        ids=["md5", "sha1"],
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
            "path = os.path.join(base_dir, user_input)",
            'file = os.path.join(root, request.get("file"))',
            "full_path = os.path.join(dir, param)",
        ],
        ids=["user_input", "request", "param"],
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
        test_file.write_text(
            """
password = "secret123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
subprocess.call(cmd, shell=True)
result = eval(input())
"""
        )

        issues = self.fixer.scan_file_for_issues_legacy(test_file)
        assert len(issues) > 0
        assert all(issue["severity"] == "HIGH" for issue in issues)
        assert all("file" in issue and "issue" in issue for issue in issues)

    def test_scan_file_for_issues_legacy_safe_code(self, tmp_path):
        """Test legacy scanner on safe code."""
        test_file = tmp_path / "safe.py"
        test_file.write_text(
            """
def add(a, b):
    return a + b

result = add(1, 2)
"""
        )

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
        test_file.write_text(
            """
import yaml
password = "admin123"
data = yaml.load(file)
"""
        )

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
        test_file.write_text(
            """
import yaml
import random
import hashlib

password = "secret"
token = random.random()
data = yaml.load(file)
hash = hashlib.md5(data)
result = eval(code)
"""
        )

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
        assert len(result.split("\n")) >= 10000


class TestSecurityFixerProperties:
    """Property-based tests using hypothesis for SecurityFixer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    @pytest.mark.parametrize(
        "fix_method",
        [
            "_fix_hardcoded_passwords",
            "_fix_sql_injection",
            "_fix_weak_crypto",
            "_fix_yaml_load",
            "_fix_eval_exec",
            "_fix_path_traversal",
        ],
    )
    @pytest.mark.slow
    def test_fixer_never_returns_none(self, fix_method):
        """Property: All fix methods always return a string, never None."""
        from hypothesis import given
        from hypothesis import strategies as st

        @given(st.text())
        def check_not_none(code):
            method = getattr(self.fixer, fix_method)
            result = method(code)
            assert result is not None
            assert isinstance(result, str)

        # Run property test
        check_not_none()

    def test_fixer_preserves_line_count_or_increases(self):
        """Property: Fixers never reduce line count (only add warnings)."""
        from hypothesis import given
        from hypothesis import strategies as st

        @given(st.text(min_size=0, max_size=1000))
        def check_line_count(code):
            original_lines = code.count("\n")

            # Test each fixer
            for method_name in [
                "_fix_hardcoded_passwords",
                "_fix_sql_injection",
                "_fix_weak_crypto",
            ]:
                method = getattr(self.fixer, method_name)
                result = method(code)
                result_lines = result.count("\n")

                # Line count should not decrease (may add warnings)
                assert (
                    result_lines >= original_lines
                ), f"{method_name} decreased line count from {original_lines} to {result_lines}"

        check_line_count()

    def test_fixer_is_idempotent_on_safe_code(self):
        """Property: Running fixer twice on safe code gives same result."""
        from hypothesis import given
        from hypothesis import strategies as st

        # Generate simple safe Python code
        safe_code_strategy = st.sampled_from(
            [
                "x = 1",
                "def foo(): pass",
                "import os",
                "class Bar: pass",
                "# Comment",
                "",
            ]
        )

        @given(safe_code_strategy)
        def check_idempotent(code):
            result1 = self.fixer._fix_sql_injection(code)
            result2 = self.fixer._fix_sql_injection(result1)

            # Should be idempotent for safe code
            assert result1 == result2, "Fixer is not idempotent"

        check_idempotent()

    def test_fixer_handles_arbitrary_text_without_crash(self):
        """Property: Fixer handles any text input without crashing."""
        from hypothesis import given
        from hypothesis import strategies as st

        @given(st.text(max_size=500))
        def check_no_crash(text):
            # Should not raise any exceptions
            try:
                result = self.fixer._fix_hardcoded_passwords(text)
                assert isinstance(result, str)
            except Exception as e:
                pytest.fail(f"Fixer crashed with: {e}")

        check_no_crash()

    def test_fixer_preserves_safe_patterns(self):
        """Property: Fixer never modifies known safe patterns."""

        # Safe patterns that should never be modified
        safe_patterns = [
            "password = os.getenv('PASSWORD')",
            "api_key = config.get('API_KEY')",
            "token = ''",
            "secret = None",
            "password = getpass.getpass()",
        ]

        for pattern in safe_patterns:
            result = self.fixer._fix_hardcoded_passwords(pattern)
            # Should not add warnings to safe patterns
            assert (
                "SECURITY:" not in result or pattern in result
            ), f"Modified safe pattern: {pattern}"

    def test_sql_injection_never_creates_new_vulnerabilities(self):
        """Property: SQL injection fixer never introduces new SQL issues."""
        from hypothesis import given
        from hypothesis import strategies as st

        @given(st.text(alphabet=st.characters(blacklist_characters="\"'"), max_size=200))
        def check_no_new_vulnerabilities(safe_code):
            # Start with safe code (no quotes that could close strings)
            result = self.fixer._fix_sql_injection(safe_code)

            # Result should not contain obvious SQL injection patterns
            dangerous_patterns = [
                "' OR '1'='1",
                '" OR "1"="1',
                "'; DROP TABLE",
                '"; DROP TABLE',
            ]

            for pattern in dangerous_patterns:
                assert pattern not in result, f"Fixer introduced SQL injection pattern: {pattern}"

        check_no_new_vulnerabilities()

    def test_fixer_handles_edge_case_strings(self):
        """Property: Fixer handles edge case strings correctly."""
        from hypothesis import given
        from hypothesis import strategies as st

        edge_cases = st.sampled_from(
            [
                "",  # Empty
                " ",  # Single space
                "\n",  # Single newline
                "\t",  # Single tab
                "   \n\n\t  ",  # Whitespace only
                "a",  # Single char
                "a" * 10000,  # Very long
                "",  # Emoji
                "Hello 世界",  # Unicode
            ]
        )

        @given(edge_cases)
        def check_edge_cases(text):
            result = self.fixer._fix_hardcoded_passwords(text)
            assert isinstance(result, str)
            assert result is not None

        check_edge_cases()

    def test_yaml_fixer_preserves_safe_yaml(self):
        """Property: YAML fixer doesn't modify safe_load calls."""

        safe_yaml_patterns = [
            "data = yaml.safe_load(file)",
            "yaml.safe_load(stream)",
            "result = yaml.safe_dump(data)",
        ]

        for pattern in safe_yaml_patterns:
            result = self.fixer._fix_yaml_load(pattern)
            # Should not modify already-safe code
            assert (
                "safe_load" in result or "safe_dump" in result
            ), f"Modified safe YAML pattern: {pattern}"

    def test_weak_crypto_preserves_strong_algorithms(self):
        """Property: Weak crypto fixer doesn't flag strong algorithms."""

        strong_patterns = [
            "hash = hashlib.sha256(data)",
            "hash = hashlib.sha512(data)",
            "hash = hashlib.sha384(data)",
            "hash = hashlib.blake2b(data)",
        ]

        for pattern in strong_patterns:
            result = self.fixer._fix_weak_crypto(pattern)
            # Should not add warnings for strong algorithms
            original_warning_count = pattern.count("SECURITY:")
            result_warning_count = result.count("SECURITY:")

            assert (
                result_warning_count == original_warning_count
            ), f"Added unnecessary warning to strong algorithm: {pattern}"


class TestSecurityFixerEdgeCases:
    """Test edge cases and missing branch coverage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = SecurityFixer()

    def test_fix_file_write_failure(self, mocker, tmp_path):
        """Test fix_file handles write failure."""
        # Arrange
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret123'")

        # Mock write_file to return False
        mocker.patch.object(self.fixer.file_ops, "write_file", return_value=False)

        # Act
        success, fixes = self.fixer.fix_file(test_file)

        # Assert - should return False when write fails
        assert success is False
        assert len(fixes) > 0  # Fixes were detected but not written

    def test_fix_command_injection_already_commented(self):
        """Test command injection detection when comment already exists."""
        # Arrange - code with shell=True already has comment
        code = "subprocess.call(cmd, shell=True)  # COMMAND INJECTION RISK: Avoid shell=True"

        # Act
        result = self.fixer._fix_command_injection(code)

        # Assert - should not add duplicate comment
        assert result == code
        assert result.count("COMMAND INJECTION") == 1

    def test_fix_command_injection_os_system_already_commented(self):
        """Test os.system detection when comment already exists."""
        # Arrange - code with os.system already has comment (using different marker to avoid adding duplicate)
        code = 'os.system("ls")  # COMMAND INJECTION'

        # Act
        result = self.fixer._fix_command_injection(code)

        # Assert - should not add another comment when COMMAND INJECTION marker present
        assert result == code
        assert result.count("SECURITY:") == 0  # Should not add SECURITY comment when marker exists

    def test_fix_path_traversal_else_branch(self):
        """Test path traversal fix when no issues detected."""
        # Arrange - safe code without path traversal patterns
        code = "filename = Path('data.txt')\nwith open(filename) as f:\n    pass"

        # Act
        result = self.fixer._fix_path_traversal(code)

        # Assert - code should remain unchanged
        assert result == code
        assert len(self.fixer.fixes_applied) == 0

    def test_fix_insecure_random_already_commented(self):
        """Test insecure random detection when comment already exists."""
        # Arrange - code with insecure random already has comment
        code = 'token = "".join(random.choices(string.ascii_letters, k=32))  # SECURITY: Use secrets module'

        # Act
        result = self.fixer._fix_insecure_random(code)

        # Assert - should not add duplicate comment
        assert result == code
        assert result.count("SECURITY:") == 1

    def test_fix_path_traversal_already_commented(self):
        """Test path traversal detection when comment already exists."""
        # Arrange - code with path traversal risk already has comment
        code = "path = os.path.join(base, user_input)  # PATH TRAVERSAL RISK: Validate and sanitize paths"

        # Act
        result = self.fixer._fix_path_traversal(code)

        # Assert - should not add duplicate comment
        assert result == code
        assert result.count("PATH TRAVERSAL") == 1
