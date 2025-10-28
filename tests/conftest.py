"""
Pytest configuration and shared fixtures for PyGuard tests.

Following PyTest Architect Agent best practices:
- Deterministic RNG seeding (autouse fixture)
- Composable, small fixtures
- AAA pattern support
- Clear, explicit test data factories
- No hidden state or dependencies
"""

import random
import shutil
import tempfile
from pathlib import Path

import pytest


# Deterministic random seed for all tests - PyTest Architect Agent principle
@pytest.fixture(autouse=True)
def _seed_rng(monkeypatch):
    """
    Seed random number generators for deterministic tests.

    Applied automatically to all tests to prevent flakiness from randomness.
    Uses function scope to ensure fresh seed for each test.
    """
    random.seed(1337)
    try:
        import numpy as np

        np.random.seed(1337)
    except ImportError:
        pass

    # Also seed hash randomization for dict/set ordering
    monkeypatch.setenv("PYTHONHASHSEED", "0")


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file in the temp directory."""

    def _create_file(name: str, content: str = "") -> Path:
        file_path = temp_dir / name
        file_path.write_text(content)
        return file_path

    return _create_file


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Python code for testing."""
    return """
import random
import yaml
password = "admin123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

token = random.random()
data = yaml.load(file)
"""


@pytest.fixture
def sample_bad_practices_code():
    """Sample code with bad practices."""
    return """
def foo(x=[]):
    x.append(1)
    return x

try:
    pass
except:
    pass

if x == None:
    pass
"""


@pytest.fixture
def sample_modern_code():
    """Sample code that can be modernized."""
    return """
# Old-style string formatting
message = "Hello %s" % name
path = "%s/%s" % (dir, file)

# Old-style type checking
if type(x) == list:
    pass

# Dict comprehension from loops
d = {}
for k, v in items:
    d[k] = v
"""


@pytest.fixture
def sample_async_code():
    """Sample async code for testing."""
    return """
import asyncio

async def fetch_data():
    # Blocking call in async function
    with open('file.txt') as f:
        data = f.read()
    return data

async def process():
    await fetch_data()
"""


@pytest.fixture
def sample_file(temp_dir, sample_vulnerable_code):
    """Create a temporary Python file with sample code."""
    file_path = temp_dir / "test_file.py"
    file_path.write_text(sample_vulnerable_code)
    return file_path


@pytest.fixture
def fixtures_dir():
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def mock_logger(monkeypatch):
    """Mock the PyGuardLogger for testing."""
    logs = []

    class MockLogger:
        def info(self, message, **kwargs):
            logs.append(("INFO", message, kwargs))

        def warning(self, message, **kwargs):
            logs.append(("WARNING", message, kwargs))

        def error(self, message, exception=None, **kwargs):
            logs.append(("ERROR", message, kwargs))

        def success(self, message, **kwargs):
            logs.append(("SUCCESS", message, kwargs))

    return MockLogger(), logs


@pytest.fixture
def python_file_factory(temp_dir):
    """Factory to create Python files with various content."""
    created_files = []

    def _create(filename: str, content: str) -> Path:
        path = temp_dir / filename
        path.write_text(content)
        created_files.append(path)
        return path

    yield _create

    # Cleanup
    for path in created_files:
        if path.exists():
            path.unlink()


@pytest.fixture
def sample_code_patterns():
    """Common code patterns for testing."""
    return {
        "sql_injection": 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        "hardcoded_password": 'password = "secret123"',
        "weak_hash": "hash = hashlib.md5(data)",
        "eval_usage": "result = eval(user_input)",
        "yaml_unsafe": "data = yaml.load(file)",
        "pickle_load": "data = pickle.load(file)",
        "os_system": 'os.system("rm -rf " + path)',
        "random_insecure": "token = random.random()",
        "shell_true": "subprocess.call(cmd, shell=True)",
        "path_traversal": "path = os.path.join(base, user_input)",
    }


@pytest.fixture
def freeze_2025_01_01():
    """Freeze time to 2025-01-01 00:00:00 UTC for deterministic time testing."""
    try:
        from freezegun import freeze_time

        with freeze_time("2025-01-01 00:00:00"):
            yield
    except ImportError:
        # If freezegun not installed, just yield without freezing
        yield


@pytest.fixture
def env(monkeypatch):
    """Fixture to set environment variables safely."""

    def _set(**kwargs):
        for key, value in kwargs.items():
            monkeypatch.setenv(key, str(value))

    return _set


@pytest.fixture
def ast_tree_factory():
    """Factory to create AST trees from code strings."""
    import ast

    def _create(code: str):
        """Parse code and return AST tree."""
        try:
            return ast.parse(code)
        except SyntaxError:
            return None

    return _create


@pytest.fixture
def code_fixer_factory():
    """Factory to create various code fixer instances for testing."""

    def _create(fixer_type: str):
        """Create a fixer instance based on type."""
        from pyguard.lib import best_practices, formatting, security

        fixers = {
            "security": security.SecurityFixer,
            "best_practices": best_practices.BestPracticesFixer,
            "formatting": formatting.FormattingFixer,
        }

        fixer_class = fixers.get(fixer_type)
        if fixer_class:
            return fixer_class()
        raise ValueError(f"Unknown fixer type: {fixer_type}")

    return _create


@pytest.fixture(autouse=True)
def reset_singleton_state():
    """Reset any singleton state between tests to ensure isolation."""
    return
    # Add any singleton reset logic here if needed


@pytest.fixture
def sample_edge_cases():
    """Edge case inputs for testing."""
    return {
        "empty_string": "",
        "none_value": None,
        "zero": 0,
        "negative": -1,
        "large_number": 10**6,
        "unicode": "Hello 世界 🌍",
        "special_chars": "!@#$%^&*()",
        "whitespace": "   \t\n   ",
        "single_char": "a",
        "long_string": "a" * 10000,
    }


# ============================================================================
# Enhanced Fixtures - Following PyTest Architect Agent Guidelines
# ============================================================================


@pytest.fixture
def isolated_temp_cwd(tmp_path, monkeypatch):
    """
    Create isolated temp directory and change to it.

    Ensures tests don't pollute the working directory and are fully isolated.
    """
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def mock_file_system(tmp_path):
    """
    Factory to create a mock file system structure for testing.

    Returns a function that creates files/dirs from a dict structure.
    Example:
        fs = mock_file_system
        fs({
            "dir1/file1.py": "content1",
            "dir2/file2.py": "content2",
        })
    """

    def _create(structure: dict) -> dict:
        """Create file structure and return mapping of paths."""
        created = {}
        for path_str, content in structure.items():
            full_path = tmp_path / path_str
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            created[path_str] = full_path
        return created

    return _create


@pytest.fixture
def capture_all_output(capsys, caplog):
    """
    Capture both stdout/stderr and log output.

    Returns a function to get all captured output as a dict.
    """

    def _get_output():
        captured = capsys.readouterr()
        return {
            "stdout": captured.out,
            "stderr": captured.err,
            "logs": [record.message for record in caplog.records],
            "log_records": caplog.records,
        }

    return _get_output


@pytest.fixture
def parametrized_code_samples():
    """
    Comprehensive code samples for parametrized testing.

    Organized by category for easy parametrization with pytest.mark.parametrize.
    """
    return {
        "security_issues": {
            "sql_injection": 'query = "SELECT * FROM users WHERE id = " + user_id',
            "command_injection": 'os.system("ls " + user_input)',
            "path_traversal": 'open("../../../etc/passwd")',
            "hardcoded_secret": 'api_key = "sk-1234567890abcdef"',
            "weak_crypto": "hashlib.md5(password).hexdigest()",
            "unsafe_deserialization": "pickle.loads(user_data)",
        },
        "best_practices": {
            "mutable_default": "def func(x=[]):",
            "bare_except": "try:\n    pass\nexcept:\n    pass",
            "none_comparison": "if x == None:",
            "type_check": "if type(x) == list:",
        },
        "modernization": {
            "old_format": '"Hello %s" % name',
            "dict_loop": "d = {}\nfor k, v in items:\n    d[k] = v",
            "format_method": '"Hello {}".format(name)',
        },
    }


@pytest.fixture
def benchmark_code_factory():
    """
    Factory for creating code samples with known performance characteristics.

    Useful for testing performance checks and optimizations.
    """

    def _create(complexity: str) -> str:
        """Create code with specific complexity."""
        templates = {
            "linear": """
def process(items):
    result = []
    for item in items:
        result.append(item * 2)
    return result
""",
            "quadratic": """
def process(items):
    result = []
    for i in items:
        for j in items:
            result.append(i * j)
    return result
""",
            "nested_loops": """
def process(items):
    for i in items:
        for j in items:
            for k in items:
                pass
""",
        }
        return templates.get(complexity, templates["linear"])

    return _create


@pytest.fixture
def syntax_edge_cases():
    """
    Edge case Python syntax for robust parser testing.

    Tests handling of valid but unusual Python constructs.
    """
    return {
        "empty_file": "",
        "only_comments": "# Just a comment\n# Another comment",
        "only_docstring": '"""Module docstring"""',
        "unicode_identifier": "变量 = 42",  # Unicode identifier
        "async_context": "async with lock:\n    pass",
        "walrus_operator": "if (n := len(items)) > 10:\n    pass",
        "type_hints": "def func(x: int) -> str:\n    return str(x)",
        "decorator_chain": "@deco1\n@deco2\n@deco3\ndef func():\n    pass",
        "match_statement": "match x:\n    case 1:\n        pass",
        "f_string_expr": 'f"{x + y:.2f}"',
    }


@pytest.fixture
def error_cases():
    """
    Invalid inputs that should be handled gracefully.

    Tests error handling and boundary conditions.
    """
    return {
        "syntax_error": "def func(\n    # Unclosed paren",
        "indentation_error": "def func():\npass",
        "invalid_unicode": b"\x80\x81\x82".decode("latin1"),
        "circular_import": "import sys\nsys.modules[__name__] = None",
    }


@pytest.fixture
def assertion_helpers():
    """
    Helper functions for common assertion patterns.

    Promotes DRY principle in test assertions.
    """

    class Helpers:
        @staticmethod
        def assert_issue_present(issues, rule_id, message_substring=None):
            """Assert that a specific issue is present."""
            matching = [i for i in issues if i.rule_id == rule_id]
            assert len(matching) > 0, f"Expected issue {rule_id} not found"
            if message_substring:
                assert any(message_substring.lower() in i.message.lower() for i in matching), (
                    f"No issue contains '{message_substring}'"
                )
            return matching[0]

        @staticmethod
        def assert_no_false_positives(issues, expected_rule_ids):
            """Assert only expected rule IDs are present."""
            actual_ids = {i.rule_id for i in issues}
            unexpected = actual_ids - set(expected_rule_ids)
            assert not unexpected, f"Unexpected rule IDs: {unexpected}"

        @staticmethod
        def assert_line_range(issue, min_line, max_line):
            """Assert issue is within line range."""
            assert min_line <= issue.line <= max_line, (
                f"Issue at line {issue.line} outside range [{min_line}, {max_line}]"
            )

    return Helpers()


@pytest.fixture
def code_normalizer():
    """
    Utility to normalize code strings for comparison.

    Removes indentation and trailing whitespace for easier test assertions.
    """
    import textwrap

    def _normalize(code: str) -> str:
        """Normalize code string."""
        return textwrap.dedent(code).strip()

    return _normalize
