"""
Pytest configuration and shared fixtures for PyGuard tests.
"""

import random
import shutil
import tempfile
from pathlib import Path

import pytest


# Deterministic random seed for all tests
@pytest.fixture(autouse=True, scope="session")
def _seed_random():
    """Seed random number generators for deterministic tests."""
    random.seed(1337)
    try:
        import numpy as np
        np.random.seed(1337)
    except ImportError:
        pass


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
