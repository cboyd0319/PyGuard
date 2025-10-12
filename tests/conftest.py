"""
Pytest configuration and shared fixtures for PyGuard tests.
"""

import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Python code for testing."""
    return '''
import random
import yaml
password = "admin123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

token = random.random()
data = yaml.load(file)
'''


@pytest.fixture
def sample_bad_practices_code():
    """Sample code with bad practices."""
    return '''
def foo(x=[]):
    x.append(1)
    return x

try:
    pass
except:
    pass

if x == None:
    pass
'''


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
    
    return MockLogger(), logs
