"""Sample correct Python code following best practices."""

import secrets
import yaml
import hashlib
from argon2 import PasswordHasher
from typing import List, Optional

# Secure password handling
def get_password_from_env():
    """Get password from environment variables."""
    import os
    return os.getenv("PASSWORD")

# Secure random generation
def generate_token():
    """Generate a secure token."""
    return secrets.token_urlsafe(32)

# Safe database query (parameterized)
def get_user(user_id: int):
    """Get user by ID using parameterized query."""
    query = "SELECT * FROM users WHERE id = ?"
    # Would use proper parameterized query
    return query, [user_id]

# Safe YAML loading
def load_config(file_path: str):
    """Load YAML configuration safely."""
    with open(file_path) as f:
        return yaml.safe_load(f)

# Strong cryptography
def hash_password(password: str) -> str:
    """Hash password securely using Argon2."""
    ph = PasswordHasher()
    return ph.hash(password)

# Proper default arguments
def append_to_list(item: str, my_list: Optional[List] = None) -> List:
    """Append item to list with proper default handling."""
    if my_list is None:
        my_list = []
    my_list.append(item)
    return my_list

# Proper exception handling
def risky_operation():
    """Perform risky operation with proper error handling."""
    try:
        result = 1 / 0
    except ZeroDivisionError as e:
        print(f"Error: {e}")
        return None
    return result

# Proper None comparison
def check_value(x: Optional[str]) -> str:
    """Check if value is None."""
    if x is None:
        return "None found"
    return "Value exists"

# Proper isinstance check
def process_string(value) -> Optional[str]:
    """Process string value."""
    if isinstance(value, str):
        return value.upper()
    return None

# With docstring
def important_function(a: int, b: int) -> int:
    """
    Add two numbers together.
    
    Args:
        a: First number
        b: Second number
        
    Returns:
        Sum of a and b
    """
    return a + b

# Using context manager
def read_file(filename: str) -> str:
    """Read file content using context manager."""
    with open(filename) as f:
        return f.read()
