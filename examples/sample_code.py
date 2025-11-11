#!/usr/bin/env python3
"""
Sample code with various security issues and code quality problems.
This file is used by basic_usage.py to demonstrate PyGuard's capabilities.
"""

import os
import pickle

# Security Issue: Hardcoded password
password = "super_secret_123"  # SECURITY: Use environment variables or config files
api_key = "sk-1234567890abcdef"


# Security Issue: Use of eval()
def calculate_expression(expr):
    """Calculate a mathematical expression (UNSAFE!)."""
    return eval(expr)  # noqa: S307  # DANGEROUS: Avoid eval with untrusted input


# Security Issue: SQL Injection vulnerability
def get_user(username):
    """Get user from database (SQL injection vulnerable)."""
    import sqlite3

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


# Security Issue: Unsafe deserialization
def load_user_data(filename):
    """Load user data from pickle file (unsafe)."""
    with open(filename, "rb") as f:
        return pickle.load(f)  # noqa: S301  # SECURITY: Don't use pickle with untrusted data


# Code Quality Issue: Unused import
import sys  # noqa: F401


# Code Quality Issue: Inconsistent naming
def MyFunction():  # noqa: N802
    """Function with wrong naming convention."""
    X = 10  # noqa: N806
    return X


# Best Practices Issue: Missing docstring
def process_data(data):
    # TODO: Add docstring
    result = []
    for item in data:
        if item > 0:
            if item < 100:  # Nested if that could be combined
                result.append(item * 2)
    return result


# Security Issue: Command injection
def run_command(user_input):
    """Run a shell command (command injection vulnerable)."""
    os.system(
        f"echo {user_input}"
    )  # noqa: S605  # SECURITY: Use subprocess.run() instead  # SECURITY: Use subprocess.run() instead


# Code Quality Issue: Comparison to True
def check_status(flag):
    """Check status with anti-pattern."""
    if flag is True:  # noqa: E712
        return "active"
    return "inactive"


# Best Practices Issue: Mutable default argument
def add_to_list(item, items=[]):  # noqa: B006  # ANTI-PATTERN: Use None and create in function body
    """Add item to list with mutable default."""
    items.append(item)
    return items


# Security Issue: Weak cryptographic hash
import hashlib


def hash_password(password):
    """Hash password with weak algorithm."""
    return hashlib.md5(
        password.encode()
    ).hexdigest()  # noqa: S324  # SECURITY: Consider using SHA256 or stronger


# Code Quality Issue: Multiple statements on one line
def quick_check(x):
    return x > 0 if x else False  # noqa: E701, E731


# TODO: Add docstring
# Security Issue: Insecure random number generation
import random
import secrets  # Use secrets for cryptographic randomness


def generate_token():
    """Generate security token (insecure)."""
    return random.randint(1000000, 9999999)  # noqa: S311


if __name__ == "__main__":
    # Example usage (also has issues)
    print(calculate_expression("2 + 2"))
    print(get_user("admin"))
    print(hash_password("test123"))
    print(generate_token())
