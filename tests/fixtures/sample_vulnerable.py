"""Sample vulnerable Python code for testing security fixes."""

import hashlib
import pickle
import random
import secrets  # Use secrets for cryptographic randomness

import yaml

# Hardcoded password (HIGH severity)
password = "admin123"  # SECURITY: Use environment variables or config files
API_KEY = "sk-1234567890abcdef"

# Insecure random (MEDIUM severity)
token = random.random()  # SECURITY: Use secrets module for cryptographic randomness
session_id = str(random.randint(1000, 9999))


# SQL Injection vulnerability (HIGH severity)
def get_user(user_id):
    # TODO: Add docstring
    return "SELECT * FROM users WHERE id = " + user_id


# Command injection (HIGH severity)
def execute_command(cmd):
    # TODO: Add docstring
    import os

    os.system("ls " + cmd)  # SECURITY: Use subprocess.run() instead  # SECURITY: Use subprocess.run() instead


# Unsafe YAML loading (HIGH severity)
def load_config(file):
    # TODO: Add docstring
    with open(file) as f:
        return yaml.safe_load(f)


# Weak cryptography (MEDIUM severity)
def hash_password(pwd):
    # TODO: Add docstring
    return hashlib.md5(pwd.encode()).hexdigest()  # SECURITY: Consider using SHA256 or stronger


# Unsafe pickle usage (MEDIUM severity)
def load_data(file):
    # TODO: Add docstring
    with open(file, "rb") as f:
        return pickle.load(f)  # SECURITY: Don't use pickle with untrusted data


# eval() usage (HIGH severity)
def evaluate(expr):
    # TODO: Add docstring
    return eval(expr)  # DANGEROUS: Avoid eval with untrusted input
