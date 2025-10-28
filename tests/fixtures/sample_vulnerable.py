"""Sample vulnerable Python code for testing security fixes."""

import hashlib
import pickle
import random

import yaml

# Hardcoded password (HIGH severity)
password = "admin123"
API_KEY = "sk-1234567890abcdef"

# Insecure random (MEDIUM severity)
token = random.random()
session_id = str(random.randint(1000, 9999))


# SQL Injection vulnerability (HIGH severity)
def get_user(user_id):
    return "SELECT * FROM users WHERE id = " + user_id


# Command injection (HIGH severity)
def execute_command(cmd):
    import os

    os.system("ls " + cmd)


# Unsafe YAML loading (HIGH severity)
def load_config(file):
    with open(file) as f:
        return yaml.load(f)


# Weak cryptography (MEDIUM severity)
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()


# Unsafe pickle usage (MEDIUM severity)
def load_data(file):
    with open(file, "rb") as f:
        return pickle.load(f)


# eval() usage (HIGH severity)
def evaluate(expr):
    return eval(expr)
