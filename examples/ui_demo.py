#!/usr/bin/env python3
"""Demo file to showcase PyGuard's beautiful UI."""

import os
import yaml

# Security issues for demonstration
password = "hardcoded_password_123"
api_key = "sk-1234567890abcdefghijklmnop"

def unsafe_function():
    """Function with security issues."""
    user_input = input("Enter command: ")
    os.system(user_input)  # Command injection
    
    code = input("Enter code: ")
    result = eval(code)  # Code injection
    
    with open("config.yaml") as f:
        config = yaml.load(f)  # Unsafe YAML
    
    return result

# Code quality issues
def bad_practices(items=[]):  # Mutable default
    if x == None:  # Wrong comparison
        pass
    return items
