"""Sample code with bad practices for testing fixes.

Note: This file intentionally contains bad practices for testing PyGuard's detection
and auto-fix capabilities. The code patterns here are NOT examples to follow.
"""

# ruff: noqa: E721
# pylint: disable=all

# Mutable default argument
import builtins
import contextlib


def append_to_list(item, my_list=None):
    if my_list is None:
        my_list = []
    my_list.append(item)
    return my_list


# Bare except clause
def risky_operation():
    with contextlib.suppress(builtins.BaseException):
        pass


# Wrong None comparison
def check_value(x):
    if x is None:
        return "None found"
    return "Value exists"


# Wrong boolean comparison
def is_active(flag):
    if flag:
        return "Active"
    return "Inactive"


# Type check instead of isinstance
def process_string(value):
    if type(value) == str:
        return value.upper()
    return None


# Missing docstring
def important_function(a, b):
    return a + b


class ImportantClass:
    def method(self):
        pass


# String concatenation in loop
def build_string(items):
    result = ""
    for item in items:
        result = result + str(item) + ","
    return result


# Not using context manager
def read_file(filename):
    f = open(filename)
    data = f.read()
    f.close()
    return data
