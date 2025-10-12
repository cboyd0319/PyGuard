# Best Practices Reference

Complete reference for Python best practices enforcement in PyGuard.

## Overview

PyGuard enforces 10+ Python best practices and code quality improvements.

---

## 1. Mutable Default Arguments

**Severity**: HIGH

### Problem

Mutable default arguments are shared across all function calls, causing unexpected behavior.

### Detected Pattern

```python
# ❌ Bad
def append_to_list(item, items=[]):
    items.append(item)
    return items

# This causes issues:
list1 = append_to_list(1)  # [1]
list2 = append_to_list(2)  # [1, 2] - Wrong! Should be [2]
```

### Fix Applied

```python
# ✅ Fixed
def append_to_list(item, items=None):  # ANTI-PATTERN: Use None and create in function body
    if items is None:
        items = []
    items.append(item)
    return items
```

### Recommendation

```python
# ✅ Best practice
def append_to_list(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items

# ✅ Also acceptable
def append_to_list(item, items=None):
    items = items or []
    items.append(item)
    return items
```

---

## 2. Bare Except Clauses

**Severity**: MEDIUM

### Problem

Bare `except:` catches all exceptions including KeyboardInterrupt and SystemExit.

### Detected Pattern

```python
# ❌ Bad
try:
    risky_operation()
except:  # Catches EVERYTHING
    pass
```

### Fix Applied

```python
# ✅ Fixed
try:
    risky_operation()
except Exception:  # Specific exception type
    pass
```

### Recommendation

```python
# ✅ Best practice - Specific exceptions
try:
    value = int(user_input)
except ValueError:
    print("Invalid number")

# ✅ Good - Multiple specific exceptions
try:
    file_operation()
except (FileNotFoundError, PermissionError) as e:
    logger.error(f"File error: {e}")

# ⚠️ Acceptable - Exception for general errors
try:
    complex_operation()
except Exception as e:
    logger.exception("Unexpected error")
    raise
```

---

## 3. None Comparison

**Severity**: LOW

### Problem

Using `==` or `!=` for None comparison is not idiomatic Python.

### Detected Pattern

```python
# ❌ Bad
if x == None:
    pass
if y != None:
    return y
```

### Fix Applied

```python
# ✅ Fixed
if x is None:
    pass
if y is not None:
    return y
```

### Recommendation

```python
# ✅ Always use "is" and "is not" for None
if value is None:
    return default

if result is not None:
    process(result)
```

---

## 4. Boolean Comparison

**Severity**: LOW

### Problem

Comparing to True/False is redundant and not Pythonic.

### Detected Pattern

```python
# ❌ Bad
if flag == True:
    pass
if active != False:
    pass
while condition == True:
    pass
```

### Fix Applied

```python
# ✅ Fixed
if flag:
    pass
if active:
    pass
while condition:
    pass
```

### Recommendation

```python
# ✅ Best practice
if is_valid:
    process()

if not is_empty:
    return data

# ✅ Explicit comparison for None/0/empty
if count is not None:  # Good - distinguishes None from 0
    process(count)

if len(items) > 0:  # Acceptable - explicit count check
    process_items()
```

---

## 5. Type Checking

**Severity**: LOW

### Problem

Using `type()` for type checking doesn't respect inheritance.

### Detected Pattern

```python
# ❌ Bad
if type(x) == int:
    pass
if type(obj) == MyClass:
    pass
```

### Fix Applied

```python
# ⚠️ Suggestion added
if type(x) == int:  # SUGGESTION: Use isinstance() for type checks
    pass
```

### Recommendation

```python
# ✅ Best practice - isinstance()
if isinstance(x, int):
    process_number(x)

# ✅ Multiple types
if isinstance(value, (int, float)):
    numeric_operation(value)

# ✅ When type() is actually needed (rare)
if type(x) is int:  # Use "is" not "=="
    # Only for exact type match, no subclasses
    pass
```

---

## 6. List Comprehensions

**Severity**: LOW

### Problem

Traditional for loops can often be replaced with more concise list comprehensions.

### Detected Pattern

```python
# ❌ Verbose
result = []
for item in items:
    result.append(item * 2)

# ❌ Verbose
squares = []
for i in range(10):
    squares.append(i ** 2)
```

### Fix Applied

```python
# ✅ Suggestion added
result = []
for item in items:
    result.append(item * 2)  # SUGGESTION: Consider list comprehension
```

### Recommendation

```python
# ✅ Best practice - List comprehension
result = [item * 2 for item in items]
squares = [i ** 2 for i in range(10)]

# ✅ With condition
evens = [x for x in range(20) if x % 2 == 0]

# ✅ Generator for large data
sum_squares = sum(x ** 2 for x in range(1000000))

# ⚠️ But don't sacrifice readability
# Bad - too complex
result = [
    process(transform(validate(item)))
    for sublist in nested_list
    for item in sublist
    if filter1(item) and filter2(item)
]

# Better - Use traditional loop for clarity
result = []
for sublist in nested_list:
    for item in sublist:
        if filter1(item) and filter2(item):
            result.append(process(transform(validate(item))))
```

---

## 7. String Concatenation in Loops

**Severity**: MEDIUM

### Problem

String concatenation in loops creates a new string object each iteration (O(n²)).

### Detected Pattern

```python
# ❌ Bad - O(n²) performance
result = ""
for item in items:
    result += str(item)
```

### Fix Applied

```python
# ⚠️ Warning added
result = ""
for item in items:
    result += str(item)  # ANTI-PATTERN: Use str.join() or list + ''.join()
```

### Recommendation

```python
# ✅ Best practice - join()
result = ''.join(str(item) for item in items)
result = ', '.join(items)

# ✅ Build list first, then join
parts = []
for item in items:
    parts.append(process(item))
result = ''.join(parts)

# ✅ For simple cases - f-string or format
name = f"{first} {last}"
url = f"https://api.com/{endpoint}"
```

---

## 8. Context Managers

**Severity**: MEDIUM

### Problem

Not using context managers for file operations can lead to resource leaks.

### Detected Pattern

```python
# ❌ Bad - File not guaranteed to close
file = open("data.txt")
content = file.read()
file.close()  # May not execute if read() raises

# ❌ Bad
f = open("output.txt", "w")
f.write(data)
```

### Fix Applied

```python
# ⚠️ Suggestion added
file = open("data.txt")  # SUGGESTION: Use context manager (with statement)
```

### Recommendation

```python
# ✅ Best practice - with statement
with open("data.txt") as file:
    content = file.read()

# ✅ Multiple files
with open("input.txt") as fin, open("output.txt", "w") as fout:
    fout.write(fin.read())

# ✅ Custom context managers
from contextlib import contextmanager

@contextmanager
def database_connection():
    conn = connect_db()
    try:
        yield conn
    finally:
        conn.close()

with database_connection() as conn:
    conn.execute(query)
```

---

## 9. Missing Docstrings

**Severity**: LOW

### Problem

Functions and classes without docstrings are harder to understand and maintain.

### Detected Pattern

```python
# ❌ No docstring
def calculate_total(items):
    return sum(item.price for item in items)

class UserManager:
    def __init__(self):
        pass
```

### Fix Applied

```python
# ✅ TODO added
def calculate_total(items):
    # TODO: Add docstring
    return sum(item.price for item in items)
```

### Recommendation

```python
# ✅ Best practice - Google-style docstrings
def calculate_total(items: list[Item]) -> float:
    """Calculate total price of items.
    
    Args:
        items: List of Item objects with price attribute.
    
    Returns:
        Total price as float.
    
    Example:
        >>> items = [Item(10.00), Item(20.00)]
        >>> calculate_total(items)
        30.0
    """
    return sum(item.price for item in items)

class UserManager:
    """Manages user accounts and authentication.
    
    Attributes:
        users: Dictionary of username to User objects.
        active_sessions: Set of active session IDs.
    """
    
    def __init__(self):
        """Initialize empty user manager."""
        self.users = {}
        self.active_sessions = set()
```

---

## 10. Global Variables

**Severity**: MEDIUM

### Problem

Global variables make code harder to test, debug, and maintain.

### Detected Pattern

```python
# ❌ Bad
counter = 0

def increment():
    global counter
    counter += 1
```

### Fix Applied

```python
# ⚠️ Warning added
def increment():
    global counter  # WARNING: Avoid global variables
    counter += 1
```

### Recommendation

```python
# ✅ Best practice - Use class attributes
class Counter:
    """Counter with encapsulated state."""
    
    def __init__(self):
        self.value = 0
    
    def increment(self):
        self.value += 1

counter = Counter()
counter.increment()

# ✅ Pass as argument
def increment(counter: int) -> int:
    """Increment counter value."""
    return counter + 1

count = 0
count = increment(count)

# ✅ Use function attributes for simple cases
def increment():
    """Increment internal counter."""
    increment.counter += 1
    return increment.counter

increment.counter = 0
```

---

## 11. Naming Conventions (PEP 8)

**Severity**: LOW

### Problem

Inconsistent naming makes code harder to read.

### PEP 8 Rules

| Type | Convention | Example |
|------|------------|---------|
| Class | PascalCase | `UserManager`, `HttpResponse` |
| Function | snake_case | `calculate_total()`, `get_user()` |
| Method | snake_case | `process_data()`, `save()` |
| Variable | snake_case | `total_count`, `user_name` |
| Constant | UPPER_SNAKE | `MAX_SIZE`, `API_KEY` |
| Private | _prefix | `_internal_func()`, `_cache` |
| Module | snake_case | `user_manager.py`, `http_client.py` |

### Detected Patterns

```python
# ❌ Bad naming
class userManager:  # Should be PascalCase
    pass

def CalculateTotal():  # Should be snake_case
    pass

MAX_size = 100  # Should be all caps
```

### Recommendation

```python
# ✅ Best practice
class UserManager:  # PascalCase for classes
    MAX_USERS = 100  # UPPER_SNAKE for constants
    
    def __init__(self):
        self.active_users = []  # snake_case for attributes
        self._cache = {}  # _prefix for private
    
    def calculate_total(self):  # snake_case for methods
        return len(self.active_users)

# ✅ Functions and variables
def get_user_by_id(user_id: int) -> User:
    """Get user by ID."""
    cached_user = _check_cache(user_id)
    return cached_user or _fetch_from_db(user_id)
```

---

## Configuration

Enable/disable specific checks in `pyguard.toml`:

```toml
[best_practices.checks]
mutable_default_arguments = true
bare_except = true
none_comparison = true
boolean_comparison = true
type_check = true
list_comprehension = true
string_concatenation = true
context_managers = true
missing_docstrings = true
global_variables = true
naming_conventions = true
```

---

## Examples

### Before PyGuard

```python
def process_items(items=[]):
    result = ""
    for item in items:
        if item == None:
            continue
        if type(item) == str:
            result += item
    return result

def read_config(filename):
    file = open(filename)
    return file.read()
```

### After PyGuard

```python
def process_items(items=None):  # ANTI-PATTERN: Use None and create in function body
    """Process list of items."""  # TODO: Add detailed docstring
    if items is None:
        items = []
    
    parts = []  # SUGGESTION: Use str.join() instead of concatenation
    for item in items:
        if item is None:  # Fixed: Use "is None"
            continue
        if isinstance(item, str):  # SUGGESTION: Use isinstance()
            parts.append(item)
    
    return ''.join(parts)

def read_config(filename):
    """Read configuration file."""
    with open(filename) as file:  # SUGGESTION: Use context manager
        return file.read()
```
