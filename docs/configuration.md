# PyGuard Configuration Guide

Complete guide to configuring PyGuard for your project.

## Configuration File

PyGuard uses TOML format for configuration. Create `pyguard.toml` in your project root.

### Basic Configuration

```toml
[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"
max_backups = 10

[formatting]
line_length = 100
use_black = true
use_isort = true

[security]
enabled = true

[best_practices]
enabled = true
```

---

## General Settings

```toml
[general]
# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "INFO"

# Directory for backups
backup_dir = ".pyguard_backups"

# Maximum backups per file
max_backups = 10

# Log file path
log_file = "logs/pyguard.jsonl"

# Enable colored output
use_color = true

# Number of parallel workers (0 = auto)
workers = 0
```

---

## Formatting Settings

```toml
[formatting]
# Maximum line length
line_length = 100

# Use Black formatter
use_black = true

# Use isort for imports
use_isort = true

# Use autopep8
use_autopep8 = false

# Black configuration
[formatting.black]
target_version = ["py38", "py39", "py310", "py311"]
skip_string_normalization = false

# isort configuration
[formatting.isort]
profile = "black"
line_length = 100
```

---

## Security Settings

```toml
[security]
# Enable security analysis
enabled = true

# Severity levels to check
severity_levels = ["HIGH", "MEDIUM", "LOW"]

# Exclude patterns
[security.exclude]
patterns = [
    "*/tests/*",
    "*/test_*.py",
    "*_test.py",
    "*/migrations/*"
]

# Custom security rules
[security.rules]
check_hardcoded_passwords = true
check_sql_injection = true
check_command_injection = true
check_insecure_random = true
check_yaml_load = true
check_pickle = true
check_eval_exec = true
check_weak_crypto = true
check_path_traversal = true
```

---

## Best Practices Settings

```toml
[best_practices]
# Enable best practices analysis
enabled = true

# Naming convention checks
naming_conventions = true

# Docstring checks
docstring_checks = true

# Exclude patterns
[best_practices.exclude]
patterns = [
    "*/vendor/*",
    "*/node_modules/*"
]

# Specific checks
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
```

---

## Environment-Specific Configuration

### Development

`pyguard.dev.toml`:

```toml
[general]
log_level = "DEBUG"
use_color = true

[security]
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[best_practices]
missing_docstrings = false  # Don't enforce in dev
```

### CI/CD

`pyguard.ci.toml`:

```toml
[general]
log_level = "WARNING"
use_color = false  # No ANSI colors in CI

[formatting]
use_black = false  # Already formatted

[security]
severity_levels = ["HIGH"]  # Only critical issues
```

Use with: `pyguard --config pyguard.ci.toml`

---

## Per-File Configuration

Use inline comments to disable specific checks:

```python
# pyguard: disable=security
password = "test123"  # OK in test files

# pyguard: disable=best-practices
def func(items=[]):  # OK for this function
    pass

# pyguard: disable-next-line=security
eval(user_input)  # Disabled for next line only
```

---

## Configuration Precedence

1. **Command-line arguments** (highest priority)
2. **Project config**: `./pyguard.toml`
3. **User config**: `~/.config/pyguard/config.toml`
4. **System config**: `/etc/pyguard/config.toml`
5. **Defaults** (lowest priority)

---

## Complete Example

```toml
# pyguard.toml - Complete configuration example

[general]
log_level = "INFO"
backup_dir = ".pyguard_backups"
max_backups = 10
log_file = "logs/pyguard.jsonl"
use_color = true
workers = 4

[formatting]
line_length = 100
use_black = true
use_isort = true
use_autopep8 = false

[formatting.black]
target_version = ["py38", "py39", "py310", "py311", "py312"]
skip_string_normalization = false

[formatting.isort]
profile = "black"
line_length = 100

[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM", "LOW"]

[security.exclude]
patterns = [
    "*/tests/*",
    "*/test_*.py",
    "*_test.py",
    "*/migrations/*",
    "*/vendor/*"
]

[security.rules]
check_hardcoded_passwords = true
check_sql_injection = true
check_command_injection = true
check_insecure_random = true
check_yaml_load = true
check_pickle = true
check_eval_exec = true
check_weak_crypto = true
check_path_traversal = true

[best_practices]
enabled = true
naming_conventions = true
docstring_checks = true

[best_practices.exclude]
patterns = [
    "*/migrations/*",
    "*/vendor/*"
]

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
```
