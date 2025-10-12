# PyGuard Architecture

This document describes the architecture and design decisions of PyGuard.

## Overview

PyGuard is a comprehensive Python QA and auto-fix tool that combines security analysis, best practices enforcement, and code formatting into a single, unified tool.

## Design Principles

1. **Modularity**: Each component (security, best practices, formatting) is independent
2. **Extensibility**: Easy to add new rules and fixers
3. **Non-destructive**: Always creates backups before modifications
4. **Transparent**: Provides detailed diffs and logs of all changes
5. **Performance**: Efficient regex-based pattern matching (AST-based coming in v0.2.0)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         PyGuard CLI                         │
│                      (pyguard/cli.py)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
    ┌──────────────┐ ┌──────────┐ ┌──────────────┐
    │   Security   │ │   Best   │ │  Formatting  │
    │    Fixer     │ │ Practices│ │    Fixer     │
    │              │ │  Fixer   │ │              │
    └──────┬───────┘ └────┬─────┘ └──────┬───────┘
           │              │               │
           └──────────────┼───────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Core Utilities     │
              │  ┌─────────────────┐  │
              │  │  PyGuardLogger  │  │
              │  │ BackupManager   │  │
              │  │  DiffGenerator  │  │
              │  │ FileOperations  │  │
              │  └─────────────────┘  │
              └───────────────────────┘
```

## Component Overview

### CLI Layer (`pyguard/cli.py`)

- Entry point for command-line usage
- Argument parsing and validation
- Orchestrates calls to fixer modules
- Handles output formatting and logging

### Security Module (`pyguard/lib/security.py`)

**Purpose**: Detect and fix security vulnerabilities

**Key Classes**:
- `SecurityFixer`: Main class for security analysis

**Detection Methods**:
- Regex-based pattern matching
- AST-based analysis (planned for v0.2.0)

**Vulnerability Categories**:
1. Hardcoded secrets (HIGH)
2. SQL injection (HIGH)
3. Command injection (HIGH)
4. Insecure random (MEDIUM)
5. Unsafe YAML loading (HIGH)
6. Pickle usage (MEDIUM)
7. eval()/exec() usage (HIGH)
8. Weak cryptography (MEDIUM)
9. Path traversal (HIGH)

### Best Practices Module (`pyguard/lib/best_practices.py`)

**Purpose**: Enforce Python coding best practices

**Key Classes**:
- `BestPracticesFixer`: Main class for best practices

**Fix Categories**:
1. Mutable default arguments
2. Bare except clauses
3. None comparison
4. Boolean comparison
5. Type checks (type() vs isinstance())
6. List comprehensions
7. String concatenation
8. Context managers
9. Missing docstrings
10. Global variables

### Formatting Module (`pyguard/lib/formatting.py`)

**Purpose**: Apply consistent code formatting

**Integrations**:
- Black: Code formatting
- isort: Import sorting
- autopep8: PEP 8 compliance

### Core Module (`pyguard/lib/core.py`)

**Key Classes**:

1. **PyGuardLogger**: Structured logging to JSONL
   - Supports INFO, WARNING, ERROR levels
   - Includes context (file, line, etc.)
   - Machine-readable output

2. **BackupManager**: File backup and restoration
   - Creates timestamped backups
   - Supports restoration
   - Automatic cleanup

3. **DiffGenerator**: Generate unified diffs
   - Colorized output
   - Configurable context lines
   - Git-style format

4. **FileOperations**: File I/O utilities
   - Safe file reading/writing
   - Directory traversal
   - Python file detection

## Data Flow

### Single File Analysis

```
1. User runs: pyguard myfile.py
2. CLI validates arguments
3. CLI creates backup of myfile.py
4. SecurityFixer analyzes myfile.py
   - Scans for vulnerabilities
   - Applies auto-fixes
   - Logs results
5. BestPracticesFixer analyzes myfile.py
   - Scans for violations
   - Applies auto-fixes
   - Logs results
6. FormattingFixer formats myfile.py
   - Runs Black
   - Runs isort
   - Logs results
7. DiffGenerator creates diff
8. CLI displays summary and diff
9. Logs written to pyguard.jsonl
```

### Directory Analysis

```
1. User runs: pyguard src/
2. CLI discovers all .py files
3. For each file:
   - Run security analysis
   - Run best practices analysis
   - Run formatting
4. Aggregate results
5. Display summary statistics
```

## Configuration

### Configuration Hierarchy

1. **Command-line arguments** (highest priority)
2. **Project configuration** (`pyguard.toml` in current directory)
3. **User configuration** (`~/.config/pyguard/pyguard.toml`)
4. **Default configuration** (built-in)

### Configuration Files

**`pyguard.toml`**: Main configuration
```toml
[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM"]

[best_practices]
enabled = true
max_complexity = 10

[formatting]
line_length = 100
```

**`config/security_rules.toml`**: Security rules
```toml
[rules]
check_hardcoded_passwords = true
check_sql_injection = true
```

## Error Handling

1. **Graceful degradation**: If one module fails, others continue
2. **Detailed logging**: All errors logged with context
3. **User feedback**: Clear error messages
4. **Backup preservation**: Backups never deleted on error

## Testing Strategy

### Unit Tests (`tests/unit/`)
- Test individual functions and methods
- Mock external dependencies
- Fast execution

### Integration Tests (`tests/integration/`)
- Test module interactions
- Test file I/O operations
- Test CLI commands

### Fixtures (`tests/fixtures/`)
- Sample vulnerable code
- Sample bad practices code
- Sample correct code

## Performance Considerations

### Current Implementation (v0.1.0)
- **Pattern matching**: Regex-based (fast but limited)
- **File processing**: Sequential (single-threaded)
- **Performance**: ~100ms per file (small files)

### Planned Improvements (v0.2.0)
- **Pattern matching**: AST-based (more accurate)
- **File processing**: Parallel (multi-threaded)
- **Caching**: Skip unchanged files
- **Incremental**: Watch mode for continuous monitoring

## Extension Points

### Adding New Security Rules

1. Add pattern to `SecurityFixer`
2. Implement fix method
3. Add tests
4. Document in `docs/security-rules.md`

Example:
```python
def _fix_new_vulnerability(self, content: str) -> str:
    """Fix description."""
    if 'vulnerable_pattern' in content:
        content = content.replace('vulnerable_pattern', 'safe_pattern')
        self.fixes_applied.append("Fixed new vulnerability")
    return content
```

### Adding New Best Practices

Similar process to security rules, but in `BestPracticesFixer`.

## Security Considerations

1. **Code Execution**: PyGuard does NOT execute analyzed code
2. **File Access**: PyGuard only reads/writes specified files
3. **Backup Safety**: Backups stored in separate directory
4. **Log Safety**: Logs do not contain secret values

## Future Architecture (v0.2.0+)

### AST-Based Analysis

```
Source Code → AST → Visitors → Issues → Fixes → Modified AST → Code
```

Benefits:
- More accurate detection
- Context-aware fixes
- Better performance
- Support for complex patterns

### Plugin System

```
PyGuard Core → Plugin API → Community Plugins
```

Allows third-party rule development.

## Related Documents

- [API Reference](api-reference.md)
- [Security Rules](security-rules.md)
- [Best Practices](best-practices.md)
- [Configuration Guide](configuration.md)
- [Contributing Guide](../CONTRIBUTING.md)
