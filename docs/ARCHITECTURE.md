# PyGuard Architecture

## What this is

PyGuard scans Python code for security vulnerabilities, quality issues, and style problems. Applies fixes automatically. This doc explains how it works.

## Design principles

- Modularity: security, best practices, formatting are independent
- Extensibility: add new rules without touching core
- Non-destructive: creates backups before changes
- Transparent: diffs and logs for all changes
- Performance: AST-based analysis (10-100x faster than regex)

## Flow

```
CLI (pyguard/cli.py)
  ├─→ SecurityFixer (pyguard/lib/security.py)
  ├─→ BestPracticesFixer (pyguard/lib/best_practices.py)
  └─→ FormattingFixer (pyguard/lib/formatting.py)
       ↓
  Core Utilities (pyguard/lib/core.py)
    - PyGuardLogger (structured JSON logs)
    - BackupManager (timestamped backups)
    - DiffGenerator (unified diffs)
    - FileOperations (safe I/O)
```

**Data in**: Python source files
**Data out**: Fixed files, backups, diffs, HTML/JSON reports
**Trust boundary**: Reads local files only, no network access

## Components

**CLI** (`pyguard/cli.py`)
- Argument parsing, orchestration, output formatting

**Security** (`pyguard/lib/security.py`)
- Detects 55+ vulnerabilities (see README for list)
- Auto-fixes 20+ issues
- Methods: AST-based analysis, pattern matching

**Best Practices** (`pyguard/lib/best_practices.py`)
- Enforces PEP 8, SWEBOK guidelines
- Fixes: mutable defaults, bare except, type checks, etc.

**Formatting** (`pyguard/lib/formatting.py`)
- Integrates: Black, isort, autopep8

**Core** (`pyguard/lib/core.py`)
- Logging: structured JSONL (INFO/WARNING/ERROR)
- Backups: timestamped with auto-cleanup
- Diffs: colorized, git-style
- File ops: safe I/O, directory traversal

## Execution flow

**Single file**:
1. `pyguard myfile.py`
2. Validate args
3. Create backup → `.pyguard_backups/myfile.py.TIMESTAMP`
4. Security scan → apply fixes → log
5. Best practices scan → apply fixes → log
6. Format (Black, isort) → log
7. Generate diff
8. Display summary + diff
9. Write `logs/pyguard.jsonl`

**Directory** (parallel processing):
1. `pyguard src/`
2. Discover all `.py` files
3. For each file: security → best practices → format
4. Aggregate results
5. Display summary

## Configuration

Precedence (highest to lowest):
1. CLI args
2. `./pyguard.toml` (project)
3. `~/.config/pyguard/config.toml` (user)
4. Built-in defaults

Example `pyguard.toml`:
```toml
[security]
enabled = true
severity_levels = ["HIGH", "MEDIUM"]

[formatting]
line_length = 100
```

## Error handling

- Graceful degradation: module failure doesn't stop others
- Detailed logging: all errors with context
- Clear user feedback
- Backups preserved on error

## Testing

- Unit tests: individual functions, mocked deps, fast
- Integration tests: module interactions, file I/O, CLI
- Fixtures: sample vulnerable/bad/correct code

Current: 257 tests passing, 69% coverage

## Performance

**Current** (v0.3.0):
- AST-based analysis (10-100x faster than regex)
- Parallel processing (6x speedup on 8 cores)
- Smart caching (instant on unchanged files)
- ~10-50ms per file

**Limits**:
- Tested: 10,000 lines per file, 100,000 total lines
- Memory: ~50MB baseline + ~1KB per file

## Extending PyGuard

**Add security rule**:
1. Add pattern to `SecurityFixer`
2. Implement fix method
3. Add tests
4. Document

```python
def _fix_new_vuln(self, content: str) -> str:
    if 'bad_pattern' in content:
        content = content.replace('bad_pattern', 'safe_pattern')
        self.fixes_applied.append("Fixed new vulnerability")
    return content
```

## Security notes

- PyGuard does NOT execute analyzed code
- Only reads/writes specified files (no network access)
- Backups in separate directory (`.pyguard_backups/`)
- Logs exclude secret values

## Future

**Plugin system** (v1.0+): Community-developed rules via plugin API

**See also**: [User Guide](user-guide.md), [Contributing](../CONTRIBUTING.md)
