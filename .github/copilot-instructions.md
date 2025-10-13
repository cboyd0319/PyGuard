# GitHub Copilot Instructions — PyGuard

> **Purpose:** PyGuard is a comprehensive Python security & code quality analysis tool with ML-powered detection, auto-fix capabilities, and support for 10+ compliance frameworks (OWASP, CWE, PCI-DSS, HIPAA, etc.). It detects 55+ security vulnerabilities and code quality issues while maintaining 100% local operation with no telemetry.

## Project Overview

- **Core functionality:** Static analysis → Detection → Auto-fix → Report
- **Security focus:** 55+ vulnerability types (CWE, OWASP Top 10, OWASP ASVS)
- **Quality analysis:** 10+ code quality checks (naming, docstrings, complexity, best practices)
- **Compliance:** Multi-framework support (OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX)
- **ML-powered:** Risk scoring, anomaly detection, vulnerability prediction
- **Auto-fix:** Automatic remediation with backup/rollback support
- **Reports:** HTML, JSON, console output with severity-based filtering

## Core Principles

### Privacy & Security First
- **No telemetry.** All analysis happens locally. Never ship code that phones home.
- **Secrets handling:** Never hardcode tokens, keys, or credentials. Use environment variables.
- **No PII in logs:** Structured logging in JSON format without sensitive data.
- **Backup before fix:** Always create backups before applying auto-fixes.

### Code Quality Standards
- **Language:** Python 3.8+ (recommend 3.13 for development)
- **Style:** PEP 8/PEP 257 with Black formatter (line length: 100)
- **Type hints:** Required for new code, mypy-friendly
- **Testing:** pytest with 70%+ coverage target
- **Logging:** Structured JSON logs (PyGuardLogger in `pyguard/lib/core.py`)

## Repository Structure

```
PyGuard/
├── pyguard/                       # Main package
│   ├── __init__.py               # Package exports
│   ├── cli.py                    # Command-line interface
│   └── lib/                      # Core library modules
│       ├── core.py               # Logger, backup, diff, file ops
│       ├── security.py           # Security vulnerability detection/fixes
│       ├── advanced_security.py  # Advanced security (taint, race conditions, ReDoS)
│       ├── ultra_advanced_security.py  # Ultra-advanced security features
│       ├── best_practices.py     # Code quality improvements
│       ├── formatting.py         # Code formatting (Black, isort)
│       ├── ast_analyzer.py       # AST-based static analysis
│       ├── ml_detection.py       # ML-powered security detection
│       ├── enhanced_detections.py # Advanced vulnerability detection
│       ├── ultra_advanced_fixes.py # Ultra-advanced automated fixes
│       ├── mcp_integration.py    # Model Context Protocol integration
│       ├── knowledge_integration.py # Knowledge base integration
│       ├── standards_integration.py # Compliance standards (OWASP, PCI-DSS, etc.)
│       ├── supply_chain.py       # Supply chain security analysis
│       ├── cache.py              # Caching for performance
│       ├── parallel.py           # Parallel processing utilities
│       ├── reporting.py          # Report generation (JSON, HTML, console)
│       └── ui.py                 # UI components and enhanced HTML reporting
├── tests/                        # Test suite
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── fixtures/                # Test fixtures and sample code
├── config/                       # Configuration files
│   ├── security_rules.toml      # Security detection rules
│   └── qa_settings.toml         # Quality assurance settings
├── docs/                         # Documentation
├── examples/                     # Example code and demos
├── scripts/                      # Utility scripts
└── benchmarks/                   # Performance benchmarks
```

## Key Modules Overview

### Core Modules
- **`cli.py`** — Command-line interface with argument parsing and main entry point
- **`lib/core.py`** — Core utilities: PyGuardLogger, BackupManager, DiffGenerator, FileOperations
- **`lib/cache.py`** — Analysis caching for improved performance (AnalysisCache, ConfigCache)
- **`lib/parallel.py`** — Parallel processing for batch operations (ParallelProcessor, BatchProcessor)

### Security Analysis
- **`lib/security.py`** — Core security vulnerability detection and fixes (SecurityFixer)
- **`lib/advanced_security.py`** — Advanced analysis: taint tracking, race conditions, ReDoS, integer overflow
- **`lib/ultra_advanced_security.py`** — Ultra-advanced security features and complex vulnerability patterns
- **`lib/ast_analyzer.py`** — AST-based static analysis (ASTAnalyzer, SecurityVisitor, CodeQualityVisitor)
- **`lib/enhanced_detections.py`** — Enhanced detection patterns for complex vulnerabilities
- **`lib/ml_detection.py`** — Machine learning-powered security detection and risk scoring

### Code Quality & Fixes
- **`lib/best_practices.py`** — Code quality improvements (BestPracticesFixer, NamingConventionFixer)
- **`lib/formatting.py`** — Code formatting with Black and isort (FormattingFixer, WhitespaceFixer)
- **`lib/ultra_advanced_fixes.py`** — Advanced automated code fixes and refactoring

### Integration & Compliance
- **`lib/mcp_integration.py`** — Model Context Protocol integration for AI-powered assistance
- **`lib/knowledge_integration.py`** — Knowledge base integration for security and compliance information
- **`lib/standards_integration.py`** — Multi-framework compliance (OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX)
- **`lib/supply_chain.py`** — Supply chain security analysis and dependency scanning

### Reporting & UI
- **`lib/reporting.py`** — Report generation: JSONReporter, HTMLReporter, ConsoleReporter, AnalysisMetrics
- **`lib/ui.py`** — Enhanced UI components and interactive HTML reporting (EnhancedConsole, ModernHTMLReporter)

## Import Patterns

PyGuard uses a two-level module structure with convenience exports at the package level:

### Direct Module Imports (Recommended for Internal Development)
```python
from pyguard.lib.core import PyGuardLogger, BackupManager, DiffGenerator
from pyguard.lib.security import SecurityFixer
from pyguard.lib.ast_analyzer import ASTAnalyzer, SecurityVisitor
from pyguard.lib.best_practices import BestPracticesFixer
```

### Package-Level Imports (Recommended for External Use)
```python
# These are exported via pyguard/__init__.py for convenience
from pyguard import PyGuardLogger, BackupManager, SecurityFixer
from pyguard import ASTAnalyzer, BestPracticesFixer, FormattingFixer
```

### Example: Adding New Functionality
When adding a new class or function that should be publicly available:
1. Add it to the appropriate module in `pyguard/lib/`
2. Export it in `pyguard/__init__.py` by adding to the import list and `__all__`
3. Update tests in `tests/unit/` or `tests/integration/`

## Development Workflow

### Environment Setup
```bash
# Install with dev dependencies
make install-dev
# or
pip install -e ".[dev]"

# Run tests
make test

# Run linters
make lint

# Format code
make format
```

### Make Targets (Essential)
- `make dev` or `make install-dev` — Install with dev dependencies
- `make test` — Run pytest with coverage
- `make lint` — Run ruff, pylint, mypy, flake8
- `make format` or `make fmt` — Format with Black and isort
- `make type` — Run mypy type checking (via lint)
- `make clean` — Remove build artifacts
- `make security` — Run Bandit security scan

### Testing Requirements
- **New features MUST have unit tests** in `tests/unit/`
- **Integration tests** for CLI and multi-file operations in `tests/integration/`
- **Fixtures:** Use recorded samples in `tests/fixtures/` for deterministic tests
- **Coverage:** Aim for 70%+ coverage; never decrease existing coverage (current: 69%)
- **Test naming:** `test_*.py` files, `Test*` classes, `test_*` methods

### Test Structure
```
tests/
├── unit/                           # Unit tests (257 total)
│   ├── test_advanced_security.py   # Advanced security detection tests
│   ├── test_ast_analyzer.py        # AST analysis tests
│   ├── test_best_practices.py      # Code quality tests
│   ├── test_cache.py               # Cache functionality tests
│   ├── test_core.py                # Core utilities tests
│   ├── test_enhanced_detections.py # Enhanced detection tests
│   ├── test_formatting.py          # Formatting tests
│   ├── test_knowledge_integration.py # Knowledge base tests
│   ├── test_mcp_integration.py     # MCP integration tests
│   ├── test_ml_detection.py        # ML detection tests
│   ├── test_reporting.py           # Report generation tests
│   ├── test_security.py            # Security detection tests
│   ├── test_standards_integration.py # Compliance tests
│   ├── test_supply_chain.py        # Supply chain security tests
│   ├── test_ultra_advanced_fixes.py # Advanced fixes tests
│   └── test_ultra_advanced_security.py # Ultra-advanced security tests
├── integration/                    # Integration tests
│   ├── test_cli.py                # CLI integration tests
│   └── test_file_operations.py    # File operation integration tests
└── fixtures/                       # Test fixtures and sample code
    ├── sample_code/               # Sample Python files for testing
    └── expected_outputs/          # Expected test outputs
```

## Coding Standards

### Type Hints (Required)
```python
# ✅ Good
def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
    """Fix security issues in a file."""
    fixes: list[str] = []
    success: bool = True
    return success, fixes

# ❌ Bad
def fix_file(self, file_path):
    fixes = []
    return True, fixes
```

### Logging (Use PyGuardLogger)
```python
from pyguard.lib.core import PyGuardLogger

logger = PyGuardLogger()
logger.info("Processing file", file_path=str(path), operation="scan")
logger.warning("Issue detected", severity="HIGH", issue_type="SQL_INJECTION")
logger.error("Operation failed", error=str(e), file_path=str(path))
```

**Logging rules:**
- Use structured logging with key-value pairs
- No secrets in logs (passwords, tokens, API keys)
- Info for normal operations, Debug for development
- Warnings/Errors must include clear remediation guidance

### Error Handling
```python
# Graceful degradation - don't fail entire run on single file
try:
    result = analyze_file(file_path)
except SyntaxError as e:
    logger.warning("Syntax error in file", file_path=str(file_path), error=str(e))
    continue  # Skip to next file
except Exception as e:
    logger.error("Unexpected error", file_path=str(file_path), error=str(e))
    raise
```

### Configuration
- User config: `~/.config/pyguard/config.toml` or `./pyguard.toml`
- System config: `config/*.toml` (defaults)
- Precedence: CLI args > Project config > User config > System config > Defaults
- Always provide sensible defaults; never require user configuration

## Security Detection Patterns

### Adding New Detections
1. **Define the vulnerability** with CWE/OWASP IDs
2. **Add detection logic** in appropriate module (`security.py`, `ast_analyzer.py`, etc.)
3. **Add fix suggestion** with clear remediation steps
4. **Add tests** with vulnerable and safe code samples
5. **Document** in `docs/security-rules.md`

### Example Detection
```python
def detect_sql_injection(self, code: str) -> list[SecurityIssue]:
    """Detect potential SQL injection vulnerabilities."""
    issues = []
    if "cursor.execute(" in code and "%" in code:
        issues.append(SecurityIssue(
            severity="HIGH",
            category="SQL Injection",
            message="Potential SQL injection via string formatting",
            cwe_id="CWE-89",
            owasp_id="ASVS-5.3.4",
            fix_suggestion="Use parameterized queries with placeholders"
        ))
    return issues
```

## Testing Patterns

### Security Detection Tests
```python
def test_detect_sql_injection(self):
    """Test SQL injection detection."""
    vulnerable_code = '''
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    '''
    analyzer = SecurityAnalyzer()
    issues = analyzer.analyze(vulnerable_code)
    
    assert any(issue.category == "SQL Injection" for issue in issues)
    assert issues[0].severity == "HIGH"
    assert "CWE-89" in issues[0].cwe_id
```

### Using Test Fixtures
- Place sample code in `tests/fixtures/`
- Use recorded HTML/JSON for external format tests
- Keep fixtures minimal and focused
- Name clearly: `sample_vulnerable.py`, `safe_code_example.py`

## Performance Guidelines

- **Target:** 1000+ lines/second on typical hardware
- **Memory:** Keep memory usage reasonable; stream large files
- **Caching:** Cache AST parsing results when processing same file multiple times
- **Parallel processing:** Consider for directory scans, but maintain deterministic output

## Documentation Standards

### Docstrings (Required)
```python
def analyze_file(self, file_path: Path, fix: bool = False) -> AnalysisResult:
    """
    Analyze a Python file for security and quality issues.
    
    Args:
        file_path: Path to the Python file to analyze
        fix: If True, automatically apply fixes to detected issues
        
    Returns:
        AnalysisResult containing detected issues and fix status
        
    Raises:
        FileNotFoundError: If the file does not exist
        SyntaxError: If the file contains invalid Python syntax
    """
```

### Code Comments
- **Don't over-comment** — code should be self-documenting
- **Do comment** complex algorithms, security considerations, or non-obvious decisions
- **TODO comments:** Use `TODO(username): description` format
- **Security notes:** Mark with `# SECURITY:` prefix

## Pull Request Checklist

Before submitting a PR, verify:

- [ ] No secrets committed; environment variables only
- [ ] All tests pass locally (`make test`)
- [ ] Code formatted with Black (`make format`)
- [ ] Type hints added for new code
- [ ] Linters pass (`make lint`)
- [ ] Documentation updated (docstrings, README if needed)
- [ ] New features have unit tests
- [ ] Backward compatibility maintained (or migration provided)
- [ ] Logs are structured; no PII or secrets
- [ ] CHANGELOG.md updated (if applicable)

## Common Tasks for Copilot

### Add a New Security Detection
1. Study similar detections in `pyguard/lib/security.py` or `pyguard/lib/ast_analyzer.py`
2. Add detection method with CWE/OWASP mapping
3. Add fix suggestion and remediation guidance
4. Create unit tests in `tests/unit/test_security.py`
5. Document in `docs/security-rules.md`

### Improve Auto-Fix Logic
1. Check existing fix patterns in `pyguard/lib/security.py`
2. Ensure backup is created before modification
3. Add rollback capability for failed fixes
4. Test with multiple code variations
5. Handle edge cases gracefully

### Add New Compliance Framework
1. Study existing mappings in knowledge base modules
2. Map CWE IDs to framework requirements
3. Add framework-specific reporting
4. Document in `docs/compliance.md` (or relevant doc)

### Optimize Performance
1. Profile with `python -m cProfile`
2. Identify bottlenecks in AST parsing or pattern matching
3. Add caching where appropriate
4. Maintain code clarity; premature optimization is the root of all evil

## Absolute Rules

❌ **Do NOT:**
- Add telemetry, analytics, or any outbound data collection
- Hardcode secrets, credentials, or API keys
- Break backward compatibility without migration path
- Remove or modify working code without justification
- Add dependencies without discussing necessity
- Execute analyzed code (static analysis only)
- Log sensitive data (passwords, tokens, PII)

✅ **Do:**
- Keep privacy and security as top priorities
- Create backups before destructive operations
- Provide clear error messages and remediation steps
- Write comprehensive tests for new features
- Follow existing code patterns and conventions
- Document complex logic and security considerations
- Use type hints and maintain type safety

## Configuration Schema

PyGuard uses TOML configuration files. Example structure:

```toml
[general]
max_line_length = 100
exclude_patterns = ["*/migrations/*", "*/vendor/*"]

[security]
enabled = true
severity_threshold = "MEDIUM"

[security.checks]
sql_injection = true
command_injection = true
hardcoded_secrets = true

[best_practices]
enabled = true
naming_conventions = true
docstring_checks = true

[formatting]
use_black = true
use_isort = true
line_length = 100
```

## Additional Resources

- **Architecture:** `docs/ARCHITECTURE.md`
- **Contributing:** `CONTRIBUTING.md`
- **Security Policy:** `SECURITY.md`
- **User Guide:** `docs/user-guide.md`
- **API Reference:** `docs/api-reference.md`
- **Security Rules:** `docs/security-rules.md`

---

## Python Version Pinning

**Recommended development version:** Python 3.13.8
**Minimum supported version:** Python 3.8
**Maximum tested version:** Python 3.13

Ensure consistency across:
- `README.md` badges
- `pyproject.toml` (requires-python)
- `Dockerfile` (FROM python:3.13-slim)
- `.github/workflows/*.yml` (python-version: '3.13')
- `.python-version` and `.tool-versions` (3.13.8)
- Documentation examples

---

**Remember:** PyGuard exists to help developers write more secure, maintainable Python code. Every feature should serve this mission while respecting user privacy and maintaining the highest code quality standards.
