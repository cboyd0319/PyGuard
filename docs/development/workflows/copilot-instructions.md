# GitHub Copilot Instructions — PyGuard

> **Purpose:** PyGuard is a comprehensive Python security & code quality analysis tool with ML-powered detection, auto-fix capabilities, and support for 10+ compliance frameworks (OWASP, CWE, PCI-DSS, HIPAA, etc.). It detects **184 security vulnerabilities** and code quality issues while maintaining 100% local operation with no telemetry. **Currently 61% complete on Security Dominance Plan** (targeting 300+ checks to surpass all competitors).

## Quick Reference (Most Common Commands)
```bash
# Development setup
make dev                    # Install with dev dependencies
pip install -e ".[dev]"     # Alternative install

# Running PyGuard
pyguard .                                           # Scan current directory
pyguard . --scan-only                               # Scan without fixing
pyguard . --security-only                           # Security checks only
pyguard . --severity HIGH                           # Only HIGH severity issues
pyguard . --format json --output report.json        # JSON report

# Quality checks (run before every commit)
make test          # Run all tests with coverage (70% min)
make format        # Format with Black and isort
pyguard pyguard/   # Use PyGuard to scan itself (replaces external linters)
make clean         # Remove build artifacts

# Quick test cycle
make format && pyguard pyguard/ --scan-only && make test
```

> **Important**: When writing unit tests or working on PyGuard code, **use PyGuard to scan itself** (`pyguard pyguard/`) instead of external tools like ruff, pylint, or flake8. PyGuard should be capable of scanning itself to find issues. If it cannot, that's a feature gap to fix.

## Project Overview

- **Core functionality:** Static analysis → Detection → Auto-fix → Report
- **Security focus:** **184 security vulnerability types** (CWE, OWASP Top 10, OWASP ASVS) — **61% toward 300+ goal**, only 16 checks behind Snyk
- **Quality analysis:** 150+ code quality checks (naming, docstrings, complexity, best practices)
- **Compliance:** Multi-framework support (OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX)
- **ML-powered:** Risk scoring, anomaly detection, vulnerability prediction
- **Auto-fix:** **199+ automatic fixes** with backup/rollback support — **100% coverage maintained**
- **Reports:** HTML, JSON, SARIF, console output with severity-based filtering
- **Frameworks:** Django, Flask, **FastAPI** (30 checks), Pandas, Pytest — **expanding to 20+ frameworks**

## Repository Standards & Configuration

### Workflow & Automation Standards
- **Dependabot:** Weekly schedule (Mondays 09:00 UTC), commit prefix `chore(deps):`, grouped updates
- **Auto-merge:** Automatic approval for all Dependabot PRs, auto-merge for patch/minor versions only
- **CI/CD:** GitHub Actions workflows in `.github/workflows/` (see `python-qa.yml`, `dependabot-auto-merge.yml`)
- **Quality Gates:** All PRs must pass linting (Ruff), type checking (mypy), tests (70% coverage), security scans before merge

### File Organization Standards
- **`.github/` directory:** Contains only GitHub-specific configs (workflows, templates, Copilot instructions)
  - Templates: `pull_request_template.md`, `ISSUE_TEMPLATE/*.yml` (lowercase naming)
  - Ownership: `CODEOWNERS` defines code review requirements (@cboyd0319)
  - Actions: Custom actions if needed in `.github/actions/`
- **Documentation:** All docs in `/docs`, never in `.github/`
- **Scripts:** Development/deployment scripts in `/scripts`, never in `.github/`
- **Configuration:** Security rules in `/config` (security_rules.toml, qa_settings.toml)

### Inclusive Terminology Standards
- **Required replacements:**
  - Use "allowlist" instead of "whitelist"
  - Use "denylist" instead of "blacklist"
  - Use "main" branch instead of "master" branch
  - Use "primary/replica" instead of "master/slave" in architecture discussions
- **Code review:** All PRs checked for outdated terminology
- **Detection rules:** PyGuard security rules updated to detect these patterns in user code

### Configuration Management
- **Security rules:** `config/security_rules.toml` — Detection patterns and severity levels
- **QA settings:** `config/qa_settings.toml` — Code quality thresholds and preferences
- **Secrets:** Environment variables only (never commit credentials)
- **MCP integration:** `.github/copilot-mcp.json` for Model Context Protocol servers
- **Compliance frameworks:** Built-in support for OWASP, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, GDPR, CCPA, FedRAMP, SOX

### GitHub Configuration Files
- **Dependabot:** `.github/dependabot.yml` — Standardized across all repos
- **Workflows:** `.github/workflows/*.yml` — GitHub Actions automation
- **Templates:** `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*.yml`
- **Copilot:** `.github/copilot-instructions.md` (this file), `.github/copilot-mcp.json`
- **Ownership:** `.github/CODEOWNERS` — Code review assignments (@cboyd0319)

## Documentation (Copilot — follow these rules)

### Documentation Hub
- Start at `docs/DOCUMENTATION_INDEX.md` (alias to `docs/index.md`) and `docs/README.md` where referenced.

### Docs Structure & Style (enforced)
- All docs live in `docs/` (never under `.github/`).
- Prefer short, scannable bullets; keep lines ≤120 chars (MD013).
- Use active voice and avoid hedging; Vale enforces terminology and spelling.
- Make commands runnable; pin versions; include expected output where useful.
- Keep cross‑links valid when moving docs; avoid broken anchors.

### Docs CI (must pass on PR)
- Markdownlint (`.github/workflows/docs-ci.yml`) — MD013 line length = 120.
- Vale style lint (`.vale.ini` + `Styles/`) — active voice, terminology, spelling.
- Lychee link check (`.lycheeignore` covers local/secret URLs).

### When adding or editing docs
- Put deep‑dives under `docs/reference/` when appropriate; link from the hub.
- Prefer bullets for configuration/performance; keep examples self‑contained.
- Run locally: `markdownlint "**/*.md"` and `vale .` before pushing.

## Core Principles

### Privacy & Security First
- **No telemetry.** All analysis happens locally. Never ship code that phones home.
- **Secrets handling:** Never hardcode tokens, keys, or credentials. Use environment variables.
- **No PII in logs:** Structured logging in JSON format without sensitive data.
- **Backup before fix:** Always create backups before applying auto-fixes.

### Code Quality Standards
- **Language:** Python 3.11+ (recommend 3.13 for development)
- **Style:** PEP 8/PEP 257 with Black formatter (line length: 100)
- **Type hints:** Required for new code, mypy-friendly
- **Testing:** pytest with 70%+ coverage target (currently 84% coverage, 78 test files)
- **Logging:** Structured JSON logs (PyGuardLogger in `pyguard/lib/core.py`)

## MCP Integration (Model Context Protocol)

PyGuard integrates with MCP servers for enhanced AI capabilities:

### Built-in (GitHub Copilot)
- **github-mcp:** Repository operations, issues, PRs (OAuth authentication, automatic - no config needed)

> ⚠️ **CRITICAL: GitHub MCP Authentication**
> 
> GitHub MCP tools are **built-in to GitHub Copilot** and use **OAuth authentication automatically**.
> 
> **DO NOT:**
> - Add GitHub server configuration to `.github/copilot-mcp.json`
> - Attempt to use Personal Access Tokens (PAT) with GitHub MCP
> - Configure any GitHub-related authentication manually
> 
> **ERROR:** If you see `API returned status 400: Personal Access Tokens are not supported for this endpoint`,
> you are attempting to use a PAT where OAuth is required. GitHub MCP uses OAuth through Copilot's built-in
> authentication only.

### External (Configured)
- **context7:** Version-specific Python security documentation (HTTP, needs API key)
  - Provides accurate docs for Bandit, Ruff, mypy, pytest, OWASP, CWE standards
  - No hallucinations, direct from source
- **openai-websearch:** Web search via OpenAI for current threat intelligence (local/uvx, needs API key)
  - Use for emerging security patterns, new CVEs, compliance updates
- **fetch:** Web content fetching (local/npx, ready)
  - Useful for CVE databases, NVD, security advisories
- **playwright:** Browser automation for web security testing (local/npx, ready)
  - Test web application security patterns

**Config:** `.github/copilot-mcp.json` (HTTP and local command servers for external integrations only)

**Environment Variables Required:**
- `COPILOT_MCP_CONTEXT7_API_KEY` — For Context7 documentation access
- `COPILOT_MCP_OPENAI_API_KEY` — For OpenAI web search capabilities

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
- **Coverage:** Aim for 70%+ coverage; never decrease existing coverage (current: 84%)
- **Test naming:** `test_*.py` files, `Test*` classes, `test_*` methods

### Test Structure
```
tests/
├── unit/                           # Unit tests (78 test files total)
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

## Data Contracts

### SecurityIssue Record
```python
@dataclass
class SecurityIssue:
    """Represents a detected security vulnerability."""
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str  # e.g., "SQL Injection", "XSS", "Hardcoded Secret"
    message: str
    file_path: str
    line_number: int
    cwe_id: str  # e.g., "CWE-89"
    owasp_id: Optional[str]  # e.g., "ASVS-5.3.4"
    confidence: float  # 0.0-1.0 (ML confidence score)
    fix_suggestion: Optional[str]
    code_snippet: Optional[str]
```

### AnalysisResult Record
```python
@dataclass
class AnalysisResult:
    """Results from analyzing a file or directory."""
    total_files: int
    total_issues: int
    issues_by_severity: dict[str, int]  # {"CRITICAL": 0, "HIGH": 5, ...}
    issues: list[SecurityIssue]
    execution_time: float
    scan_timestamp: str  # ISO 8601 format
    frameworks_applied: list[str]  # ["owasp", "pci-dss", ...]
```

### Configuration Schema
```python
@dataclass
class PyGuardConfig:
    """PyGuard configuration."""
    severity_threshold: str = "MEDIUM"  # Minimum severity to report
    frameworks: list[str] = field(default_factory=list)  # Compliance frameworks
    exclude_patterns: list[str] = field(default_factory=list)
    auto_fix: bool = False
    backup_enabled: bool = True
    max_line_length: int = 100
    enable_ml: bool = True  # Enable ML-powered detection
```

> If you add fields, maintain backward compatibility and provide migration guidance.

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
5. Document in `docs/security-rules.md` or `docs/README.md`

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
4. Document in `docs/README.md` (compliance section)

### Optimize Performance
1. Profile with `python -m cProfile`
2. Identify bottlenecks in AST parsing or pattern matching
3. Add caching where appropriate
4. Maintain code clarity; premature optimization is the root of all evil

## Common Pitfalls & Gotchas

1. **Python Version:** Supports 3.11+ but recommend 3.13 for development
   - Check with `python3 --version` or `python --version`
   - CI tests on Python 3.11, 3.12, and 3.13

2. **Virtual Environment:** Always activate before development
   - Symptom: `ModuleNotFoundError: No module named 'pyguard'`
   - Fix: `source .venv/bin/activate` (Linux/Mac) or `.venv\Scripts\activate` (Windows)

3. **Import Paths:** Use proper import patterns (see Import Patterns section)
   - ✅ GOOD: `from pyguard.lib.core import PyGuardLogger`
   - ✅ ALSO GOOD: `from pyguard import PyGuardLogger` (via __init__.py)
   - ❌ AVOID: `from ..lib.core import PyGuardLogger`

4. **Type Hints:** Required for new code (mypy checking)
   - All public functions need type hints
   - Use `# type: ignore[<code>]` sparingly with justification

5. **Test Isolation:** Tests must not depend on external services
   - Mock all HTTP calls
   - Use fixtures for test data
   - No live API calls in tests

6. **Secrets:** Never commit .env or files containing secrets
   - .gitignore already handles this
   - CI fails if secrets detected in code

7. **AST Parsing:** Handle syntax errors gracefully
   - Symptom: `SyntaxError` on malformed Python files
   - Fix: Catch and log, continue with next file (don't crash entire scan)

8. **Coverage Threshold:** Maintain 70% minimum coverage
   - Running tests will fail if coverage drops below threshold
   - Add tests before adding new features

9. **Security Rule Updates:** Keep CWE/OWASP mappings current
   - Reference official databases (cwe.mitre.org, owasp.org)
   - Document sources in code comments

10. **Auto-Fix Idempotency:** All fixes must be idempotent
    - Running fix twice should produce same result as running once
    - Test with `--fix` flag multiple times

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

### Documentation
- **Main Docs:** `docs/README.md` — Comprehensive documentation (architecture, usage, API)
- **Development:** `docs/UPDATEv2.md` — Development status and roadmap
- **Security Rules:** `docs/security-rules.md` — Security detection rules reference
- **Contributing:** `CONTRIBUTING.md` — Contribution guidelines
- **Security Policy:** `SECURITY.md` — Security reporting and policies

### GitHub Copilot Configuration
- **MCP Servers:** `.github/COPILOT-MCP-SERVERS.md` — MCP server configuration guide
- **MCP Config:** `.github/copilot-mcp.json` — MCP server definitions (Context7, OpenAI, Fetch, Playwright)

---

## Python Version Pinning

**Recommended development version:** Python 3.13.9
**Minimum supported version:** Python 3.11
**Maximum tested version:** Python 3.13

Ensure consistency across:
- `README.md` badges
- `pyproject.toml` (requires-python)
- `Dockerfile` (FROM python:3.13-slim)
- `.github/workflows/*.yml` (python-version: '3.13')
- `.python-version` and `.tool-versions` (3.13.9)
- Documentation examples

---

## Quick Reference

### Common Development Tasks

**Setup and Test**
```bash
make dev              # Install with dev dependencies
make test             # Run full test suite with coverage
make test-fast        # Run tests without coverage
make lint             # Run all linters (ruff, pylint, mypy, flake8)
make format           # Format code with Black and isort
make security         # Run Bandit security scan
```

**Running PyGuard**
```bash
pyguard src/                    # Scan and fix entire directory
pyguard file.py                 # Scan and fix single file
pyguard src/ --security-only    # Only security fixes
pyguard src/ --scan-only        # Scan without fixing
pyguard src/ --no-backup        # Skip backup creation
```

**Common Code Patterns**
```python
# Import core utilities
from pyguard.lib.core import PyGuardLogger, BackupManager, DiffGenerator

# Import security analysis
from pyguard.lib.security import SecurityFixer
from pyguard.lib.ast_analyzer import ASTAnalyzer, SecurityVisitor

# Import code quality
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.formatting import FormattingFixer

# Use structured logging
logger = PyGuardLogger()
logger.info("Operation complete", file_path=str(path), status="success")
```

**Testing Patterns**
```python
# Unit test structure
def test_detect_vulnerability(self):
    """Test detection of specific vulnerability."""
    vulnerable_code = '''
    # Sample vulnerable code
    '''
    analyzer = SecurityFixer()
    issues = analyzer.analyze(vulnerable_code)
    
    assert len(issues) > 0
    assert issues[0].severity == "HIGH"
    assert "CWE-" in issues[0].cwe_id
```

### Key Files to Know

| File | Purpose |
|------|---------|
| `pyguard/cli.py` | Main CLI entry point |
| `pyguard/__init__.py` | Package exports |
| `pyguard/lib/core.py` | Core utilities (logging, backup, diff) |
| `pyguard/lib/security.py` | Security vulnerability detection |
| `pyguard/lib/ast_analyzer.py` | AST-based static analysis |
| `pyproject.toml` | Package configuration |
| `pytest.ini` | Test configuration |
| `Makefile` | Development commands |

---

**Remember:** PyGuard exists to help developers write more secure, maintainable Python code. Every feature should serve this mission while respecting user privacy and maintaining the highest code quality standards.
