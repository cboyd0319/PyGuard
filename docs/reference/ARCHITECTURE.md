# PyGuard Architecture

**Version:** 0.7.0 | **Status:** Production Ready | **Last Updated:** 2025-11-14

## Overview

PyGuard is a comprehensive Python security and code quality analysis tool that detects vulnerabilities, enforces best practices, and provides automated fixes. It's designed to be:

- **Production-ready:** 84%+ test coverage (target: 87%), strict type checking, extensive CI/CD integration
- **High-performance:** RipGrep integration for 10-100x faster scanning, parallel processing, smart caching
- **Framework-aware:** Deep understanding of 25 frameworks - Django, Flask, FastAPI, Tornado, Celery, asyncio, and 19 more
- **Fix-capable:** 199+ auto-fixes (107 safe, 72 unsafe) for detected issues with automatic backups
- **Minimal dependencies:** Only 2 core dependencies (rich + watchdog), 2 optional for notebooks (nbformat + nbclient)

## Core Architecture

### Three-Layer Design

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI & User Interface                     │
│                  (cli.py, ui.py, reporting.py)              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core Engine                            │
│          (core.py, rule_engine.py, ast_analyzer.py)         │
│                                                              │
│  • AST Analysis • Pattern Matching • Rule Evaluation        │
│  • Fix Application • Severity Assessment                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Detection Modules (lib/)                   │
│                                                              │
│  Security           │  Best Practices   │  Framework-Specific│
│  ─────────          │  ───────────      │  ─────────────────│
│  • injection        │  • pep8           │  • flask           │
│  • crypto           │  • type hints     │  • django          │
│  • auth             │  • performance    │  • fastapi         │
│  • xss              │  • modern python  │  • sqlalchemy      │
│  • secrets          │  • naming         │  • pandas          │
│  • AI/ML security   │  • complexity     │  • tensorflow      │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
pyguard/
├── cli.py                      # Main CLI orchestrator (PyGuardCLI class)
├── api.py                      # Programmatic API (PyGuardAPI class)
├── git_hooks_cli.py            # Git hooks integration (separate CLI)
├── __init__.py                 # Package initialization + version
│
├── commands/                   # Command implementations (v0.7.0 new)
│   ├── scan.py                 # Read-only security & quality analysis
│   ├── fix.py                  # Apply auto-fixes with backups
│   ├── init.py                 # Interactive configuration generator
│   ├── validate_config.py      # Configuration verification
│   ├── watch.py                # Real-time file monitoring & fixing
│   ├── doctor.py               # Environment diagnostics
│   └── explain.py              # Remediation guidance
│
└── lib/                        # Detection & analysis modules (114 Python files)
    ├── __init__.py             # Module registry
    │
    ├── core.py                 # Core data structures (BackupManager, FileOperations, PyGuardLogger)
    ├── rule_engine.py          # Rule evaluation engine with RuleRegistry
    ├── ast_analyzer.py         # Python AST analysis utilities (ASTAnalyzer class)
    │
    ├── Security Modules (14 files - 739 checks total)/
    │   ├── security.py               # Core security (20+ checks)
    │   ├── advanced_security.py      # Advanced patterns (taint analysis, ReDoS, race conditions)
    │   ├── ruff_security.py          # All 73 Bandit/Ruff S-rules
    │   ├── api_security.py           # REST/GraphQL/WebSocket (20 checks)
    │   ├── api_security_fixes.py     # API security auto-fixes
    │   ├── auth_security.py          # Authentication & authorization (15 checks)
    │   ├── crypto_security.py        # Cryptography vulnerabilities (15 checks)
    │   ├── ai_ml_security.py         # ML/LLM-specific risks (30+ checks)
    │   ├── blockchain_security.py    # Web3/crypto vulnerabilities
    │   ├── cloud_security.py         # AWS/Azure/GCP misconfigurations (15 checks)
    │   ├── mobile_iot_security.py    # Mobile and IoT security
    │   ├── ultra_advanced_security.py # Complex vulnerability patterns (21+ checks)
    │   ├── enhanced_security_fixes.py # Enhanced auto-fix implementations
    │   └── notebook_security.py      # Jupyter notebook security (8+ checks)
    │
    ├── Framework Modules (25 verified files - 266+ rules)/
    │   ├── framework_django.py       # Django security (13 checks)
    │   ├── framework_flask.py        # Flask security (7 checks)
    │   ├── framework_fastapi.py      # FastAPI security (37 checks)
    │   ├── framework_tornado.py      # Tornado async framework (20 checks)
    │   ├── framework_celery.py       # Celery task queue (20 checks)
    │   ├── framework_pyramid.py      # Pyramid web framework (15 checks)
    │   ├── framework_asyncio.py      # asyncio patterns (15 checks)
    │   ├── framework_sanic.py        # Sanic async framework (14 checks)
    │   ├── framework_quart.py        # Quart async Flask (15 checks)
    │   ├── framework_bottle.py       # Bottle micro-framework (10 checks)
    │   ├── framework_sqlalchemy.py   # SQLAlchemy ORM (14 checks)
    │   ├── framework_peewee.py       # Peewee ORM (12 checks)
    │   ├── framework_pony.py         # Pony ORM (12 checks)
    │   ├── framework_tortoise.py     # Tortoise ORM (15 checks)
    │   ├── framework_pandas.py       # Pandas data analysis (7 checks)
    │   ├── framework_numpy.py        # NumPy arrays (15 checks)
    │   ├── framework_tensorflow.py   # TensorFlow ML (20 checks)
    │   ├── framework_sklearn.py      # Scikit-learn ML (8 checks)
    │   ├── framework_scipy.py        # SciPy scientific (10 checks)
    │   ├── framework_pyspark.py      # PySpark big data (10 checks)
    │   ├── framework_airflow.py      # Airflow orchestration (9 checks)
    │   ├── framework_streamlit.py    # Streamlit UI (7 checks)
    │   ├── framework_dash.py         # Plotly Dash (5 checks)
    │   ├── framework_gradio.py       # Gradio ML UI (6 checks)
    │   └── framework_pytest.py       # Pytest testing (8 checks)
    │
    ├── Best Practices/
    │   ├── best_practices.py         # General Python best practices
    │   ├── pep8_comprehensive.py     # PEP 8 style guide
    │   ├── modern_python.py          # Modern Python idioms
    │   ├── type_checker.py           # Type hint enforcement
    │   ├── comprehensions.py         # List/dict comprehension patterns
    │   ├── exception_handling.py     # Exception handling patterns
    │   └── performance_checks.py     # Performance anti-patterns
    │
    ├── Auto-Fix Modules/
    │   ├── api_security_fixes.py     # API security fixes
    │   ├── enhanced_security_fixes.py # Enhanced security fixes
    │   ├── ultra_advanced_fixes.py   # Complex auto-fixes
    │   └── notebook_auto_fix_enhanced.py # Jupyter notebook fixes
    │
    ├── Integration & Utilities/
    │   ├── sarif_reporter.py         # SARIF output for GitHub
    │   ├── reporting.py              # Report generation
    │   ├── ci_integration.py         # CI/CD helpers
    │   ├── git_hooks.py              # Git hook integration
    │   ├── mcp_integration.py        # MCP server integration
    │   ├── ripgrep_filter.py         # RipGrep fast scanning
    │   ├── parallel.py               # Parallel processing
    │   ├── cache.py                  # Result caching
    │   └── ui.py                     # Terminal UI components
    │
    └── Jupyter Support/
        ├── notebook_security.py      # Notebook-specific checks
        ├── notebook_analyzer.py      # Notebook AST analysis
        └── notebook_auto_fix_enhanced.py # Notebook auto-fixes
```

## Key Components

### 1. Core Engine (`core.py`, `rule_engine.py`)

**Purpose:** Central rule evaluation and violation management.

**Key Data Structures:**
```python
@dataclass
class RuleViolation:
    rule_id: str              # e.g., "SEC001"
    category: RuleCategory    # SECURITY, BEST_PRACTICES, etc.
    severity: RuleSeverity    # HIGH, MEDIUM, LOW
    message: str              # Human-readable description
    line_number: int          # Source location
    column: int
    fix_suggestion: str | None  # Auto-fix suggestion
    fix_applicability: FixApplicability  # SAFE, UNSAFE, MANUAL
```

**Design Principles:**
- Immutable data structures for thread safety
- Type-safe with dataclasses and enums
- Extensible through Protocol-based interfaces

### 2. AST Analyzer (`ast_analyzer.py`)

**Purpose:** Python Abstract Syntax Tree analysis utilities.

**Capabilities:**
- Function call detection
- Variable assignment tracking
- Import analysis
- Control flow analysis
- Context-aware pattern matching

**Key Functions:**
```python
def find_function_calls(node: ast.AST, func_name: str) -> list[ast.Call]
def get_string_from_node(node: ast.AST) -> str | None
def is_dangerous_function(call: ast.Call) -> bool
```

### 3. Detection Modules

**Pattern:** Each module implements domain-specific detection logic.

**Structure:**
```python
def analyze_<domain>(file_path: Path, content: str) -> list[RuleViolation]:
    """Main entry point for detection."""
    tree = ast.parse(content)
    violations = []
    
    # Visitor pattern or explicit traversal
    for node in ast.walk(tree):
        if matches_pattern(node):
            violations.append(create_violation(node))
    
    return violations
```

**Module Categories:**
1. **Security:** Vulnerability detection (injection, XSS, secrets, etc.)
2. **Framework:** Framework-specific patterns (Django, Flask, etc.)
3. **Best Practices:** Code quality (PEP 8, type hints, etc.)
4. **Auto-Fix:** Automated remediation logic

### 4. CLI Interface (`cli.py`)

**Design:** Comprehensive command-line interface with subcommands.

**Main Commands:**
```bash
pyguard <path>                  # Scan files
pyguard --fix <path>            # Apply fixes
pyguard --sarif <path>          # SARIF output
pyguard --config <path>         # Custom config
pyguard --fast                  # RipGrep mode
pyguard --compliance-report     # Compliance summary
```

**Configuration:**
- Environment variables
- `pyguard.toml` configuration file
- CLI argument overrides

### 5. Auto-Fix Engine

**Safety Levels:**
1. **SAFE:** 100% safe transformations (e.g., add missing imports)
2. **UNSAFE:** May change behavior (e.g., replace `eval()` with `ast.literal_eval()`)
3. **MANUAL:** Requires human review

**Fix Application:**
```python
def apply_fix(violation: RuleViolation, content: str) -> str:
    """Apply a fix to source code."""
    if violation.fix_applicability == FixApplicability.SAFE:
        return apply_safe_fix(violation, content)
    elif violation.fix_applicability == FixApplicability.UNSAFE:
        if user_confirms():
            return apply_unsafe_fix(violation, content)
    return content  # No fix applied
```

### 6. Framework Integration

**Approach:** Deep framework understanding for accurate detection.

**Example (Django):**
- Understands Django ORM patterns
- Detects raw SQL usage
- Checks for CSRF protection
- Validates authentication decorators
- Analyzes template rendering

**Example (FastAPI):**
- Async function analysis
- Dependency injection patterns
- Pydantic model validation
- OpenAPI security schemes

## Performance Optimizations

### 1. RipGrep Integration (`ripgrep_filter.py`)

**Strategy:** Pre-filter files before AST parsing.

**Benefits:**
- 10-100x faster scanning
- Pattern-based file filtering
- Parallel execution
- Incremental scanning

**Usage:**
```bash
pyguard --fast <path>           # Enable RipGrep
pyguard --scan-secrets --fast   # 114x faster secret scanning
```

### 2. Caching (`cache.py`)

**Strategy:** Cache analysis results to avoid re-parsing.

**Cache Key:** `(file_path, file_mtime, content_hash)`

**Invalidation:** Automatic on file modification.

### 3. Parallel Processing (`parallel.py`)

**Strategy:** Process multiple files concurrently.

**Implementation:**
- Process pool for CPU-bound tasks
- Thread pool for I/O-bound tasks
- Configurable worker count

## Security Model

### Detection Categories

**OWASP Top 10 Coverage:**
- ✅ A01:2021 - Broken Access Control
- ✅ A02:2021 - Cryptographic Failures
- ✅ A03:2021 - Injection
- ✅ A04:2021 - Insecure Design
- ✅ A05:2021 - Security Misconfiguration
- ✅ A06:2021 - Vulnerable Components
- ✅ A07:2021 - Authentication Failures
- ✅ A08:2021 - Software/Data Integrity
- ✅ A09:2021 - Security Logging Failures
- ✅ A10:2021 - SSRF

**Compliance Frameworks:**
- PCI-DSS
- HIPAA
- SOC 2
- ISO 27001
- NIST
- GDPR
- CCPA
- FedRAMP
- SOX

### Severity Assignment

**Criteria:**
1. **HIGH:** Exploitable vulnerabilities (SQL injection, XSS, secrets)
2. **MEDIUM:** Security weaknesses (weak crypto, missing validation)
3. **LOW:** Best practices violations (style issues, minor optimizations)

## Extension Points

### 1. Custom Rules

Users can add custom detection rules:

```python
from pyguard.lib.core import RuleViolation, RuleSeverity

def detect_custom_pattern(node: ast.AST) -> RuleViolation | None:
    """Custom detection logic."""
    if matches_my_pattern(node):
        return RuleViolation(
            rule_id="CUSTOM001",
            severity=RuleSeverity.HIGH,
            message="Custom pattern detected",
            line_number=node.lineno,
        )
    return None
```

### 2. Custom Auto-Fixes

Implement custom fix logic:

```python
from pyguard.lib.fix_safety import FixApplicability

def fix_custom_pattern(violation: RuleViolation, content: str) -> str:
    """Apply custom fix."""
    # Transformation logic
    return transformed_content
```

### 3. Output Formats

Add custom reporters:

```python
from pyguard.lib.reporting import Reporter

class CustomReporter(Reporter):
    def generate(self, violations: list[RuleViolation]) -> str:
        """Generate custom report format."""
        return format_as_custom(violations)
```

## CI/CD Integration

### GitHub Actions

**Pre-built Action:** `cboyd0319/pyguard-action`

```yaml
- uses: cboyd0319/pyguard-action@v1
  with:
    path: .
    fail-on: high
    sarif: true
```

### GitLab CI

```yaml
pyguard:
  script:
    - pip install pyguard
    - pyguard --sarif src/ > pyguard.sarif
  artifacts:
    reports:
      sast: pyguard.sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: pyguard
        name: PyGuard Security Scan
        entry: pyguard
        language: system
        types: [python]
```

## Testing Architecture

### Test Organization

```
tests/
├── unit/              # Unit tests for each module
├── integration/       # Integration tests
├── fixtures/          # Test fixtures
│   ├── notebooks/     # Jupyter notebooks for testing
│   └── *.py           # Sample vulnerable code
└── benchmarks/        # Performance benchmarks
```

### Test Coverage

- **Target:** 90%+ line coverage, 85%+ branch coverage
- **Current:** 87%+ coverage
- **Strategy:** 
  - Property-based testing with Hypothesis
  - Snapshot testing for auto-fixes
  - Integration tests for CLI

## Future Architecture Improvements

### Planned Enhancements

1. **Plugin System:** Dynamic module loading for custom detections
2. **Language Server Protocol:** IDE integration (VS Code, PyCharm)
3. **Web Dashboard:** Visual reporting and trend analysis
4. **AI-Powered Fixes:** LLM-assisted fix suggestions
5. **Multi-language Support:** Extend to JavaScript, TypeScript, Go

### Refactoring Opportunities

1. **Split Large Modules:** `ai_ml_security.py` (27K lines) → sub-package
2. **Visitor Pattern:** Refactor AST traversal for consistency
3. **Strategy Pattern:** Pluggable detection strategies
4. **Factory Pattern:** Dynamic reporter/fixer instantiation

## Contributing

### Adding a New Detection

1. Create module in `pyguard/lib/<category>_<name>.py`
2. Implement `analyze_<name>(path, content) -> list[RuleViolation]`
3. Add tests in `tests/unit/test_<name>.py`
4. Register in `pyguard/lib/__init__.py`
5. Document in `docs/reference/capabilities-reference.md`

### Adding Auto-Fix

1. Implement fix in `<module>_fixes.py`
2. Set appropriate `FixApplicability` level
3. Add snapshot tests for idempotency
4. Document in fix suggestion

### Code Style

- **Formatting:** Black (line-length=100)
- **Imports:** isort (black profile)
- **Linting:** Ruff, Pylint, mypy
- **Type Hints:** 100% coverage for public APIs
- **Testing:** pytest, 90%+ coverage

## Distribution Architecture (v0.7.0+)

### Multi-Channel Distribution Strategy

PyGuard will be available through multiple channels to meet developers where they work:

1. **PyPI** (Current) - `pip install pyguard`
2. **Homebrew** (v0.7.0) - `brew install pyguard`
3. **GitHub Action** (Current) - Native CI/CD integration
4. **Docker Hub** (v0.7.0) - Official container images
5. **VS Code Extension** (v0.7.0) - IDE integration via LSP
6. **PyCharm Plugin** (v0.8.0) - IntelliJ Platform integration

### Language Server Protocol (LSP) Integration

Real-time security linting in IDEs powered by LSP:

- Real-time diagnostics as you type
- Quick fix suggestions (CodeActions)
- Hover information for security issues
- Jupyter notebook cell-level scanning

### Secure Supply Chain

PyGuard implements industry-leading security practices:

- **SLSA Level 3 Provenance** (v0.8.0) - Verifiable build integrity
- **Sigstore/Cosign Signing** (v0.8.0) - Keyless release signing
- **SBOM Generation** (v0.7.0) - Complete dependency transparency
- **Reproducible Builds** (v1.0.0) - Bit-for-bit verification

See [DISTRIBUTION.md](DISTRIBUTION.md) for comprehensive distribution strategy and [ROADMAP.md](ROADMAP.md) for detailed timelines.

---

**Document Version:** 1.1  
**Last Updated:** 2025-11-03  
**Maintainer:** Chad Boyd  
**Distribution:** [DISTRIBUTION.md](DISTRIBUTION.md)  
**Roadmap:** [ROADMAP.md](ROADMAP.md)
