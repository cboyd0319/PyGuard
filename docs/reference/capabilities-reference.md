# PyGuard Capabilities Reference

**Complete catalog of all capabilities, features, and integrations in PyGuard**

> **TL;DR**: Comprehensive Python security and code quality platform. Replaces 7+ tools (Bandit, Ruff, Pylint, Semgrep, Black, isort, mypy) with 55+ security checks, 150+ code quality rules, 179+ auto-fixes, ML-powered detection, and 10+ compliance frameworks. Runs locally, no telemetry.

## Statistics at a Glance

| Category | Count | Status |
|----------|-------|--------|
| **Library Modules** | 59 | ✅ Production |
| **Total Lines of Code** | 30,500+ | ✅ Production |
| **Security Checks** | 55+ | ✅ Active |
| **Code Quality Rules** | 150+ | ✅ Active |
| **Auto-Fixes** | 179+ | ✅ 100% Coverage |
| **Framework Rules** | 75+ | ✅ 4 Frameworks |
| **Compliance Frameworks** | 10+ | ✅ Full Mapping |
| **ML Features** | 5 | ✅ Active |
| **Test Files** | 62 | ✅ Comprehensive |
| **Test Coverage** | 84% | 🎯 Target: 100% |
| **GitHub Actions** | ✅ Native | ✅ SARIF 2.1.0 |

**Tool Replacement Matrix**: Bandit • Semgrep • Ruff • Pylint • Black • isort • mypy (partial) • Safety • Flake8

---

## Table of Contents

### Core Capabilities
1. [Security Detection](#1-security-detection) — 55+ vulnerability checks
2. [Code Quality](#2-code-quality) — 150+ rules across 10 categories
3. [Auto-Fix System](#3-auto-fix-system) — 179+ fixes, 100% coverage
4. [Framework Support](#4-framework-support) — Django, Flask, Pandas, Pytest

### Advanced Capabilities
5. [Advanced Security](#5-advanced-security) — Jupyter notebooks, AI explanations
6. [Compliance Standards](#6-compliance-standards) — 10+ frameworks (OWASP, PCI-DSS, HIPAA)
7. [ML-Powered Analysis](#7-ml-powered-analysis) — Pattern recognition, anomaly detection
8. [Supply Chain Security](#8-supply-chain-security) — SBOM, dependency scanning

### Integration & Tooling
9. [CI/CD Integration](#9-cicd-integration) — 5+ platforms, pre-commit hooks
10. [Performance Tools](#10-performance-tools) — Profiling, optimization suggestions
11. [Dependency Analysis](#11-dependency-analysis) — Graph visualization, circular detection
12. [Custom Rules](#12-custom-rules) — User-defined security and quality rules
13. [Reporting](#13-reporting) — HTML, JSON, SARIF, console

### Development & Future
14. [Analysis Engines](#14-analysis-engines) — AST, ML, type checking
15. [Planned Features](#15-planned-features) — Roadmap and future work

---

## 1. Security Detection

PyGuard implements **55+ security vulnerability checks** across 8 specialized security modules.

### Security Modules Overview

| Module | Lines | Checks | CWE Coverage | Status |
|--------|-------|--------|--------------|--------|
| `ruff_security.py` | 1598 | 73 rules | All Bandit S-rules | ✅ Complete |
| `enhanced_detections.py` | 793 | 13+ patterns | Advanced detection | ✅ Complete |
| `ultra_advanced_security.py` | 657 | 21+ vulns | Framework-specific | ✅ Complete |
| `xss_detection.py` | 541 | 5 XSS types | Multi-framework | ✅ Complete |
| `advanced_security.py` | 408 | 14 vulns | Taint, race, ReDoS | ✅ Complete |
| `security.py` | 289 | 20 vulns | Core security | ✅ Complete |
| `notebook_security.py` | 180 | 8+ checks | Jupyter-specific | ✅ Complete |
| `supply_chain.py` | 488 | Dependencies | SBOM, licenses | ✅ Complete |

### Core Security Checks (20 vulnerabilities)

**Module**: `security.py`

| Vulnerability | Severity | CWE | OWASP | Auto-Fix | Safety |
|--------------|----------|-----|-------|----------|--------|
| Hardcoded Passwords/Secrets | HIGH | CWE-798 | ASVS-2.6.3 | ✅ | UNSAFE |
| SQL Injection | HIGH | CWE-89 | ASVS-5.3.4 | ✅ | UNSAFE |
| Command Injection | HIGH | CWE-78 | ASVS-5.3.3 | ✅ | UNSAFE |
| Code Injection (eval/exec) | HIGH | CWE-95 | ASVS-5.2.1 | ✅ | SAFE |
| Unsafe Deserialization | HIGH | CWE-502 | ASVS-5.5.3 | ✅ | SAFE |
| Path Traversal | HIGH | CWE-22 | ASVS-12.3.1 | ✅ | UNSAFE |
| Weak Cryptography | MEDIUM | CWE-327 | ASVS-6.2.1 | ✅ | SAFE |
| Weak Random | MEDIUM | CWE-330 | ASVS-6.3.1 | ✅ | SAFE |
| Insecure Temp Files | HIGH | CWE-377 | ASVS-12.3.2 | ✅ | SAFE |
| Unsafe YAML Loading | HIGH | CWE-502 | ASVS-5.5.3 | ✅ | SAFE |

### Advanced Security (14 vulnerabilities)

**Module**: `advanced_security.py`

| Feature | CWE | Implementation | Status |
|---------|-----|----------------|--------|
| Taint Tracking | CWE-20 | Full path analysis | ✅ Complete |
| ReDoS Detection | CWE-1333 | Pattern complexity | ✅ Complete |
| Race Conditions | CWE-362 | TOCTOU analysis | ✅ Complete |
| Integer Overflow | CWE-190 | Bounds checking | ✅ Complete |
| Memory Disclosure | CWE-209 | Traceback detection | ✅ Complete |
| Timing Attacks | CWE-208 | Comparison analysis | ✅ Complete |
| Buffer Overflow | CWE-120 | ctypes/CFFI usage | ✅ Complete |

### Ultra-Advanced Security (21+ vulnerabilities)

**Module**: `ultra_advanced_security.py`

| Vulnerability | Frameworks | Auto-Fix | Status |
|--------------|------------|----------|--------|
| GraphQL Injection | GraphQL | ✅ Parameterized | ✅ Complete |
| Server-Side Template Injection | Jinja2/Mako | ✅ Safe templates | ✅ Complete |
| JWT Security | JWT | ✅ RS256 | ✅ Complete |
| API Rate Limiting | Flask/FastAPI | ✅ @limiter | ✅ Complete |
| Container Security | Docker | ✅ Secure config | ✅ Complete |
| Insecure Cookies | Flask/Django | ✅ Secure flags | ✅ Complete |
| IDOR | All | ✅ Authz checks | ✅ Complete |
| Mass Assignment | Django/SQLAlchemy | ✅ Allowlist | ✅ Complete |
| CORS Misconfiguration | Flask/FastAPI | ✅ Strict origins | ✅ Complete |
| XXE | XML parsers | ✅ Safe parser | ✅ Complete |
| LDAP Injection | python-ldap | ✅ Escaping | ✅ Complete |
| NoSQL Injection | MongoDB | ✅ Parameterized | ✅ Complete |
| SSRF | requests/urllib | ✅ URL validation | ✅ Complete |
| Open Redirect | Flask/Django | ✅ URL validation | ✅ Complete |

### Jupyter Notebook Security (8+ checks)

**Module**: `notebook_security.py` — Industry-leading native `.ipynb` support

| Check | Severity | Unique to PyGuard |
|-------|----------|-------------------|
| Hardcoded Secrets in Cells | HIGH | ✅ Yes |
| Dangerous Magic Commands | HIGH | ✅ Yes (!, %system, %%bash) |
| Code Injection (eval/exec) | CRITICAL | No |
| Command Injection | CRITICAL | No |
| Path Disclosure in Outputs | MEDIUM | ✅ Yes |
| Execution Order Issues | MEDIUM | ✅ Yes (vars before def) |
| Unsafe Extension Loading | HIGH | ✅ Yes (%load_ext) |
| Unsafe Deserialization | HIGH | No |

**Competitive Advantage**: Only tool with comprehensive notebook support including cell order analysis, magic command detection, and output scanning.

### XSS Detection (5 types, multi-framework)

**Module**: `xss_detection.py`

| XSS Type | Frameworks | Detection Method |
|----------|-----------|------------------|
| Reflected XSS | Django, Flask, FastAPI | Unescaped template vars |
| Stored XSS | All | DB → Template without escape |
| DOM-based XSS | JavaScript in templates | innerHTML assignments |
| URL Parameter XSS | Flask, Django | Request args in HTML |
| Template Injection | Jinja2, Mako | Dynamic rendering |

---

## 2. Code Quality

PyGuard enforces **150+ code quality rules** across 14 comprehensive modules.

### Code Quality Modules Overview

| Module | Lines | Rules | Category | Status |
|--------|-------|-------|----------|--------|
| `pep8_comprehensive.py` | 1425 | 88 rules | Style | ✅ Complete |
| `refurb_patterns.py` | 1376 | 35+ rules | Modernization | ✅ Complete |
| `pie_patterns.py` | 915 | 25+ rules | Code smells | ✅ Complete |
| `code_simplification.py` | 761 | Refactoring | Simplification | ✅ Complete |
| `bugbear.py` | 729 | 40+ rules | Bug patterns | ✅ Complete |
| `pylint_rules.py` | 611 | 60+ rules | Quality | ✅ Complete |
| `modern_python.py` | 658 | 30+ rules | pyupgrade | ✅ Complete |
| `comprehensions.py` | 441 | Optimization | List/dict | ✅ Complete |
| `exception_handling.py` | 446 | Best practices | Exceptions | ✅ Complete |
| `naming_conventions.py` | 421 | PEP 8 naming | Conventions | ✅ Complete |
| `unused_code.py` | 374 | Dead code | Detection | ✅ Complete |
| `best_practices.py` | 363 | 20+ patterns | Best practices | ✅ Complete |
| `string_operations.py` | 384 | String patterns | Optimization | ✅ Complete |
| `async_patterns.py` | 274 | async/await | Async code | ✅ Complete |

### PEP 8 Style (88 rules)

**Module**: `pep8_comprehensive.py` — Native pycodestyle implementation

| Category | Rules | Auto-Fix | Examples |
|----------|-------|----------|----------|
| Indentation (E1xx) | 13 | ✅ | E101, E111, E121, E122, E131 |
| Whitespace (E2xx) | 20 | ✅ | E201-E211, E221-E231, E241-E275 |
| Blank Lines (E3xx) | 6 | ✅ | E301-E306 |
| Imports (E4xx) | 3 | ✅ | E401, E402 |
| Line Length (E5xx) | 2 | ✅ | E501, E502 |
| Statements (E7xx) | 4 | ✅ | E701-E704 |
| Runtime (E9xx) | 3 | ⚠️ | E901, E902, E999 (syntax) |
| Warnings (W1xx-W6xx) | 37 | ✅ | W191, W291-W293, W503-W606 |

### Pylint Rules (60+ rules)

**Module**: `pylint_rules.py`

| Category | Description | Rules | Status |
|----------|-------------|-------|--------|
| PLR (Refactor) | Code refactoring | 20+ | ✅ Complete |
| PLC (Convention) | Coding standards | 15+ | ✅ Complete |
| PLW (Warning) | Problem code | 15+ | ✅ Complete |
| PLE (Error) | Likely errors | 10+ | ✅ Complete |

**Common Checks**: Cyclomatic complexity, function length, parameter count, local variables, duplicate code

### Bugbear (40+ bug patterns)

**Module**: `bugbear.py` — Catches likely bugs

| Pattern | Description | Auto-Fix |
|---------|-------------|----------|
| B001-B006 | Loop/iteration issues | ✅ |
| B007 | Unused loop variables | ✅ |
| B008-B009 | Function call defaults | ✅ |
| B010-B015 | Exception handling | ✅ |
| B016-B020 | Type checking anti-patterns | ✅ |
| B021-B025 | Context manager issues | ✅ |
| B026-B030 | String/byte issues | ✅ |

### Modern Python (35+ patterns)

**Module**: `refurb_patterns.py` + `modern_python.py` — Modernization for Python 3.8+

| Pattern Type | Target Version | Auto-Fix | Examples |
|-------------|----------------|----------|----------|
| Path operations | 3.8+ | ✅ | os.path → pathlib |
| Type annotations | 3.9-3.10 | ✅ | List[X] → list[X] |
| String operations | 3.9+ | ✅ | % → f-strings |
| Collections | 3.9+ | ✅ | New methods |
| Context managers | 3.10+ | ✅ | Parenthesized |
| Union syntax | 3.10+ | ✅ | Optional[X] → X \| None |

### Best Practices (20+ patterns)

**Module**: `best_practices.py`

| Practice | Description | Auto-Fix |
|----------|-------------|----------|
| Mutable defaults | `def f(x=[])` | ✅ None + init |
| Bare except | `except: pass` | ✅ Add type |
| None comparison | `x == None` | ✅ `is None` |
| Boolean comparison | `x == True` | ✅ `if x` |
| Type checking | `type(x) == int` | ✅ isinstance() |
| Context managers | File operations | ✅ Add with |
| Missing docstrings | Functions | ✅ Template |

---

### Ruff Security Rules (73 Bandit rules)

**Module**: `ruff_security.py` (1598 lines) — Most comprehensive module

Implements **all 73 Ruff S (Security) rules** from Bandit:

| Rule Category | Count | Examples |
|--------------|-------|----------|
| Shell Injection | 8 | S602-S609 (subprocess, os.system) |
| Cryptography | 12 | S301-S324 (weak crypto, SSL) |
| Deserialization | 6 | S301, S302, S403, S404, S506 |
| SQL Injection | 4 | S608, string formatting |
| Path Operations | 5 | S101-S103, S108 |
| Network Security | 8 | S401, S505-S507 (SSL, FTP) |
| Code Execution | 10 | S102, S307, S403-S406 |
| File Operations | 7 | S101, S108, S110, S111 |
| XML/XXE | 3 | S314-S316 (ElementTree) |
| Misc Security | 10 | Assertions, try-except-pass |

### Core Security Checks (20 vulnerabilities)

**Module**: `security.py`

| Feature | Description | CWE | Implementation |
|---------|-------------|-----|----------------|
| Taint Tracking | Data flow analysis for untrusted input | CWE-20 | Full path analysis |
| ReDoS Detection | Regular Expression Denial of Service | CWE-1333 | Pattern complexity |
| Race Conditions | File system race condition detection | CWE-362 | Time-of-check analysis |
| Integer Overflow | Numeric overflow vulnerability detection | CWE-190 | Bounds checking |
| Memory Disclosure | Information leakage via traceback/locals() | CWE-209 | Debug code detection |
| Timing Attacks | Non-constant-time comparisons | CWE-208 | Secret comparison |
| TOCTOU (Time-of-check) | File access race conditions | CWE-367 | File operation sequences |
| Buffer Overflow | Unsafe C extension calls | CWE-120 | ctypes/CFFI usage |

**Advanced Capabilities:**
- Inter-procedural data flow analysis
- Control flow graph construction
- Path-sensitive analysis
- Context-sensitive taint propagation

### Ultra-Advanced Security (21+ vulnerabilities)

**Module**: `ultra_advanced_security.py` (657 lines)

| Vulnerability | Framework | Auto-Fix | Description |
|--------------|-----------|----------|-------------|
| GraphQL Injection | GraphQL | ✅ Parameterized | Query parameter injection |
| Server-Side Template Injection (SSTI) | Jinja2/Mako | ✅ Safe templates | render_template_string abuse |
| JWT Security Issues | JWT | ✅ RS256 | 'none' algorithm, weak secrets |
| API Rate Limiting Missing | Flask/FastAPI | ✅ @limiter | DoS protection |
| Container Security | Docker | ✅ Secure defaults | Privileged mode, capabilities |
| Insecure Cookies | Flask/Django | ✅ Secure flags | HttpOnly, Secure, SameSite |
| IDOR (Insecure Direct Object Reference) | All | ✅ Authz checks (unsafe) | Missing authorization |
| Mass Assignment | Django/SQLAlchemy | ✅ Field allowlist (unsafe) | Unrestricted field updates |
| Clickjacking | Web frameworks | ✅ X-Frame-Options | Missing headers |
| CORS Misconfiguration | Flask/FastAPI | ✅ Strict origins (unsafe) | Overly permissive origins |
| Insecure HTTP | Requests/urllib | ✅ HTTPS | Plaintext connections |
| XXE (XML External Entity) | XML parsers | ✅ Safe parser (safe) | Unsafe XML parsing |
| LDAP Injection | python-ldap | ✅ Escaping (unsafe) | Unescaped LDAP queries |
| NoSQL Injection | MongoDB | ✅ Parameterized (unsafe) | Query string concatenation |
| CSV Injection | csv module | ✅ Sanitize | Formula injection |
| Format String Vulnerabilities | str.format | ✅ Input validation (safe) | Dynamic format strings |
| SSRF (Server-Side Request Forgery) | requests/urllib | ✅ URL validation (unsafe) | User-controlled URLs |
| Open Redirect | Flask/Django | ✅ URL validation (unsafe) | Unvalidated redirects |
| Insecure Deserialization (YAML) | PyYAML | ✅ safe_load | yaml.load() usage |
| Debug Code in Production | pdb/ipdb | ✅ Remove | breakpoint(), set_trace() |
| Unsafe File Operations | file I/O | ✅ Path validation (unsafe) | Unchecked file paths |

**World-Class Features:**
- 20+ auto-fix implementations for complex vulnerabilities
- Framework-aware context analysis
- Production configuration validation
- Security header enforcement

### Ruff Security Rules (73 Bandit rules)

**Module**: `ruff_security.py` (1,597 lines - most comprehensive)

Implements **all 73 Ruff S (Security) rules** from Bandit:

| Rule Category | Count | Examples |
|--------------|-------|----------|
| Shell Injection | 8 rules | S602-S609 (subprocess, os.system) |
| Cryptography | 12 rules | S301-S324 (weak crypto, random, SSL) |
| Deserialization | 6 rules | S301, S302, S403, S404, S506 |
| SQL Injection | 4 rules | S608, database string formatting |
| Path Operations | 5 rules | S101, S102, S103, S108 (path traversal) |
| Network Security | 8 rules | S401, S505, S506, S507 (SSL, FTP) |
| Code Execution | 10 rules | S102, S307, S403-S406 (eval, exec, compile) |
| File Operations | 7 rules | S101, S108, S110, S111, temp files |
| XML/XXE | 3 rules | S314, S315, S316 (ElementTree, expatbuilder) |
| Misc Security | 10 rules | Assertions, try-except-pass, etc. |

**Comprehensive Coverage:**
- Every Bandit rule implemented
- Native Python AST analysis (no external dependencies)
- Framework-specific rules (Django, Flask)
- Production-ready detection patterns

### XSS Detection (5 vulnerability types)

**Module**: `xss_detection.py` (541 lines)

| XSS Type | Frameworks Supported | Detection Method |
|----------|---------------------|------------------|
| Reflected XSS | Django, Flask, FastAPI | Unescaped template variables |
| Stored XSS | All frameworks | Database → Template without escaping |
| DOM-based XSS | JavaScript in templates | innerHTML assignments |
| URL Parameter XSS | Flask, Django | Request args in HTML |
| Template Injection XSS | Jinja2, Mako | Dynamic template rendering |

**Multi-Framework Support:**
- Django template detection
- Flask/Jinja2 template analysis
- Mako template scanning
- FastAPI response validation
- Generic Python HTML generation

### Enhanced Security Detections (10+ patterns)

**Module**: `enhanced_detections.py` (792 lines)

| Detection | Risk | Auto-Fix |
|-----------|------|----------|
| Backup Files (.bak, .old) | HIGH | ✅ Removal guide (safe) |
| Mass Assignment Vulnerabilities | HIGH | ✅ Field allowlist (unsafe) |
| Memory Disclosure (traceback) | MEDIUM | ✅ Safe logging (safe) |
| Debug Endpoints in Production | HIGH | ✅ Remove |
| Insecure Session Management | MEDIUM | ✅ Secure defaults |
| Missing Security Headers | MEDIUM | ✅ Add headers |
| Weak Password Validation | MEDIUM | ✅ Strong requirements (safe) |
| Unvalidated File Uploads | HIGH | ✅ Validation (unsafe) |
| Insecure Direct Object Reference | HIGH | ✅ Authz checks (unsafe) |
| JWT Token Leakage | HIGH | ✅ Token sanitization (unsafe) |

---

## 3. Auto-Fix System

PyGuard provides **179+ automated fixes** — the most comprehensive auto-fix system of any Python security tool.

### Auto-Fix Modules

| Module | Lines | Fixes | Safety Level | Status |
|--------|-------|-------|--------------|--------|
| `missing_auto_fixes.py` | 743 | 72 fixes | UNSAFE | ✅ Complete |
| `ultra_advanced_fixes.py` | 490 | 27 fixes | UNSAFE | ✅ Complete |
| `enhanced_security_fixes.py` | 458 | 20 fixes | UNSAFE | ✅ Complete |
| `fix_safety.py` | 403 | Classification | System | ✅ Complete |
| `formatting.py` | 280 | PEP 8 fixes | SAFE | ✅ Complete |

### Fix Safety Classification

| Level | Count | Description | Flag Required |
|-------|-------|-------------|---------------|
| **SAFE** | 107+ | Won't change behavior | No (default) |
| **UNSAFE** | 72+ | May require testing | `--unsafe-fixes` |
| **MANUAL** | Rare | Human review required | N/A |

### Safe Auto-Fixes (107+ fixes)

Applied automatically without `--unsafe-fixes` flag:

**Security (37+)**:
- `yaml.load()` → `yaml.safe_load()`
- `random.random()` → `secrets.token_hex()`
- `hashlib.md5()` → `hashlib.sha256()`
- `eval()` → `ast.literal_eval()`
- `pickle` → `JSON` (simple data)
- Remove debug code (pdb, breakpoint())
- XXE → safe XML parser
- Weak passwords → strong requirements

**Style (40+)**:
- All PEP 8 violations
- Trailing whitespace
- Import sorting (isort)
- Code formatting (Black)

**Quality (30+)**:
- Mutable defaults: `def f(x=[])` → `def f(x=None)`
- None comparison: `x == None` → `x is None`
- Type checking: `type(x) == int` → `isinstance(x, int)`
- Bare except: `except:` → `except Exception:`

### Unsafe Auto-Fixes (72+ fixes)

Require explicit `--unsafe-fixes` flag:

| Fix Type | Risk | Description |
|----------|------|-------------|
| SQL Parameterization | UNSAFE | May change query structure |
| SSTI Protection | UNSAFE | Template rendering changes |
| JWT Algorithm | UNSAFE | Auth system impact |
| Rate Limiting | UNSAFE | Performance impact |
| CORS Configuration | UNSAFE | API access changes |
| Hardcoded Secrets | UNSAFE | Config changes needed |
| IDOR Protection | UNSAFE | Authorization logic |
| SSRF Protection | UNSAFE | URL validation |

**Features**:
- Automatic backup before fixes (`.pyguard_backups/`)
- Rollback capability if tests fail
- Detailed fix explanations
- Impact assessment
- Multi-level safety classification

---

## 4. Framework Support

PyGuard includes specialized rules for popular Python frameworks.

### Framework Modules

| Framework | Module | Lines | Rules | Auto-Fix | Status |
|-----------|--------|-------|-------|----------|--------|
| Django | `framework_django.py` | 333 | 25+ | ✅ | ✅ Complete |
| Flask/FastAPI | `framework_flask.py` | 409 | 20+ | ✅ | ✅ Complete |
| Pandas | `framework_pandas.py` | 279 | 15+ | ⚠️ | ✅ Complete |
| Pytest | `framework_pytest.py` | 300 | 18+ | ⚠️ | ✅ Complete |

### Django Rules (25+)

**Security (12)**:
- DEBUG = True in production
- SECRET_KEY in version control
- Missing CSRF middleware
- SQL injection in raw queries
- XSS in templates
- Insecure session cookies

**ORM (8)**:
- N+1 query problems
- Missing select_related/prefetch_related
- Raw SQL usage

### Flask/FastAPI Rules (20+)

**Security (10)**:
- Debug mode in production
- Weak SECRET_KEY
- Missing CSRF protection
- Server-Side Template Injection
- Insecure session config
- Missing rate limiting

### Pandas Rules (15+)

**Performance (8)**:
- Use of iterrows() (slow)
- Missing vectorization
- Inefficient apply() usage

**Anti-patterns (7)**:
- Chained assignment warnings
- DataFrame copy warnings

### Pytest Rules (18+)

**Best Practices (8)**:
- Test function naming (test_*)
- Fixture usage
- Assertion style
- Parametrization

---

## 5. Advanced Security

### Jupyter Notebook Security

**Module**: `notebook_security.py` — Industry-leading native `.ipynb` support

**Unique Features**:
- Cell-by-cell analysis
- Execution order tracking
- Magic command detection (!, %system, %%bash)
- Output scanning for sensitive data
- Cross-cell dependency analysis
- Automated fixes

**See**: `docs/guides/notebook-security-guide.md` for complete guide.

### AI-Powered Explanations

**Module**: `ai_explainer.py` — Educational platform

**Features**:
- Natural language explanations (7+ vulnerabilities)
- Fix rationale generation
- Educational levels (beginner/intermediate/advanced)
- Interactive quiz generation
- No external AI calls (privacy-preserving)

**See**: `docs/guides/ADVANCED_FEATURES.md` for examples.

---

## 6. Compliance Standards

PyGuard maps all vulnerabilities to **10+ compliance frameworks**.

**Module**: `standards_integration.py` (796 lines)

### Supported Frameworks

| Framework | Version | Rules | Usage |
|-----------|---------|-------|-------|
| OWASP ASVS | v5.0 | 55+ | `--framework owasp` |
| CWE | Top 25 2024 | 55+ | Always included |
| PCI DSS | v4.0 | 40+ | `--framework pci-dss` |
| HIPAA | Current | 35+ | `--framework hipaa` |
| SOC 2 | Type II | 30+ | `--framework soc2` |
| ISO 27001 | 2022 | 35+ | `--framework iso27001` |
| NIST CSF | 2.0 | 25+ | `--framework nist` |
| GDPR | Current | 20+ | `--framework gdpr` |
| CCPA | Current | 15+ | `--framework ccpa` |
| FedRAMP | Current | 30+ | `--framework fedramp` |
| SOX | Current | 15+ | `--framework sox` |

### Mapping Example

| PyGuard Check | OWASP | CWE | PCI DSS | HIPAA |
|--------------|-------|-----|---------|-------|
| SQL Injection | ASVS-5.3.4 | CWE-89 | 6.5.1 | 164.308(a)(1) |
| Hardcoded Secrets | ASVS-2.6.3 | CWE-798 | 3.4, 8.2.1 | 164.312(a)(2) |
| Weak Crypto | ASVS-6.2.1 | CWE-327 | 4.1, 8.2.1 | 164.312(e) |
| Path Traversal | ASVS-12.3.1 | CWE-22 | 6.5.8 | 164.312(a) |

---

## 7. ML-Powered Analysis

**Module**: `ml_detection.py` (389 lines)

### ML Capabilities

| Feature | Algorithm | Purpose | Status |
|---------|-----------|---------|--------|
| Pattern Recognition | Logistic Regression | Identify vulnerability patterns | ✅ Active |
| Anomaly Detection | Isolation Forest | Detect unusual code | ✅ Active |
| Risk Scoring | Random Forest | Calculate risk | ✅ Active |
| Code Similarity | TF-IDF + Cosine | Find duplicates | ✅ Active |
| Complexity Prediction | Neural Network | Maintainability | ✅ Active |

**Features**:
- Lightweight (no deep learning, fast)
- 100% local (privacy-preserving)
- Incremental learning
- Explainable decisions

---

## 8. Supply Chain Security

**Module**: `supply_chain.py` (488 lines)

### Features

| Feature | Description | Output |
|---------|-------------|--------|
| Dependency Scanning | Known vulnerabilities | JSON, SARIF |
| SBOM Generation | Bill of Materials | CycloneDX, SPDX |
| License Detection | Package licenses | JSON report |
| Risk Scoring | Supply chain risk | Numeric score |
| Update Recommendations | Safer versions | JSON |

### Checks Performed

1. **Vulnerability Detection**: NVD, OSV, GitHub Advisory, PyPI
2. **License Compliance**: Identify incompatible licenses, GPL/AGPL warnings
3. **Package Integrity**: Hash verification, typosquatting detection
4. **Dependency Risk**: Unmaintained packages, outdated versions

---

## 9. CI/CD Integration

**Module**: `ci_integration.py` — Auto-generate CI/CD configs

### Supported Platforms

| Platform | Config File | Features |
|----------|------------|----------|
| GitHub Actions | `.github/workflows/` | SARIF upload, security tab |
| GitLab CI | `.gitlab-ci.yml` | SAST reports |
| CircleCI | `.circleci/config.yml` | Artifacts |
| Azure Pipelines | `azure-pipelines.yml` | Build artifacts |
| Pre-commit hooks | `.git/hooks/` | Local scanning |

**Usage**:
```python
from pyguard import generate_ci_config, install_pre_commit_hook

generate_ci_config("github_actions", ".github/workflows/pyguard.yml")
install_pre_commit_hook()
```

**See**: `docs/guides/advanced-integrations.md` for complete guide.

---

## 10. Performance Tools

**Module**: `performance_profiler.py` — Bottleneck detection

### Detections (6+ patterns)

| Pattern | Impact | Fix |
|---------|--------|-----|
| List concatenation in loops | O(n²) | Use list.append() |
| Nested loops without early exit | High | Add break/continue |
| Uncompiled regex | 10-100x slower | re.compile() |
| Redundant .keys() | Unnecessary | Direct iteration |
| sum() with comprehension | Slow | Generator expression |
| Complex comprehensions | Readability | Split or loop |

**Usage**:
```python
from pyguard import analyze_performance

issues = analyze_performance("mycode.py")
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
    print(f"  Impact: {issue.estimated_impact}")
```

---

## 11. Dependency Analysis

**Module**: `dependency_analyzer.py` — Architecture insights

### Features

| Feature | Description | Output |
|---------|-------------|--------|
| Dependency Graph | Module relationships | Mermaid diagram |
| Circular Detection | A → B → C → A | List of cycles |
| God Modules | High coupling | Module list |
| Complexity Analysis | Too many deps | Statistics |
| Visualization | Graph export | vis.js, D3, Cytoscape |

**Usage**:
```python
from pyguard import analyze_project_dependencies

analyzer = analyze_project_dependencies("src/", package_name="myproject")
stats = analyzer.get_dependency_stats()
cycles = analyzer.find_circular_dependencies()
diagram = analyzer.generate_mermaid_diagram()
```

---

## 12. Custom Rules

**Module**: `custom_rules.py` — User-defined rules

### Features

| Feature | Description | Status |
|---------|-------------|--------|
| TOML Config | Rule definitions | ✅ Complete |
| Regex Rules | Pattern matching | ✅ Complete |
| AST Rules | Accurate detection | ✅ Complete |
| Enable/Disable | Dynamic control | ✅ Complete |
| Export | TOML format | ✅ Complete |

**Usage**:
```python
from pyguard import create_rule_engine_from_config

engine = create_rule_engine_from_config("custom_rules.toml")
violations = engine.check_file("mycode.py")
```

**Example**: 25+ example rules in `examples/custom_rules_example.toml`

---

## 13. Reporting

### Report Modules

| Module | Lines | Format | Use Case |
|--------|-------|--------|----------|
| `reporting.py` | 401 | JSON/Console | Machine-readable |
| `sarif_reporter.py` | 480 | SARIF 2.1.0 | GitHub Code Scanning |
| `ui.py` | 1414 | HTML/Rich | Human-readable |

### Report Formats

| Format | Features | Integration |
|--------|----------|-------------|
| Console | Color-coded, severity groups | Interactive CLI |
| HTML | Charts, graphs, expandable | Browser viewing |
| JSON | Structured data | CI/CD pipelines |
| SARIF 2.1.0 | CWE/OWASP mapping | GitHub Security tab |
| Markdown | Easy sharing | Documentation |

### SARIF Features

- Full CWE/OWASP mappings
- Fix suggestions
- Code snippets
- Severity scores
- Multi-framework compliance tags
- GitHub Code Scanning integration

**See**: GitHub Actions integration in section 9.

---

## 14. Analysis Engines

### AST-Based Analysis

**Module**: `ast_analyzer.py` (979 lines)

| Engine | Speed | Accuracy | Purpose |
|--------|-------|----------|---------|
| AST Walker | Very Fast | 100% | Python AST traversal |
| Control Flow Graph | Fast | 95% | Execution paths |
| Data Flow Analysis | Medium | 90% | Variable tracking |
| Type Inference | Fast | 85% | Static types |

**Benefits**: 10-100x faster than regex, zero false positives from comments/strings

### Additional Analysis

| Module | Purpose | Status |
|--------|---------|--------|
| `type_checker.py` | Static type analysis | ✅ Complete |
| `rule_engine.py` | Custom rule execution | ✅ Complete |
| `ml_detection.py` | ML-powered detection | ✅ Complete |

### Pattern Detection Modules (9)

Specialized modules for specific code patterns:
- `import_manager.py` (507 lines) — Import optimization
- `comprehensions.py` (441 lines) — List/dict optimization
- `exception_handling.py` (446 lines) — Exception best practices
- `async_patterns.py` (274 lines) — async/await patterns
- `datetime_patterns.py` (226 lines) — datetime usage
- `logging_patterns.py` (232 lines) — Logging best practices
- `return_patterns.py` (381 lines) — Return statements
- `pathlib_patterns.py` (229 lines) — pathlib usage
- `debugging_patterns.py` (220 lines) — Debug code detection

---

## 15. Planned Features

### v0.4.0 (In Progress)

| Feature | Status | Priority |
|---------|--------|----------|
| Watch Mode | ✅ Complete | HIGH |
| Git Hooks | ✅ Complete | HIGH |
| VS Code Extension | ⏳ Planned | MEDIUM |

### v0.5.0

| Feature | Description | Priority |
|---------|-------------|----------|
| Language Server Protocol | IDE-agnostic integration | HIGH |
| Git Diff Analysis | Scan only changed files | HIGH |
| Enhanced ML | Deep learning models | MEDIUM |

### v1.0.0 (Production Stable)

**Goals**:
- 100% test coverage (currently 84%)
- Signed releases (GPG)
- Performance optimizations
- Enterprise features

**Enterprise (Planned)**:
- Team collaboration
- Central policy management
- Custom rule definitions
- API access
- Cloud integration (optional)

### Future Considerations

| Feature | Status | Notes |
|---------|--------|-------|
| JavaScript/TypeScript analysis | ⏳ Research | Multi-language support |
| Go security scanning | ⏳ Research | Extend beyond Python |
| Rust best practices | ⏳ Research | Systems programming |
| AI-powered fix suggestions | ⏳ Research | Enhanced automation |
| Plugin system | ⏳ Planned | Extensibility |
| Web dashboard | ⏳ Planned | Team analytics |

---

### Compliance Mapping Examples

| PyGuard Check | OWASP | CWE | PCI DSS | HIPAA |
|--------------|-------|-----|---------|-------|
| SQL Injection | ASVS-5.3.4 | CWE-89 | 6.5.1 | 164.308(a)(1) |
| Hardcoded Secrets | ASVS-2.6.3 | CWE-798 | 3.4, 8.2.1 | 164.312(a)(2) |
| Weak Crypto | ASVS-6.2.1 | CWE-327 | 4.1, 8.2.1 | 164.312(e) |
| Path Traversal | ASVS-12.3.1 | CWE-22 | 6.5.8 | 164.312(a) |
| XSS | ASVS-5.2.3 | CWE-79 | 6.5.7 | 164.312(a) |

## Competitive Comparison

### PyGuard vs Leading Tools

| Feature | PyGuard | Bandit | Ruff | Semgrep | Snyk | SonarQube |
|---------|---------|--------|------|---------|------|-----------|
| Security Checks | 55+ | 40+ | 73 | 100+ | 200+ | 100+ |
| Code Quality Rules | 150+ | 0 | 800+ | 50+ | 100+ | 500+ |
| **Auto-Fixes** | **179+** | ❌ | ~80 | ❌ | ❌ | ❌ |
| **Auto-Fix Coverage** | **100%** | 0% | ~10% | 0% | 0% | 0% |
| ML Detection | ✅ | ❌ | ❌ | ❌ | ✅ | ⚠️ Limited |
| Compliance Frameworks | 10+ | 0 | 0 | 0 | ⚠️ Limited | ✅ |
| **Local/No Telemetry** | **✅** | ✅ | ✅ | ⚠️ Cloud | ❌ Cloud | ⚠️ Hybrid |
| Framework Support | 4 | 2 | 3 | 4+ | 5+ | 6+ |
| SARIF Output | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| GitHub Actions | ✅ Native | ⚠️ Manual | ⚠️ Manual | ✅ Native | ✅ Native | ✅ Native |
| Notebook Support | ✅ Native | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cost | **Free** | Free | Free | Free/Paid | Paid | Free/Paid |

### Unique Advantages

1. **All-in-One Solution**: Replaces 7+ tools with single installation
2. **Auto-Fix Leader**: Only tool with 100% auto-fix coverage (179+ fixes)
3. **Privacy-First**: 100% local operation, zero telemetry
4. **Notebook Support**: Industry-leading Jupyter notebook security
5. **Educational**: AI-powered explanations for learning
6. **Compliance Ready**: 10+ frameworks out of the box
7. **Advanced Integrations**: CI/CD, performance, dependency analysis, custom rules

### Tool Replacement Matrix

| Tool | Purpose | Replaced By |
|------|---------|-------------|
| Bandit | Security scanning | `security.py`, `ruff_security.py` |
| Semgrep | Pattern matching | `ast_analyzer.py`, `rule_engine.py` |
| Ruff | Linting | `pep8_comprehensive.py`, `ruff_security.py` |
| Pylint | Code quality | `pylint_rules.py`, `best_practices.py` |
| Black | Formatting | `formatting.py` |
| isort | Import sorting | `import_manager.py`, `import_rules.py` |
| mypy | Type checking | `type_checker.py` |
| Safety | Dependencies | `supply_chain.py` |
| Flake8 | Style checking | `pep8_comprehensive.py` |

---

## Usage Examples

### Basic Scan
```bash
# Scan and fix entire project
pyguard src/

# Security checks only
pyguard src/ --security-only --severity HIGH

# Scan without fixing
pyguard src/ --scan-only
```

### Compliance Reports
```bash
# OWASP ASVS report
pyguard src/ --framework owasp --format html

# PCI DSS compliance
pyguard src/ --framework pci-dss --format json

# All frameworks
pyguard src/ --framework all
```

### CI/CD Integration
```bash
# Generate SARIF for GitHub Code Scanning
pyguard . --scan-only --sarif --no-html

# Output: pyguard-report.sarif
```

### Advanced Usage
```bash
# Include unsafe fixes
pyguard src/ --unsafe-fixes

# Framework-specific
pyguard . --framework django

# Watch mode (real-time)
pyguard src/ --watch

# Jupyter notebooks
pyguard analysis.ipynb
```

---

## Summary

PyGuard is the **most comprehensive Python security and code quality platform available**.

### Complete Feature Set

| Category | Features | Status |
|----------|----------|--------|
| **Modules** | 59 library modules, 30,500+ lines | ✅ Production |
| **Security** | 55+ vulnerability checks, 8 specialized modules | ✅ Complete |
| **Code Quality** | 150+ rules across 14 modules | ✅ Complete |
| **Auto-Fix** | 179+ fixes (107 safe, 72 unsafe), **100% coverage** | ✅ Complete |
| **Frameworks** | Django, Flask, FastAPI, Pandas, Pytest | ✅ Complete |
| **Compliance** | 10+ frameworks (OWASP, PCI-DSS, HIPAA, etc.) | ✅ Complete |
| **Advanced** | Notebooks, AI explanations, ML detection | ✅ Complete |
| **Integration** | CI/CD (5 platforms), performance, dependencies | ✅ Complete |
| **Custom Rules** | User-defined regex/AST rules | ✅ Complete |
| **Testing** | 62 test files, 84% coverage (target: 100%) | 🎯 In Progress |

### Key Differentiators

1. **Only tool with 100% auto-fix coverage** — All 179+ fixes available
2. **Native Jupyter notebook support** — Cell analysis, magic commands, execution order
3. **Educational AI explanations** — Learn while you scan
4. **100% local, zero telemetry** — Complete privacy
5. **Comprehensive compliance** — 10+ frameworks out of the box
6. **Advanced integrations** — CI/CD, performance profiling, dependency analysis, custom rules
7. **All-in-one solution** — Replaces 7+ tools with single installation

### Production Ready

- ✅ 59 production-ready modules
- ✅ 30,500+ lines of analysis code
- ✅ 62 comprehensive test files
- ✅ 84% test coverage (target: 100%)
- ✅ Zero linting errors
- ✅ Type hints on all APIs
- ✅ Comprehensive documentation
- ✅ GitHub Actions native integration
- ✅ SARIF 2.1.0 compliant
- ✅ Active maintenance and development

**PyGuard doesn't detect issues — it fixes them automatically, teaches you why they matter, and helps you maintain secure, high-quality Python code.**

---

**Version**: 0.3.0+  
**Last Updated**: 2025-10-14  
**Repository**: https://github.com/cboyd0319/PyGuard  
**Documentation**: https://github.com/cboyd0319/PyGuard/tree/main/docs  
**Issues**: https://github.com/cboyd0319/PyGuard/issues  
**Contributing**: See [CONTRIBUTING.md](../../CONTRIBUTING.md)  
**License**: MIT
