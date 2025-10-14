# PyGuard Documentation

**TL;DR**: Python security & code quality analysis tool. Replaces Ruff, Bandit, Semgrep, Pylint, Black, isort, mypy.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Basic usage
pyguard myfile.py          # Scan and fix
pyguard src/               # Scan directory
pyguard src/ --scan-only   # Scan without fixing
```

## Core Features

### Security Analysis
- **55+ vulnerability types**: SQL injection, command injection, path traversal, hardcoded secrets, weak crypto
- **CWE/OWASP mappings**: Full compliance with OWASP ASVS, CWE Top 25
- **Auto-fix capabilities**: Safe fixes applied automatically, unsafe fixes with `--unsafe-fixes` flag
- **Severity levels**: CRITICAL, HIGH, MEDIUM, LOW

### Code Quality
- **PEP 8 compliance**: Style guide enforcement with Black/isort integration
- **Best practices**: Mutable defaults, None comparisons, type checking patterns
- **Complexity analysis**: Cyclomatic and cognitive complexity metrics
- **Documentation checks**: Missing docstrings, type hints

### AST-Based Analysis
- **10-100x faster** than regex-based tools
- **Context-aware**: Understands Python syntax and semantics
- **Zero false positives**: No matches in comments/strings
- **Deep analysis**: Control flow, data flow, complexity

## Configuration

Create `pyguard.toml` or `~/.config/pyguard/config.toml`:

```toml
[security]
enabled = true
severity_threshold = "MEDIUM"

[formatting]
line_length = 100
use_black = true
use_isort = true

[best_practices]
enabled = true
max_complexity = 10
```

## CLI Options

```bash
pyguard [OPTIONS] PATH

Options:
  --scan-only           Scan without fixing
  --security-only       Security fixes only
  --unsafe-fixes        Enable unsafe auto-fixes (requires explicit consent)
  --no-backup          Skip backup creation
  --severity LEVEL     Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)
  --format FORMAT      Output format (console/json/html)
  --output FILE        Output file path
```

## Python API

```python
from pyguard import SecurityFixer, BestPracticesFixer, ASTAnalyzer

# Security analysis
security = SecurityFixer()
issues = security.scan_file_for_issues("myfile.py")
fixes = security.fix_file("myfile.py", unsafe_fixes=False)

# Code quality
quality = BestPracticesFixer()
improvements = quality.fix_file("myfile.py")

# AST analysis
analyzer = ASTAnalyzer()
metrics = analyzer.analyze("myfile.py")
```

## Architecture

PyGuard uses a modular architecture:

1. **CLI Layer** (`pyguard/cli.py`) - Command-line interface
2. **Analysis Layer** (`pyguard/lib/`) - Core detection and fixing modules
   - `security.py` - Security vulnerability detection
   - `best_practices.py` - Code quality improvements
   - `ast_analyzer.py` - AST-based static analysis
   - `formatting.py` - Code formatting (Black/isort)
3. **Integration Layer** - MCP, standards, supply chain
4. **Reporting Layer** - Console, JSON, HTML, SARIF output

## Security Rules

PyGuard detects 55+ vulnerability types mapped to CWE/OWASP standards:

| Category | Examples | Severity | CWE | OWASP |
|----------|----------|----------|-----|-------|
| Code Injection | `eval()`, `exec()`, `compile()` | CRITICAL | CWE-95 | ASVS-5.2.1 |
| Command Injection | `subprocess` with `shell=True` | CRITICAL | CWE-78 | ASVS-5.3.3 |
| SQL Injection | String concatenation in queries | CRITICAL | CWE-89 | ASVS-5.3.4 |
| Hardcoded Secrets | Passwords, API keys in code | HIGH | CWE-798 | ASVS-2.6.3 |
| Weak Crypto | MD5, SHA1, DES | HIGH | CWE-327 | ASVS-6.2.1 |
| Path Traversal | Unvalidated file paths | HIGH | CWE-22 | ASVS-12.3.1 |
| Unsafe Deserialization | `pickle.load()`, `yaml.load()` | HIGH | CWE-502 | ASVS-5.5.3 |

For complete list, see [security-rules.md](security-rules.md).

## Compliance Frameworks

PyGuard supports 10+ compliance frameworks:

- OWASP ASVS v5.0
- OWASP Top 10
- CWE Top 25
- PCI DSS
- HIPAA
- SOC 2
- ISO 27001
- NIST CSF
- GDPR
- CCPA

Generate compliance reports:
```bash
pyguard src/ --framework owasp --format json --output owasp-report.json
```

## Troubleshooting

### Common Issues

**Problem:** `ModuleNotFoundError: No module named 'pyguard'`
**Solution:** Install in development mode: `pip install -e ".[dev]"`

**Problem:** Tests failing
**Solution:** Reinstall dependencies: `pip install -e ".[dev]" --force-reinstall`

**Problem:** MyPy type errors
**Solution:** Run `python -m mypy pyguard/ --ignore-missing-imports`

**Problem:** Coverage decreased
**Solution:** Add tests for new features: `python -m pytest tests/ --cov=pyguard --cov-report=html`

## Performance

- **Speed**: 1000+ lines/second on typical hardware
- **Memory**: Efficient AST caching and parallel processing
- **Scalability**: Handles large codebases with directory scanning

## Development

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Development setup
- Testing guidelines (991 tests, 82% coverage)
- Code standards (PEP 8, type hints)
- Pull request process

Current metrics:
- Tests: 991 passing, 2 skipped
- Coverage: 82%
- Ruff: 0 errors
- MyPy: 0 errors
- Pylint: 8.82/10

## Roadmap

See [UPDATEv2.md](UPDATEv2.md) for detailed development status and roadmap.

Current priorities:
- Phase 2B: Auto-fix expansion (90% complete)
- Phase 3: Advanced detection features
- Phase 4: Ruff complete parity

## Support

- **Issues**: [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Security**: See [SECURITY.md](../SECURITY.md)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Community**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)

## License

MIT License - see [LICENSE](../LICENSE)
