# Contributing to PyGuard

## Code of Conduct

Be respectful, inclusive, collaborative, and professional. Report unacceptable behavior to maintainers or via [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## How to Contribute

**Reporting bugs**
1. Check [existing issues](https://github.com/cboyd0319/PyGuard/issues) first.
2. Include: title, steps to reproduce, expected vs actual, PyGuard version, Python version, OS, code sample.

Example:
```
Title: SecurityFixer crashes on f-strings with nested calls

Steps:
1. Create: query = f"SELECT * FROM {get_table()}.{get_column()}"
2. Run: pyguard test.py --security-only
3. Error: sre_constants.error: bad character range

Expected: Detect SQL injection
Actual: Crash

Environment: PyGuard 0.3.0, Python 3.11.5, macOS 14.1
```

**Suggesting features**
- Clear title, detailed description, why it's useful, code examples if applicable.

**Contributing code**
1. Find or create an issue.
2. Comment to claim it.
3. Fork and create feature branch.
4. Implement, add tests, update docs.
5. Submit PR.

## Development Setup

**Prerequisites**: Python 3.8+ (3.13 recommended), Git, pip

**Setup**:
```bash
git clone https://github.com/YOUR_USERNAME/PyGuard.git
cd PyGuard
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"
pyguard --version
pytest
```

**Tools** (auto-installed with `[dev]`): pytest, pytest-cov, black, isort, pylint, mypy, flake8

## Development Workflow

**Branch naming**:
- `feature/` — New features (e.g., `feature/ast-based-fixer`)
- `bugfix/` — Bug fixes (e.g., `bugfix/regex-escape`)
- `docs/` — Documentation (e.g., `docs/api-ref`)
- `refactor/` — Code refactoring
- `test/` — Test improvements

**Development cycle**:
```bash
git checkout -b feature/my-feature
# ... edit files ...
make test
make format
make lint
git add .
git commit -m "feat: add type hint fixer"
git push origin feature/my-feature
# Open PR on GitHub
```

**Make targets**:
- `make dev` — Install dev dependencies
- `make test` — Run tests with coverage
- `make lint` — Run all linters (ruff, pylint, mypy, flake8)
- `make format` or `make fmt` — Format with Black and isort
- `make type` — Type check with mypy
- `make clean` — Remove build artifacts

## Coding Standards

**Style**: PEP 8 with modifications
- Line length: 100 (not 88)
- Quotes: double quotes
- Format: `black pyguard/ --line-length=100`
- Imports: `isort pyguard/ --profile=black`

**Type hints** (required for new code):
```python
# Good
def fix_file(self, file_path: Path) -> tuple[bool, list[str]]:
    fixes: list[str] = []
    return True, fixes

# Bad
def fix_file(self, file_path):
    return True, []
```

**Docstrings** (Google style, required for public APIs):
```python
def apply_fix(code: str, pattern: str, replacement: str) -> tuple[str, bool]:
    """Apply a regex-based fix to code.

    Args:
        code: Source code to fix.
        pattern: Regex pattern to match.
        replacement: Replacement string.

    Returns:
        Tuple of (fixed_code, was_modified).
    """
```

**Naming**:
- Classes: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_prefix`

**Error handling** (be specific):
```python
# Good
try:
    content = file_path.read_text(encoding="utf-8")
except FileNotFoundError:
    logger.error(f"File not found: {file_path}")
    raise
except UnicodeDecodeError as e:
    logger.error(f"Cannot decode {file_path}: {e}")
    return False, []

# Bad
try:
    content = file_path.read_text()
except:
    return False, []
```

## Testing

**Test structure**:
```
tests/
├── unit/              # Unit tests
├── integration/       # Integration tests
└── fixtures/          # Test data
```

**Writing tests** (pytest with descriptive names):
```python
from pyguard import SecurityFixer

def test_fix_hardcoded_password_in_assignment():
    """Detect and warn about hardcoded password."""
    code = 'password = "secret123"'
    fixer = SecurityFixer()
    fixed_code, modified = fixer._fix_hardcoded_passwords(code)
    
    assert modified
    assert "SECURITY:" in fixed_code
```

**Coverage** (aim for >70%):
```bash
pytest --cov=pyguard --cov-report=html --cov-report=term
open htmlcov/index.html
```

## Commit Format

Use Conventional Commits:

```
<type>(<scope>): <subject>
```

**Types**: feat, fix, docs, style, refactor, perf, test, build, ci, chore

**Examples**:
```bash
feat(security): add path traversal detection
fix(cli): handle empty file paths
docs: update installation instructions
feat(api)!: change SecurityFixer.fix_file signature

BREAKING CHANGE: returns tuple instead of dict
```

**Rules**:
- Imperative mood ("add" not "added")
- First line ≤ 50 chars
- Body wraps at 72 chars
- Explain what and why, not how
- Reference issues: `Fixes #123`

## Pull Request Process

**Before submitting**:
- [ ] Tests pass (`make test`)
- [ ] Code formatted (`make format`)
- [ ] Linting passes (`make lint`)
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] Branch up-to-date with `main`

**PR template**:
```markdown
## Description
Brief description of changes

## Type
- [ ] Bug fix / [ ] Feature / [ ] Breaking / [ ] Docs

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated

## Checklist
- [ ] Self-review completed
- [ ] Tests pass locally

Fixes #123
```

**Review process**:
1. Automated checks run (GitHub Actions)
2. Maintainer review (3-5 business days)
3. Address feedback and push updates
4. Merge when approved

After merge: added to CONTRIBUTORS.md, included in next release.

## Release Management

**Versioning**: Semantic Versioning (SemVer)
- Major (X.0.0): Breaking changes
- Minor (0.X.0): New features, backwards compatible
- Patch (0.0.X): Bug fixes

**Version files** (must be consistent):
- `pyguard/__init__.py` — `__version__`
- `pyproject.toml` — `version`
- `Dockerfile` — `LABEL version`
- `README.md` — Version badge

**Creating a release** (maintainers only):
```bash
./scripts/release.sh
```

Script handles: version updates, CHANGELOG, tests, git commit/tag, instructions for PyPI publish.

**Git tagging**:
```bash
git tag -a v0.3.0 -m "Release version 0.3.0"
git push origin v0.3.0
```

Tags from `main` branch trigger automated release workflow. Do not modify or delete pushed tags.

## Project Structure

```
PyGuard/
├── pyguard/          # Main package
│   ├── cli.py       # CLI
│   └── lib/         # Core: security, best_practices, formatting, core utils
├── tests/           # Unit and integration tests
├── config/          # security_rules.toml, qa_settings.toml
├── docs/            # Documentation
└── benchmarks/      # Performance tests
```

## Performance Tips

**Prefer AST over regex** (10-100x faster):
```python
# Good
import ast
class Visitor(ast.NodeVisitor):
    def visit_Call(self, node):
        ...

# Avoid (except for simple patterns)
pattern = r"yaml\.load\("
```

**Cache expensive operations**:
```python
from functools import lru_cache

@lru_cache(maxsize=128)
def parse_file(path: Path) -> ast.Module:
    return ast.parse(path.read_text())
```

**Lazy load heavy imports**:
```python
def format_with_black(code: str) -> str:
    import black  # Import only when needed
    return black.format_str(code, mode=black.Mode())
```

**Profile changes**:
```bash
python -m cProfile -o profile.stats -m pyguard src/
python -m pstats profile.stats
```

## Areas Needing Help

Priority areas for contributions:
- Performance (AST-based fixers)
- Testing (>70% coverage target)
- Documentation (user guides, tutorials)
- Security rules (new patterns)
- Integrations (VS Code, pre-commit hooks)

## Getting Help

- [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- Issues tagged `question`
- Email: your.email@example.com

## License

By contributing, you agree contributions will be licensed under MIT License.

---

Thanks for contributing to PyGuard!
