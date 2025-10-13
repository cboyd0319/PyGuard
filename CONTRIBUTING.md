# Contributing to PyGuard

Thank you for considering contributing to PyGuard! We want to make contributing to this project as easy and transparent as possible.

## 📋 **Table of Contents**

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Project Structure](#project-structure)
- [Performance Considerations](#performance-considerations)

---

## 📜 **Code of Conduct**

This project adheres to a code of conduct that all contributors are expected to follow:

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome diverse perspectives and experiences
- **Be collaborative**: Work together to improve the project
- **Be professional**: Focus on constructive feedback

Report any unacceptable behavior to the project maintainers.

---

## 🤝 **How Can I Contribute?**

### **Reporting Bugs**

Before creating bug reports, please check the [existing issues](https://github.com/cboyd0319/PyGuard/issues) to avoid duplicates.

**Good Bug Reports Include:**
- Clear, descriptive title
- Exact steps to reproduce the issue
- Expected behavior vs. actual behavior
- PyGuard version (`pyguard --version`)
- Python version (`python --version`)
- Operating system
- Relevant code samples or logs

**Example Bug Report:**

```markdown
**Title**: SecurityFixer fails on f-strings with complex expressions

**Description**:
When running `pyguard` on files with f-strings containing complex expressions,
the security fixer crashes with a regex error.

**Steps to Reproduce**:
1. Create file with: `query = f"SELECT * FROM {get_table()}.{get_column()}"`
2. Run: `pyguard test.py --security-only`
3. See error

**Expected**: Should detect SQL injection vulnerability
**Actual**: Crashes with "sre_constants.error: bad character range"

**Environment**:
- PyGuard: 0.1.0
- Python: 3.11.5
- OS: macOS 14.1
```

### **Suggesting Enhancements**

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear, descriptive title
- Provide detailed description of the proposed functionality
- Explain why this enhancement would be useful
- Include code examples if applicable

### **Contributing Code**

1. **Find an issue** to work on or create a new one
2. **Comment on the issue** to let others know you're working on it
3. **Fork the repository** and create a feature branch
4. **Implement your changes** following our coding standards
5. **Add tests** for new functionality
6. **Update documentation** as needed
7. **Submit a pull request**

---

## 🛠️ **Development Setup**

### **Prerequisites**

- Python 3.8 or higher (3.13 recommended for development)
- Git
- pip or Poetry

### **Setup Instructions**

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/PyGuard.git
cd PyGuard

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install in development mode with all dependencies
pip install -e ".[dev]"

# 4. Verify installation
pyguard --version
pytest
```

### **Development Dependencies**

The project uses these tools (automatically installed with `[dev]`):

- **pytest** - Testing framework
- **pytest-cov** - Test coverage
- **black** - Code formatting
- **isort** - Import sorting
- **pylint** - Code linting
- **mypy** - Static type checking
- **flake8** - Style guide enforcement

---

## 🔄 **Development Workflow**

### **Branch Naming Convention**

Use descriptive branch names with these prefixes:

- `feature/` - New features (e.g., `feature/ast-based-fixer`)
- `bugfix/` - Bug fixes (e.g., `bugfix/regex-escape-issue`)
- `docs/` - Documentation only (e.g., `docs/api-reference`)
- `refactor/` - Code refactoring (e.g., `refactor/security-fixer`)
- `test/` - Test improvements (e.g., `test/add-integration-tests`)

**Example**:

```bash
git checkout -b feature/add-type-hint-fixer
```

### **Development Cycle**

```bash
# 1. Create and checkout branch
git checkout -b feature/my-feature

# 2. Make your changes
# ... edit files ...

# 3. Run tests
make test

# 4. Format code
make format  # or make fmt

# 5. Type check
make type

# 6. Lint code
make lint

# 7. Commit changes
git add .
git commit -m "feat: add type hint fixer"

# 8. Push to your fork
git push origin feature/my-feature

# 9. Open Pull Request on GitHub
```

**Quick reference for Make targets:**
- `make dev` - Install development dependencies
- `make test` - Run test suite with coverage
- `make lint` - Run all linters (ruff, pylint, mypy, flake8)
- `make format` or `make fmt` - Format code with Black and isort
- `make type` - Run type checking with mypy
- `make clean` - Remove build artifacts

---

## 📝 **Coding Standards**

### **Code Style**

We follow **PEP 8** with some modifications:

- **Line Length**: 100 characters (not 88)
- **Quotes**: Double quotes for strings
- **Formatting**: Use Black with `--line-length=100`
- **Import Sorting**: Use isort with profile "black"

**Automatic Formatting**:

```bash
# Format all code
black pyguard/ --line-length=100
isort pyguard/ --profile=black
```

### **Type Hints**

All new code must include type hints:

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
    success = True
    return success, fixes
```

### **Docstrings**

Use Google-style docstrings for all public functions, classes, and modules:

```python
def apply_fix(code: str, pattern: str, replacement: str) -> tuple[str, bool]:
    """Apply a regex-based fix to code.

    Args:
        code: The source code to fix.
        pattern: The regex pattern to match.
        replacement: The replacement string.

    Returns:
        A tuple of (fixed_code, was_modified).

    Example:
        >>> code = "x == None"
        >>> fixed, modified = apply_fix(code, r"== None", "is None")
        >>> print(fixed)
        x is None
    """
    # implementation
```

### **Naming Conventions**

- **Classes**: `PascalCase` (e.g., `SecurityFixer`)
- **Functions/Methods**: `snake_case` (e.g., `fix_file`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_LINE_LENGTH`)
- **Private**: Prefix with `_` (e.g., `_apply_fix`)
- **Type Variables**: `PascalCase` with `T` prefix (e.g., `TNode`)

### **Error Handling**

Always use specific exceptions and provide helpful error messages:

```python
# ✅ Good
try:
    content = file_path.read_text(encoding="utf-8")
except FileNotFoundError:
    logger.error(f"File not found: {file_path}")
    raise
except UnicodeDecodeError as e:
    logger.error(f"Cannot decode file {file_path}: {e}")
    return False, []

# ❌ Bad
try:
    content = file_path.read_text()
except:
    return False, []
```

---

## 🧪 **Testing Guidelines**

### **Test Structure**

```
tests/
├── test_security.py          # Security fixer tests
├── test_best_practices.py    # Best practices fixer tests
├── test_formatting.py        # Formatting tests
├── test_core.py              # Core utilities tests
├── test_cli.py               # CLI tests
└── fixtures/                 # Test data
    ├── sample_code.py
    └── expected_output.py
```

### **Writing Tests**

Use **pytest** with clear, descriptive test names:

```python
import pytest
from pathlib import Path
from pyguard import SecurityFixer


class TestSecurityFixer:
    """Test suite for SecurityFixer."""

    def test_fix_hardcoded_password_in_assignment(self):
        """Should detect and warn about hardcoded password in variable assignment."""
        code = 'password = "secret123"'
        fixer = SecurityFixer()
        
        fixed_code, modified = fixer._fix_hardcoded_passwords(code)
        
        assert modified
        assert "SECURITY:" in fixed_code
        assert "secret123" in fixed_code

    def test_fix_sql_injection_with_format(self):
        """Should detect and fix SQL injection using .format()."""
        code = 'query = "SELECT * FROM users WHERE id = {}".format(user_id)'
        fixer = SecurityFixer()
        
        fixed_code, modified = fixer._fix_sql_injection(code)
        
        assert modified
        assert "ANTI-PATTERN:" in fixed_code

    def test_no_fix_when_no_issues(self):
        """Should not modify code without security issues."""
        code = 'x = 42'
        fixer = SecurityFixer()
        
        fixed_code, modified = fixer._fix_hardcoded_passwords(code)
        
        assert not modified
        assert fixed_code == code
```

### **Test Coverage**

Aim for **>80% test coverage**:

```bash
# Run tests with coverage
pytest --cov=pyguard --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

### **Integration Tests**

Test end-to-end workflows:

```python
def test_full_pipeline_on_sample_project(tmp_path):
    """Test complete PyGuard workflow on sample project."""
    # Create sample project
    project_dir = tmp_path / "sample_project"
    project_dir.mkdir()
    (project_dir / "main.py").write_text('password = "test123"')
    
    # Run PyGuard
    result = subprocess.run(
        ["pyguard", str(project_dir)],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    assert "SECURITY:" in (project_dir / "main.py").read_text()
```

---

## 💬 **Commit Message Format**

We follow **Conventional Commits** for clear, structured commit history:

### **Format**

```
<type>(<scope>): <subject>

<body>

<footer>
```

### **Types**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

### **Examples**

```bash
# Feature
git commit -m "feat(security): add path traversal detection"

# Bug fix
git commit -m "fix(cli): handle empty file paths correctly"

# Documentation
git commit -m "docs: update README with installation instructions"

# Breaking change
git commit -m "feat(api)!: change SecurityFixer.fix_file signature

BREAKING CHANGE: SecurityFixer.fix_file now returns tuple instead of dict"
```

### **Best Practices**

- Use imperative mood ("add" not "added" or "adds")
- First line ≤ 50 characters
- Body wraps at 72 characters
- Explain *what* and *why*, not *how*
- Reference issues: `Fixes #123`, `Closes #456`

---

## 🔀 **Pull Request Process**

### **Before Submitting**

- [ ] Tests pass (`pytest`)
- [ ] Code is formatted (`black pyguard/`)
- [ ] Imports are sorted (`isort pyguard/`)
- [ ] Type checks pass (`mypy pyguard/`)
- [ ] Linting passes (`pylint pyguard/`)
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] Branch is up-to-date with `main`

### **PR Template**

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally

## Related Issues
Fixes #123
```

### **Review Process**

1. **Automated Checks**: GitHub Actions will run tests and linters
2. **Code Review**: Maintainer will review within 3-5 business days
3. **Changes Requested**: Address feedback and push updates
4. **Approval**: Once approved, maintainer will merge

### **After Merge**

- Your changes will be included in the next release
- You'll be added to CONTRIBUTORS.md
- Thank you for your contribution! 🎉

---

## 📂 **Project Structure**

Understanding the codebase organization:

```
PyGuard/
├── pyguard/                  # Main package
│   ├── __init__.py          # Package exports
│   ├── cli.py               # Command-line interface
│   └── lib/                 # Core library
│       ├── __init__.py
│       ├── core.py          # Logger, backup, diff, file ops
│       ├── security.py      # Security vulnerability fixes
│       ├── best_practices.py # Code quality improvements
│       └── formatting.py    # Code formatting
├── tests/                   # Test suite
│   ├── test_security.py
│   ├── test_best_practices.py
│   ├── test_formatting.py
│   └── test_cli.py
├── config/                  # Configuration files
│   ├── security_rules.toml
│   └── qa_settings.toml
├── docs/                    # Documentation
├── benchmarks/              # Performance benchmarks
├── .github/                 # GitHub workflows
│   └── workflows/
│       ├── test.yml
│       └── lint.yml
├── pyproject.toml           # Project metadata
├── setup.py                 # Setup script
├── README.md               # Project README
├── CONTRIBUTING.md         # This file
├── CHANGELOG.md            # Version history
└── LICENSE                 # MIT License
```

---

## ⚡ **Performance Considerations**

When contributing, keep performance in mind:

### **AST Over Regex**

Prefer AST-based analysis over regex when possible (10-100x faster):

```python
# ✅ Good - AST-based
import ast

class SecurityVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "load" and node.func.value.id == "yaml":
                # Handle yaml.load()
                pass

# ❌ Avoid - Regex-based (only for simple patterns)
import re
pattern = r"yaml\.load\("
```

### **Caching**

Cache expensive operations:

```python
from functools import lru_cache

@lru_cache(maxsize=128)
def parse_file(file_path: Path) -> ast.Module:
    """Parse file and cache AST."""
    return ast.parse(file_path.read_text())
```

### **Lazy Loading**

Import heavy modules only when needed:

```python
# ✅ Good
def format_with_black(code: str) -> str:
    import black  # Import only when formatting
    return black.format_str(code, mode=black.Mode())

# ❌ Avoid
import black  # Imported even if never used
```

### **Profiling**

Profile your changes:

```bash
# Profile with cProfile
python -m cProfile -o profile.stats -m pyguard src/

# Analyze results
python -m pstats profile.stats
> sort cumulative
> stats 20
```

---

## 🎯 **Areas Needing Help**

We especially welcome contributions in these areas:

- 🚀 **Performance**: AST-based fixers to replace regex patterns
- 📊 **Testing**: Increase test coverage above 80%
- 📝 **Documentation**: User guides, tutorials, API reference
- 🔍 **Security Rules**: Additional vulnerability patterns
- 🎨 **Best Practices**: More code quality checks
- 🛠️ **Integrations**: VS Code extension, pre-commit hooks
- 🌐 **Localization**: Translations for error messages

---

## 📞 **Getting Help**

Need help with your contribution?

- **Discussions**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Issues**: Tag with `question` label
- **Email**: your.email@example.com

---

## 📜 **License**

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to PyGuard! Every contribution, no matter how small, helps make Python development safer and more maintainable. 🐍✨
