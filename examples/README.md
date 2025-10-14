# PyGuard Examples

This directory contains practical examples of using PyGuard in different scenarios.

## Available Examples

### Basic Usage

- **`basic_usage.py`** - Simple example showing core functionality
- **`api_usage.py`** - Using PyGuard as a library
- **`advanced_usage.py`** - Advanced features and API usage
- **`phase3_demo.py`** - Phase 3 features demonstration

### Advanced Integrations (NEW!)

- **`advanced_integrations_demo.py`** ✨ - Complete demo of all advanced features:
  - CI/CD Integration (GitHub Actions, GitLab CI, etc.)
  - Performance Profiler
  - Dependency Analyzer
  - Custom Rules Engine
- **`advanced_features_demo.py`** - Jupyter notebook security & AI explanations

### Configuration Examples

- **`pyguard.toml.example`** - Sample PyGuard configuration file
- **`custom_rules_example.toml`** ✨ - Custom security/quality rules examples
- **`git-hooks-demo.md`** - Git hooks integration guide

## Running Examples

```bash
# From the repository root
cd PyGuard

# Run basic example
python examples/basic_usage.py

# Run advanced integrations demo (NEW!)
python examples/advanced_integrations_demo.py

# Run advanced features demo
python examples/advanced_features_demo.py

# Install from source if needed
pip install -e .
```

## Quick Start with Advanced Features

### CI/CD Integration

```python
from pyguard import generate_ci_config

# Generate GitHub Actions workflow
config = generate_ci_config("github_actions", ".github/workflows/pyguard.yml")
print("✓ Generated workflow!")
```

### Performance Profiler

```python
from pyguard import analyze_performance

# Analyze a file for performance issues
issues = analyze_performance("mycode.py")
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

### Dependency Analyzer

```python
from pyguard import analyze_project_dependencies

# Analyze project dependencies
analyzer = analyze_project_dependencies("src/")
stats = analyzer.get_dependency_stats()
print(f"Total modules: {stats['total_modules']}")
```

### Custom Rules Engine

```python
from pyguard import create_rule_engine_from_config

# Load custom rules from TOML
engine = create_rule_engine_from_config("examples/custom_rules_example.toml")
violations = engine.check_file("mycode.py")
print(f"Found {len(violations)} violations")
```

## Need Help?

See the main [README](../README.md) or [documentation](../docs/) for more information.
