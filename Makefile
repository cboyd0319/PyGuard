.PHONY: help install install-dev dev test test-fast test-parallel lint format fmt type clean build docs

help:
	@echo "PyGuard - Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install        - Install PyGuard in production mode"
	@echo "  install-dev    - Install PyGuard with development dependencies"
	@echo "  dev            - Alias for install-dev"
	@echo "  test           - Run test suite with coverage"
	@echo "  test-fast      - Run tests without coverage"
	@echo "  test-parallel  - Run tests in parallel (32% faster)"
	@echo "  lint           - Run all linters (ruff, pylint, mypy)"
	@echo "  format         - Format code with black and isort"
	@echo "  fmt            - Alias for format"
	@echo "  type           - Run type checking with mypy"
	@echo "  clean          - Remove build artifacts and cache files"
	@echo "  build          - Build distribution packages"
	@echo "  docs           - Generate documentation"
	@echo "  benchmark      - Run performance benchmarks"
	@echo "  security       - Run security checks with bandit"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# Alias for install-dev
dev: install-dev
	@echo "✅ Development dependencies installed!"

test:
	pytest tests/ -v --cov=pyguard --cov-report=term-missing --cov-report=html

test-fast:
	pytest tests/ --no-cov -x

test-parallel:
	pytest tests/ -n auto --no-cov -q

lint:
	@echo "Running ruff..."
	ruff check pyguard/
	@echo "Running pylint..."
	pylint pyguard/
	@echo "Running mypy..."
	mypy pyguard/
	@echo "Running flake8..."
	flake8 pyguard/

format:
	@echo "Formatting with black..."
	black pyguard/ tests/ examples/
	@echo "Sorting imports with isort..."
	isort pyguard/ tests/ examples/

# Alias for format
fmt: format

# Type checking target
type:
	@echo "Running type checks with mypy..."
	mypy pyguard/

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache/ .coverage htmlcov/
	rm -rf .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "Clean complete!"

build: clean
	python -m build

docs:
	@echo "Building documentation..."
	@echo "Documentation generation not yet implemented"

benchmark:
	@echo "Running benchmarks..."
	python benchmarks/bench_security.py

security:
	@echo "Running security checks..."
	bandit -r pyguard/ -ll

# Continuous Integration targets
ci-test:
	pytest tests/ -v --cov=pyguard --cov-report=xml --cov-report=term

ci-lint:
	ruff check pyguard/ --output-format=github
	pylint pyguard/ --output-format=colorized

# Development helpers
dev-setup: install-dev
	pre-commit install
	@echo "Development environment ready!"

watch-test:
	@echo "Watching for changes..."
	pytest-watch tests/ -v

# Quick checks before commit
pre-commit: format lint test-fast
	@echo "✅ Pre-commit checks passed!"
