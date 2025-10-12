#!/bin/bash
# Quality check script for PyGuard
# Runs comprehensive quality checks before committing

set -e

echo "🔍 PyGuard Quality Checks"
echo "========================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall status
ERRORS=0

# Function to run a check
run_check() {
    local name=$1
    local command=$2
    
    echo -n "Running $name... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        ERRORS=$((ERRORS + 1))
    fi
}

# Check Python version
echo "Python version: $(python --version)"
echo ""

# Format check
echo "📝 Code Formatting"
run_check "black" "black --check pyguard/ tests/"
run_check "isort" "isort --check pyguard/ tests/"
echo ""

# Linting
echo "🔍 Linting"
run_check "ruff" "ruff check pyguard/"
run_check "pylint" "pylint pyguard/ --exit-zero"
run_check "mypy" "mypy pyguard/ --ignore-missing-imports"
run_check "flake8" "flake8 pyguard/"
echo ""

# Security
echo "🔒 Security"
run_check "bandit" "bandit -r pyguard/ -ll -q"
echo ""

# Tests
echo "🧪 Tests"
run_check "pytest" "pytest tests/ -q"
echo ""

# Summary
echo "========================="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ $ERRORS check(s) failed${NC}"
    exit 1
fi
