#!/usr/bin/env bash
# Validation script for PyGuard GitHub Action
# Run this before publishing to GitHub Marketplace

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "🔍 Validating PyGuard GitHub Action..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

check_file() {
    local file=$1
    local description=$2
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✓${NC} $description exists: $file"
    else
        echo -e "${RED}✗${NC} $description missing: $file"
        ((ERRORS++))
    fi
}

check_content() {
    local file=$1
    local pattern=$2
    local description=$3
    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $description"
    else
        echo -e "${RED}✗${NC} $description not found in $file"
        ((ERRORS++))
    fi
}

warn_if_missing() {
    local file=$1
    local pattern=$2
    local description=$3
    if ! grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "${YELLOW}⚠${NC}  Warning: $description (optional but recommended)"
        ((WARNINGS++))
    fi
}

echo "📋 Checking required files..."
check_file "action.yml" "Action metadata"
check_file "README.md" "README"
check_file "LICENSE" "License file"
check_file "docs/guides/github-action-guide.md" "Action guide"
check_file "MARKETPLACE.md" "Marketplace documentation"
echo ""

echo "📋 Checking action.yml structure..."
check_content "action.yml" "name:" "Action name defined"
check_content "action.yml" "description:" "Action description defined"
check_content "action.yml" "author:" "Action author defined"
check_content "action.yml" "branding:" "Action branding defined"
check_content "action.yml" "inputs:" "Action inputs defined"
check_content "action.yml" "outputs:" "Action outputs defined"
check_content "action.yml" "runs:" "Action runs defined"
check_content "action.yml" "using: 'composite'" "Composite action type"
echo ""

echo "📋 Checking required inputs..."
check_content "action.yml" "paths:" "paths input"
check_content "action.yml" "scan-only:" "scan-only input"
check_content "action.yml" "security-only:" "security-only input"
check_content "action.yml" "upload-sarif:" "upload-sarif input"
echo ""

echo "📋 Checking required outputs..."
check_content "action.yml" "issues-found:" "issues-found output"
check_content "action.yml" "sarif-file:" "sarif-file output"
echo ""

echo "📋 Checking example workflows..."
check_file "examples/github-workflows/basic-security-scan.yml" "Basic scan example"
check_file "examples/github-workflows/security-gate.yml" "Security gate example"
check_file "examples/github-workflows/multi-path-scan.yml" "Multi-path example"
check_file "examples/github-workflows/scheduled-audit.yml" "Scheduled audit example"
echo ""

echo "📋 Checking test workflow..."
check_file ".github/workflows/test-action.yml" "Action test workflow"
echo ""

echo "📋 Checking documentation..."
check_file "docs/GITHUB_ACTION_QUICK_REFERENCE.md" "Quick reference"
check_file "docs/GITHUB_ACTION_PUBLISHING.md" "Publishing guide"
echo ""

echo "📋 Checking README content..."
check_content "README.md" "GitHub Action" "GitHub Action section in README"
warn_if_missing "README.md" "GitHub Marketplace" "Marketplace badge"
echo ""

echo "📋 Checking version consistency..."
VERSION_PYPROJECT=$(grep -m1 "version = " pyproject.toml | cut -d'"' -f2 2>/dev/null || echo "not found")
VERSION_README=$(grep -m1 "Version.*badge" README.md | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" 2>/dev/null || echo "not found")

if [[ "$VERSION_PYPROJECT" == "$VERSION_README" ]]; then
    echo -e "${GREEN}✓${NC} Version consistent: $VERSION_PYPROJECT"
else
    echo -e "${YELLOW}⚠${NC}  Version mismatch: pyproject.toml=$VERSION_PYPROJECT, README.md=$VERSION_README"
    ((WARNINGS++))
fi
echo ""

echo "📋 Checking branding..."
check_content "action.yml" "icon:" "Branding icon defined"
check_content "action.yml" "color:" "Branding color defined"
echo ""

echo "📋 Checking permissions documentation..."
check_content "docs/guides/github-action-guide.md" "permissions:" "Permissions documented"
check_content "docs/guides/github-action-guide.md" "security-events:" "Security events permission documented"
echo ""

echo "📋 Checking SARIF integration..."
check_content "action.yml" "upload-sarif" "SARIF upload in action"
check_content "action.yml" "github/codeql-action/upload-sarif" "CodeQL SARIF upload action"
echo ""

echo "📋 Validating YAML syntax..."
if command -v yamllint &> /dev/null; then
    if yamllint action.yml 2>/dev/null; then
        echo -e "${GREEN}✓${NC} action.yml YAML syntax valid"
    else
        echo -e "${RED}✗${NC} action.yml has YAML syntax errors"
        ((ERRORS++))
    fi
else
    echo -e "${YELLOW}⚠${NC}  yamllint not installed, skipping YAML validation"
    ((WARNINGS++))
fi
echo ""

echo "📋 Checking for security best practices..."
check_content "action.yml" "actions/checkout@" "Using pinned checkout action"
check_content "action.yml" "actions/setup-python@" "Using pinned setup-python action"
echo ""

echo "📋 Checking PyGuard installation..."
if [[ -f "setup.py" ]] && [[ -f "pyproject.toml" ]]; then
    echo -e "${GREEN}✓${NC} PyGuard package structure exists"
else
    echo -e "${RED}✗${NC} PyGuard package structure incomplete"
    ((ERRORS++))
fi
echo ""

# Summary
echo "═══════════════════════════════════════════════════"
echo "Validation Summary"
echo "═══════════════════════════════════════════════════"

if [[ $ERRORS -eq 0 ]] && [[ $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}✅ All checks passed! Ready to publish to GitHub Marketplace.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run tests: gh workflow run test-action.yml"
    echo "2. Create release tag: git tag -a v0.3.0 -m 'Release v0.3.0'"
    echo "3. Push tag: git push origin v0.3.0"
    echo "4. Publish to marketplace from GitHub Releases page"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Validation passed with $WARNINGS warning(s).${NC}"
    echo "   These are optional improvements but not blockers."
    echo ""
    echo "Ready to publish to GitHub Marketplace."
    exit 0
else
    echo -e "${RED}❌ Validation failed with $ERRORS error(s) and $WARNINGS warning(s).${NC}"
    echo "   Please fix the errors above before publishing."
    exit 1
fi
