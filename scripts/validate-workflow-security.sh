#!/bin/bash
# Validate GitHub Actions workflow security
# Based on PYSEC_OMEGA security standards

set -euo pipefail

WORKFLOWS_DIR=".github/workflows"
ERRORS=0
WARNINGS=0

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}GitHub Actions Security Validator${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check 1: SHA-pinned actions
echo -e "${BLUE}[1/7] Checking action pinning...${NC}"
NON_PINNED=$(grep -r "uses:" "$WORKFLOWS_DIR" --include="*.yml" --include="*.yaml" | grep -v "@[a-f0-9]\{40\}" | grep -v "# v" | grep -v "./.github/actions/" | grep -v "uses: ./" || true)
if [ -n "$NON_PINNED" ]; then
    echo -e "${RED}❌ ERROR: Found non-SHA-pinned actions:${NC}"
    echo "$NON_PINNED"
    ((ERRORS++))
else
    echo -e "${GREEN}✅ All external actions are SHA-pinned${NC}"
fi
echo ""

# Check 2: Workflow injection vulnerabilities
echo -e "${BLUE}[2/7] Checking for workflow injection...${NC}"
INJECTION_RISK=$(grep -rn "github.event" "$WORKFLOWS_DIR" | grep "run:" | grep -v "env:" || true)
if [ -n "$INJECTION_RISK" ]; then
    echo -e "${YELLOW}⚠️  WARNING: Potential workflow injection risk:${NC}"
    echo "$INJECTION_RISK"
    echo -e "${YELLOW}Verify that github.event.* values are not interpolated directly in run blocks${NC}"
    ((WARNINGS++))
else
    echo -e "${GREEN}✅ No obvious workflow injection risks${NC}"
fi
echo ""

# Check 3: Excessive permissions
echo -e "${BLUE}[3/7] Checking permissions...${NC}"
EXCESSIVE_PERMS=$(grep -rn "permissions:" "$WORKFLOWS_DIR" | grep -E "write-all|{}" || true)
if [ -n "$EXCESSIVE_PERMS" ]; then
    echo -e "${RED}❌ ERROR: Found excessive permissions:${NC}"
    echo "$EXCESSIVE_PERMS"
    ((ERRORS++))
else
    echo -e "${GREEN}✅ No excessive permissions found${NC}"
fi
echo ""

# Check 4: pull_request_target usage
echo -e "${BLUE}[4/7] Checking pull_request_target usage...${NC}"
PR_TARGET=$(grep -l "pull_request_target" "$WORKFLOWS_DIR"/*.yml 2>/dev/null || true)
if [ -n "$PR_TARGET" ]; then
    # Check if any of these workflows checkout PR code
    UNSAFE_PR_TARGET=""
    for workflow in $PR_TARGET; do
        # Check if workflow checks out PR code (ref: github.event.pull_request.head.*)
        if grep -q "ref.*github.event.pull_request.head" "$workflow"; then
            UNSAFE_PR_TARGET="$UNSAFE_PR_TARGET\n$workflow"
        fi
    done
    
    if [ -n "$UNSAFE_PR_TARGET" ]; then
        echo -e "${RED}❌ ERROR: Unsafe pull_request_target usage (checks out PR code):${NC}"
        echo -e "$UNSAFE_PR_TARGET"
        ((ERRORS++))
    else
        echo -e "${GREEN}✅ pull_request_target usage is safe (no PR code checkout)${NC}"
    fi
else
    echo -e "${GREEN}✅ No pull_request_target usage${NC}"
fi
echo ""

# Check 5: Secrets in run blocks
echo -e "${BLUE}[5/7] Checking for secrets in run blocks...${NC}"
SECRET_EXPOSURE=$(grep -rn "secrets\." "$WORKFLOWS_DIR" | grep "run:" | grep -v "env:" || true)
if [ -n "$SECRET_EXPOSURE" ]; then
    echo -e "${RED}❌ ERROR: Potential secret exposure in run blocks:${NC}"
    echo "$SECRET_EXPOSURE"
    ((ERRORS++))
else
    echo -e "${GREEN}✅ No secrets directly in run blocks${NC}"
fi
echo ""

# Check 6: persist-credentials
echo -e "${BLUE}[6/7] Checking persist-credentials setting...${NC}"
PERSIST_CREDS=$(grep -A5 "actions/checkout@" "$WORKFLOWS_DIR"/*.yml 2>/dev/null | grep "persist-credentials: true" || true)
if [ -n "$PERSIST_CREDS" ]; then
    echo -e "${YELLOW}⚠️  WARNING: Found persist-credentials: true${NC}"
    echo "$PERSIST_CREDS"
    echo -e "${YELLOW}Consider using persist-credentials: false for security${NC}"
    ((WARNINGS++))
else
    echo -e "${GREEN}✅ No workflows persisting credentials${NC}"
fi
echo ""

# Check 7: Required security workflows
echo -e "${BLUE}[7/7] Checking required security workflows...${NC}"
REQUIRED_WORKFLOWS=("codeql.yml" "scorecard.yml" "dependency-review.yml")
MISSING_WORKFLOWS=()
for workflow in "${REQUIRED_WORKFLOWS[@]}"; do
    if [ ! -f "$WORKFLOWS_DIR/$workflow" ]; then
        MISSING_WORKFLOWS+=("$workflow")
    fi
done

if [ ${#MISSING_WORKFLOWS[@]} -gt 0 ]; then
    echo -e "${YELLOW}⚠️  WARNING: Missing recommended security workflows:${NC}"
    for workflow in "${MISSING_WORKFLOWS[@]}"; do
        echo "  - $workflow"
    done
    ((WARNINGS++))
else
    echo -e "${GREEN}✅ All recommended security workflows present${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Security Validation Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Errors:   ${RED}$ERRORS${NC}"
echo -e "Warnings: ${YELLOW}$WARNINGS${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}🎉 All security checks passed!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Validation completed with warnings${NC}"
    exit 0
else
    echo -e "${RED}❌ Validation failed with errors${NC}"
    exit 1
fi
