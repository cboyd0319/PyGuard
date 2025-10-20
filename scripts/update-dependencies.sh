#!/usr/bin/env bash
# Update dependencies with SHA256 hash verification
# Usage: ./scripts/update-dependencies.sh [--upgrade]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "🔒 PyGuard Dependency Update with Hash Verification"
echo "=================================================="
echo ""

# Check if pip-tools is installed
if ! command -v pip-compile &> /dev/null; then
    echo "❌ pip-tools is not installed"
    echo "   Install with: pip install pip-tools"
    exit 1
fi

echo "✅ pip-tools found"
echo ""

# Determine if this is an upgrade
UPGRADE_FLAG=""
if [ "${1:-}" = "--upgrade" ]; then
    UPGRADE_FLAG="--upgrade"
    echo "🔄 Upgrading all dependencies to latest versions"
else
    echo "📌 Updating hashes for pinned versions (no upgrades)"
    echo "   Use --upgrade flag to upgrade to latest versions"
fi
echo ""

# Generate requirements.txt with hashes
echo "1️⃣  Generating requirements.txt with SHA256 hashes..."
pip-compile \
    --generate-hashes \
    --allow-unsafe \
    --resolver=backtracking \
    ${UPGRADE_FLAG} \
    requirements.in \
    -o requirements.txt

echo "✅ Generated requirements.txt with $(grep -c 'sha256:' requirements.txt) hashes"
echo ""

# Generate requirements-dev.txt with hashes
echo "2️⃣  Generating requirements-dev.txt with SHA256 hashes..."
pip-compile \
    --generate-hashes \
    --allow-unsafe \
    --resolver=backtracking \
    ${UPGRADE_FLAG} \
    requirements-dev.in \
    -o requirements-dev.txt

echo "✅ Generated requirements-dev.txt with $(grep -c 'sha256:' requirements-dev.txt) hashes"
echo ""

# Summary
echo "=================================================="
echo "✅ Dependency update complete!"
echo ""
echo "📊 Summary:"
echo "   - Production dependencies: $(grep -c 'sha256:' requirements.txt) hashes"
echo "   - Development dependencies: $(grep -c 'sha256:' requirements-dev.txt) hashes"
echo ""
echo "🔍 Next steps:"
echo "   1. Review the changes with: git diff requirements*.txt"
echo "   2. Test installation: pip install -r requirements.txt --require-hashes"
echo "   3. Run tests: pytest"
echo "   4. Run security scan: bandit -r pyguard/"
echo "   5. Commit changes: git add requirements*.txt && git commit"
echo ""
echo "🔒 All dependencies are cryptographically verified with SHA256 hashes"
echo "   This prevents supply chain attacks including:"
echo "   - Dependency confusion"
echo "   - Typosquatting"
echo "   - Package hijacking"
echo "   - Malicious dependency injection"
echo ""
echo "📚 See docs/DEPENDENCY_MANAGEMENT.md for more information"
