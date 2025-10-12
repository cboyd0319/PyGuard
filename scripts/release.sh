#!/bin/bash
# Release script for PyGuard
# Creates a new release with proper versioning and changelog

set -e

echo "🚀 PyGuard Release Script"
echo "========================"
echo ""

# Check if we're on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "❌ Error: Must be on main branch to release"
    echo "   Current branch: $BRANCH"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Uncommitted changes detected"
    echo "   Please commit or stash changes before releasing"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(python -c "import pyguard; print(pyguard.__version__)")
echo "Current version: $CURRENT_VERSION"
echo ""

# Ask for new version
read -p "Enter new version (e.g., 0.2.0): " NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    echo "❌ Error: No version specified"
    exit 1
fi

echo ""
echo "📋 Release checklist:"
echo "  - Update version in pyguard/__init__.py"
echo "  - Update CHANGELOG.md"
echo "  - Run tests"
echo "  - Create git tag"
echo "  - Build packages"
echo "  - Push to GitHub"
echo ""

read -p "Continue with release $NEW_VERSION? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Release cancelled"
    exit 1
fi

echo ""
echo "🔄 Updating version..."
sed -i "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" pyguard/__init__.py

echo "📝 Updating CHANGELOG..."
DATE=$(date +%Y-%m-%d)
sed -i "s/## \[Unreleased\]/## [$NEW_VERSION] - $DATE/" CHANGELOG.md

echo "🧪 Running tests..."
if ! pytest tests/ -q; then
    echo "❌ Tests failed"
    exit 1
fi

echo "🔍 Running linters..."
if ! make lint > /dev/null 2>&1; then
    echo "⚠️  Linting warnings detected (continuing anyway)"
fi

echo "📦 Building packages..."
python -m build

echo "📝 Creating git commit..."
git add pyguard/__init__.py CHANGELOG.md
git commit -m "Release version $NEW_VERSION"

echo "🏷️  Creating git tag..."
git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"

echo ""
echo "✅ Release $NEW_VERSION prepared!"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git show HEAD"
echo "  2. Push to GitHub: git push && git push --tags"
echo "  3. Create GitHub release"
echo "  4. Upload to PyPI: python -m twine upload dist/*"
echo ""
