#!/bin/bash
# Development environment setup script for PyGuard

set -e

echo "🚀 Setting up PyGuard development environment"
echo "=============================================="
echo ""

# Check Python version
echo "Checking Python version..."
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

REQUIRED_VERSION="3.8"
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "❌ Error: Python 3.8 or higher is required"
    exit 1
fi
echo "✓ Python version OK"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo "✓ pip upgraded"
echo ""

# Install PyGuard in development mode
echo "Installing PyGuard in development mode..."
pip install -e ".[dev]"
echo "✓ PyGuard installed"
echo ""

# Install pre-commit hooks
if command -v pre-commit &> /dev/null; then
    echo "Installing pre-commit hooks..."
    pre-commit install
    echo "✓ Pre-commit hooks installed"
else
    echo "⚠ pre-commit not found, skipping hook installation"
fi
echo ""

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p logs backups
echo "✓ Directories created"
echo ""

# Run initial tests
echo "Running initial tests..."
if pytest tests/ -q; then
    echo "✓ Tests passed"
else
    echo "⚠ Some tests failed - this is expected for a new setup"
fi
echo ""

echo "=============================================="
echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run tests: make test"
echo "  3. Run linters: make lint"
echo "  4. Format code: make format"
echo ""
echo "Happy coding! 🎉"
