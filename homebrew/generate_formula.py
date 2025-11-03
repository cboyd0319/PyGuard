#!/usr/bin/env python3
"""
Generate Homebrew formula with proper SHA256 checksums.

This script helps prepare the PyGuard Homebrew formula for publishing
by calculating the SHA256 checksum of the release tarball.

Usage:
    python generate_formula.py <version>
    
Example:
    python generate_formula.py 0.7.0
"""

import hashlib
from pathlib import Path
import sys
import urllib.request


def calculate_sha256_from_url(url: str) -> str:
    """Download and calculate SHA256 checksum of a file."""
    print(f"Downloading {url}...")
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
            sha256 = hashlib.sha256(data).hexdigest()
            print(f"✓ SHA256: {sha256}")
            return sha256
    except Exception as e:
        print(f"✗ Error downloading: {e}")
        return "PLACEHOLDER_SHA256"


def update_formula(version: str, sha256: str):
    """Update the Homebrew formula with version and SHA256."""
    formula_path = Path(__file__).parent / "pyguard.rb"
    
    if not formula_path.exists():
        print(f"✗ Formula not found: {formula_path}")
        return
    
    formula_content = formula_path.read_text()
    
    # Update URL to point to PyPI release
    pypi_url = f"https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-{version}.tar.gz"
    formula_content = formula_content.replace(
        'url "https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-0.6.0.tar.gz"',
        f'url "{pypi_url}"'
    )
    
    # Update SHA256
    formula_content = formula_content.replace(
        'sha256 "PLACEHOLDER_SHA256"',
        f'sha256 "{sha256}"'
    )
    
    # Write updated formula
    formula_path.write_text(formula_content)
    print(f"✓ Formula updated: {formula_path}")
    print(f"  Version: {version}")
    print(f"  URL: {pypi_url}")
    print(f"  SHA256: {sha256}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_formula.py <version>")
        print("Example: python generate_formula.py 0.7.0")
        sys.exit(1)
    
    version = sys.argv[1]
    print(f"Generating Homebrew formula for PyGuard v{version}")
    print("-" * 60)
    
    # Calculate SHA256 from PyPI
    pypi_url = f"https://files.pythonhosted.org/packages/source/p/pyguard/pyguard-{version}.tar.gz"
    sha256 = calculate_sha256_from_url(pypi_url)
    
    # Update formula
    update_formula(version, sha256)
    
    print("-" * 60)
    print("Next steps:")
    print("1. Review the updated formula: homebrew/pyguard.rb")
    print("2. Test locally: brew install --build-from-source ./homebrew/pyguard.rb")
    print("3. Run tests: brew test pyguard")
    print("4. Commit and push to homebrew-pyguard tap repository")


if __name__ == "__main__":
    main()
