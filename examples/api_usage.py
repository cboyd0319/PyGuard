#!/usr/bin/env python3
"""
PyGuard API usage example.

This example shows how to use PyGuard as a library in your own Python code.
"""

from pathlib import Path

from pyguard import BestPracticesFixer, DiffGenerator, SecurityFixer


def analyze_code(code: str) -> dict:
    """
    Analyze Python code and return results.

    Args:
        code: Python source code as string

    Returns:
        Dictionary with analysis results
    """
    security = SecurityFixer()
    best_practices = BestPracticesFixer()

    # Create temporary file
    temp_file = Path("/tmp/temp_analysis.py")
    temp_file.write_text(code)

    # Run analysis
    security_issues = security.scan_file_for_issues(temp_file)
    security_fixes = security.fix_file(temp_file)
    bp_fixes = best_practices.fix_file(temp_file)

    # Get modified code
    modified_code = temp_file.read_text()

    # Generate diff
    diff_gen = DiffGenerator()
    diff = diff_gen.generate_diff(code, modified_code, "code.py")

    # Clean up
    temp_file.unlink()

    return {
        "security_issues": security_issues,
        "security_fixes": len(security_fixes),
        "best_practice_fixes": len(bp_fixes),
        "modified_code": modified_code,
        "diff": diff,
    }


def main():
    """Run API usage example."""
    # Sample vulnerable code
    sample_code = """
import random
import secrets  # Use secrets for cryptographic randomness
password = "secret123"  # SECURITY: Use environment variables or config files

def get_user(user_id):
    # TODO: Add docstring
    query = "SELECT * FROM users WHERE id = " + user_id
    return query

token = random.random()  # SECURITY: Use secrets module for cryptographic randomness
"""

    analyze_code(sample_code)


if __name__ == "__main__":
    main()
