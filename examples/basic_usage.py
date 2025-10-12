#!/usr/bin/env python3
"""
Basic PyGuard usage example.

This example demonstrates the core functionality of PyGuard:
- Security vulnerability detection and fixes
- Best practices enforcement
- Code formatting
"""

from pathlib import Path
from pyguard import (
    SecurityFixer,
    BestPracticesFixer,
    FormattingFixer,
    PyGuardLogger,
)


def main():
    """Run basic PyGuard analysis."""
    # Initialize components
    logger = PyGuardLogger()
    security = SecurityFixer()
    best_practices = BestPracticesFixer()
    formatter = FormattingFixer()

    # Example file to analyze
    file_path = Path("sample_code.py")
    
    if not file_path.exists():
        logger.error("Sample file not found", file=str(file_path))
        return

    logger.info("Starting PyGuard analysis", file=str(file_path))

    # Read original code
    original_code = file_path.read_text()

    # Apply security fixes
    logger.info("Applying security fixes...")
    security_result = security.fix_file(file_path)
    logger.info(
        f"Security: {len(security_result)} fixes applied",
        fixes=security_result
    )

    # Apply best practices
    logger.info("Applying best practices...")
    bp_result = best_practices.fix_file(file_path)
    logger.info(
        f"Best practices: {len(bp_result)} fixes applied",
        fixes=bp_result
    )

    # Format code
    logger.info("Formatting code...")
    format_result = formatter.format_file(file_path)
    logger.info(
        f"Formatting: {'success' if format_result['success'] else 'failed'}",
        result=format_result
    )

    logger.info("Analysis complete!")
    print("\n✅ PyGuard analysis completed successfully!")
    print(f"   Security fixes: {len(security_result)}")
    print(f"   Best practice fixes: {len(bp_result)}")
    print(f"   Formatting: {'applied' if format_result['success'] else 'skipped'}")


if __name__ == "__main__":
    main()
