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
    BestPracticesFixer,
    FormattingFixer,
    PyGuardLogger,
    SecurityFixer,
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
        logger.error("Sample file not found", file_path=str(file_path))
        return

    logger.info("Starting PyGuard analysis", file_path=str(file_path))

    # Read original code (kept for reference/comparison)
    # original_code = file_path.read_text()

    # Apply security fixes
    logger.info("Applying security fixes...")
    security_result = security.fix_file(file_path)
    logger.info(
        f"Security: {len(security_result)} fixes applied",
        details={"fix_count": len(security_result), "fixes": str(security_result)[:200]}
    )

    # Apply best practices
    logger.info("Applying best practices...")
    bp_result = best_practices.fix_file(file_path)
    logger.info(
        f"Best practices: {len(bp_result)} fixes applied",
        details={"fix_count": len(bp_result), "fixes": str(bp_result)[:200]}
    )

    # Format code
    logger.info("Formatting code...")
    format_result = formatter.format_file(file_path)
    logger.info(
        f"Formatting: {'success' if format_result['success'] else 'failed'}",
        details={"success": format_result.get('success', False)}
    )

    logger.info("Analysis complete!")


if __name__ == "__main__":
    main()
