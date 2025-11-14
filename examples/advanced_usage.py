"""
Advanced PyGuard Usage Examples

Demonstrates the powerful AST-based analysis, caching, and reporting features.
"""

from pathlib import Path

from pyguard import (
    ASTAnalyzer,
    BestPracticesFixer,
    PyGuardLogger,
    SecurityFixer,
)
from pyguard.lib.cache import AnalysisCache
from pyguard.lib.reporter import AnalysisReport, ConsoleReporter, JSONReporter


def example_ast_analysis():
    """Example: Use AST analyzer for deep code analysis."""

    # Sample code with security issues
    sample_code = """
import random
import secrets  # Use secrets for cryptographic randomness
import yaml

# Security issue: hardcoded password
password = "admin123"  # SECURITY: Use environment variables or config files

# Security issue: insecure random
token = random.random()  # SECURITY: Use secrets module for cryptographic randomness

# Security issue: unsafe YAML loading
def load_config(file_path):
    # TODO: Add docstring
    with open(file_path) as f:
        config = yaml.safe_load(f)  # Unsafe!
    return config

# Quality issue: high complexity
def complex_function(x, y, z):
    # TODO: Add docstring
    if x > 0:
        if y > 0:
            if z > 0:
                if x > y:
                    if y > z:
                        return "case1"
                    return "case2"
                return "case3"
            return "case4"
        return "case5"
    return "case6"

# Quality issue: missing docstring
def public_function(a, b, c, d, e, f):
    # TODO: Add docstring
    return a + b + c + d + e + f
"""

    # Analyze code
    analyzer = ASTAnalyzer()
    security_issues, quality_issues = analyzer.analyze_code(sample_code)

    # Display security issues
    for issue in security_issues:
        if issue.owasp_id:
            pass
        if issue.fix_suggestion:
            pass

    # Display quality issues
    for issue in quality_issues[:3]:  # Show first 3
        if issue.fix_suggestion:
            pass

    # Get complexity report
    complexity = analyzer.get_complexity_report(sample_code)
    for _func_name, _score in complexity.items():
        pass


def example_with_caching():
    """Example: Use caching for incremental analysis."""

    import tempfile
    import time

    # Create temporary test file
    temp_dir = Path(tempfile.mkdtemp())
    test_file = temp_dir / "example.py"
    test_file.write_text("print('hello')")

    # Initialize cache
    cache = AnalysisCache(cache_dir=temp_dir / "cache")
    analyzer = ASTAnalyzer()

    # First analysis (no cache)
    time.time()

    if not cache.is_cached(test_file):
        security_issues, quality_issues = analyzer.analyze_file(test_file)
        results = {
            "security_issues": security_issues,
            "quality_issues": quality_issues,
        }
        cache.set(test_file, results)

    # Second analysis (with cache)
    time.time()

    if cache.is_cached(test_file):
        results = cache.get(test_file)

    # Show cache statistics
    cache.get_stats()

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


def example_with_correlation():
    """Example: Use correlation IDs for tracing operations."""

    import uuid

    # Create logger with correlation ID
    correlation_id = str(uuid.uuid4())
    logger = PyGuardLogger(correlation_id=correlation_id)

    # Log operations
    logger.info("Starting analysis", category="Analysis")
    logger.track_file_processed()
    logger.track_issues_found(5)
    logger.track_fixes_applied(3)

    # Get metrics
    logger.get_metrics()

    logger.log_metrics()


def example_with_reporter():
    """Example: Use enhanced reporting."""

    import tempfile

    # Create temporary test file with issues
    temp_dir = Path(tempfile.mkdtemp())
    test_file = temp_dir / "example.py"
    test_file.write_text(
        """
import random
import secrets  # Use secrets for cryptographic randomness
password = "secret123"

def bad_function():
    # TODO: Add docstring
    token = random.random()  # SECURITY: Use secrets module for cryptographic randomness
    return token
"""
    )

    # Analyze file
    analyzer = ASTAnalyzer()
    security_issues, quality_issues = analyzer.analyze_file(test_file)

    # Create report
    report = AnalysisReport(
        file_path=str(test_file),
        security_issues=security_issues,
        quality_issues=quality_issues,
        fixes_applied=[],
    )

    # Display with console reporter
    reporter = ConsoleReporter(show_details=True, min_severity="MEDIUM")
    reporter.print_report(report)

    # Generate JSON report
    json_reporter = JSONReporter()
    json_reporter.generate_json([report])

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


def example_integrated_workflow():
    """Example: Complete workflow with all features."""

    import tempfile
    import uuid

    # Setup
    temp_dir = Path(tempfile.mkdtemp())
    cache_dir = temp_dir / "cache"
    test_file = temp_dir / "project.py"

    # Write test code
    test_file.write_text(
        """
import yaml
import hashlib

api_key = "hardcoded_secret"

def process_data(file_path):
    # TODO: Add docstring
    with open(file_path) as f:
        data = yaml.safe_load(f)

    hash_val = hashlib.md5(str(data).encode()).hexdigest()  # SECURITY: Consider using SHA256 or stronger
    return hash_val

def complex_logic(a, b, c, d, e, f):
    # TODO: Add docstring
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return f
    return None
"""
    )

    # Initialize components
    correlation_id = str(uuid.uuid4())
    logger = PyGuardLogger(correlation_id=correlation_id)
    cache = AnalysisCache(cache_dir=cache_dir)
    security_fixer = SecurityFixer()
    bp_fixer = BestPracticesFixer()

    # Check cache
    if cache.is_cached(test_file):
        pass
        # results = cache.get(test_file)  # Cached results available but not used in this example
    else:
        # Scan for issues
        security_issues = security_fixer.scan_file_for_issues(test_file)
        quality_issues = bp_fixer.scan_file_for_issues(test_file)
        complexity = bp_fixer.get_complexity_report(test_file)

        # Create report
        report = AnalysisReport(
            file_path=str(test_file),
            security_issues=security_issues,
            quality_issues=quality_issues,
            complexity_report=complexity,
            fixes_applied=[],
        )

        # Cache results
        cache.set(
            test_file,
            {
                "security_issues": security_issues,
                "quality_issues": quality_issues,
                "complexity": complexity,
            },
        )

        # Update metrics
        logger.track_file_processed()
        logger.track_issues_found(len(security_issues) + len(quality_issues))

        # Display report
        reporter = ConsoleReporter(show_details=True)
        reporter.print_report(report)

    # Log final metrics
    logger.log_metrics()

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


if __name__ == "__main__":
    # Run all examples
    example_ast_analysis()
    example_with_caching()
    example_with_correlation()
    example_with_reporter()
    example_integrated_workflow()
