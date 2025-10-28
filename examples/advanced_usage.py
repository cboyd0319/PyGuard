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
    print("\n" + "=" * 80)
    print("Example 1: AST-Based Analysis")
    print("=" * 80)

    # Sample code with security issues
    sample_code = """
import random
import yaml

# Security issue: hardcoded password
password = "admin123"

# Security issue: insecure random
token = random.random()

# Security issue: unsafe YAML loading
def load_config(file_path):
    with open(file_path) as f:
        config = yaml.load(f)  # Unsafe!
    return config

# Quality issue: high complexity
def complex_function(x, y, z):
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
    return a + b + c + d + e + f
"""

    # Analyze code
    analyzer = ASTAnalyzer()
    security_issues, quality_issues = analyzer.analyze_code(sample_code)

    # Display security issues
    print(f"\n Found {len(security_issues)} security issues:")
    for issue in security_issues:
        print(f"\n  [{issue.severity}] {issue.category}")
        print(f"  Line {issue.line_number}: {issue.message}")
        if issue.owasp_id:
            print(f"  OWASP: {issue.owasp_id}")
        if issue.fix_suggestion:
            print(f"  💡 Fix: {issue.fix_suggestion}")

    # Display quality issues
    print(f"\n✨ Found {len(quality_issues)} code quality issues:")
    for issue in quality_issues[:3]:  # Show first 3
        print(f"\n  [{issue.severity}] {issue.category}")
        print(f"  Line {issue.line_number}: {issue.message}")
        if issue.fix_suggestion:
            print(f"  💡 Fix: {issue.fix_suggestion}")

    # Get complexity report
    complexity = analyzer.get_complexity_report(sample_code)
    print("\n Complexity Report:")
    for func_name, score in complexity.items():
        status = "[WARN] HIGH" if score > 10 else "[OK] OK"
        print(f"  {func_name}: {score} {status}")


def example_with_caching():
    """Example: Use caching for incremental analysis."""
    print("\n" + "=" * 80)
    print("Example 2: Incremental Analysis with Caching")
    print("=" * 80)

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
    print("\n First analysis (no cache):")
    start = time.time()

    if not cache.is_cached(test_file):
        security_issues, quality_issues = analyzer.analyze_file(test_file)
        results = {
            "security_issues": security_issues,
            "quality_issues": quality_issues,
        }
        cache.set(test_file, results)
        print(f"  Analyzed and cached in {(time.time() - start)*1000:.2f}ms")

    # Second analysis (with cache)
    print("\n Second analysis (with cache):")
    start = time.time()

    if cache.is_cached(test_file):
        results = cache.get(test_file)
        print(f"  Retrieved from cache in {(time.time() - start)*1000:.2f}ms")
        print("  ⚡ Much faster!")

    # Show cache statistics
    stats = cache.get_stats()
    print("\n📈 Cache Statistics:")
    print(f"  Entries: {stats['entries']}")
    print(f"  Size: {stats['size_mb']} MB")

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


def example_with_correlation():
    """Example: Use correlation IDs for tracing operations."""
    print("\n" + "=" * 80)
    print("Example 3: Correlation IDs for Distributed Tracing")
    print("=" * 80)

    import uuid

    # Create logger with correlation ID
    correlation_id = str(uuid.uuid4())
    logger = PyGuardLogger(correlation_id=correlation_id)

    print(f"\n🔍 Correlation ID: {correlation_id}")

    # Log operations
    logger.info("Starting analysis", category="Analysis")
    logger.track_file_processed()
    logger.track_issues_found(5)
    logger.track_fixes_applied(3)

    # Get metrics
    metrics = logger.get_metrics()
    print("\n Metrics:")
    print(f"  Files processed: {metrics['files_processed']}")
    print(f"  Issues found: {metrics['issues_found']}")
    print(f"  Fixes applied: {metrics['fixes_applied']}")
    print(f"  Processing rate: {metrics['files_per_second']:.2f} files/sec")

    logger.log_metrics()


def example_with_reporter():
    """Example: Use enhanced reporting."""
    print("\n" + "=" * 80)
    print("Example 4: Enhanced Reporting")
    print("=" * 80)

    import tempfile

    # Create temporary test file with issues
    temp_dir = Path(tempfile.mkdtemp())
    test_file = temp_dir / "example.py"
    test_file.write_text(
        """
import random
password = "secret123"

def bad_function():
    token = random.random()
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
    json_report = json_reporter.generate_json([report])
    print("\n📄 JSON Report (summary):")
    print(f"  Total issues: {json_report['summary']['total_issues']}")
    print(f"  High severity: {json_report['summary']['high_severity']}")

    # Cleanup
    import shutil

    shutil.rmtree(temp_dir)


def example_integrated_workflow():
    """Example: Complete workflow with all features."""
    print("\n" + "=" * 80)
    print("Example 5: Complete Integrated Workflow")
    print("=" * 80)

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
    with open(file_path) as f:
        data = yaml.load(f)
    
    hash_val = hashlib.md5(str(data).encode()).hexdigest()
    return hash_val

def complex_logic(a, b, c, d, e, f):
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

    print(f"\n🔍 Processing with correlation ID: {correlation_id[:8]}...")

    # Check cache
    if cache.is_cached(test_file):
        print("[OK] Using cached results")
        # results = cache.get(test_file)  # Cached results available but not used in this example
    else:
        print(" Analyzing file...")

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
    print("\n[OK] Workflow complete!")


if __name__ == "__main__":
    print("=" * 80)
    print("PyGuard Advanced Usage Examples")
    print("=" * 80)

    # Run all examples
    example_ast_analysis()
    example_with_caching()
    example_with_correlation()
    example_with_reporter()
    example_integrated_workflow()

    print("\n" + "=" * 80)
    print("All examples completed successfully!")
    print("=" * 80)
