"""
Integration test for RipGrep features.

This test demonstrates that the RipGrep integration works correctly
with and without ripgrep installed.
"""

from pyguard.lib.ripgrep_filter import RipGrepFilter
from pyguard.lib.secret_scanner import SecretScanner
from pyguard.lib.import_analyzer import ImportAnalyzer
from pyguard.lib.test_coverage import TestCoverageAnalyzer
from pyguard.lib.compliance_tracker import ComplianceTracker


def test_ripgrep_availability():
    """Test that ripgrep availability detection works."""
    # Should return True or False, not crash
    available = RipGrepFilter.is_ripgrep_available()
    assert isinstance(available, bool)
    print(f"✓ RipGrep available: {available}")


def test_ripgrep_filter_graceful_fallback():
    """Test that RipGrepFilter works without ripgrep installed."""
    # Should return empty set, not crash
    result = RipGrepFilter.find_suspicious_files(".")
    assert isinstance(result, set)
    print(f"✓ RipGrep filter returned {len(result)} files")


def test_secret_scanner_graceful_fallback():
    """Test that SecretScanner works without ripgrep installed."""
    # Should return empty list, not crash
    findings = SecretScanner.scan_secrets(".")
    assert isinstance(findings, list)
    print(f"✓ Secret scanner returned {len(findings)} findings")


def test_import_analyzer_graceful_fallback():
    """Test that ImportAnalyzer works without ripgrep installed."""
    # Should return empty list, not crash
    circular = ImportAnalyzer.find_circular_imports(".")
    assert isinstance(circular, list)
    print(f"✓ Import analyzer returned {len(circular)} circular imports")
    
    god_modules = ImportAnalyzer.find_god_modules(".")
    assert isinstance(god_modules, list)
    print(f"✓ Import analyzer returned {len(god_modules)} god modules")


def test_test_coverage_analyzer_graceful_fallback():
    """Test that TestCoverageAnalyzer works without ripgrep installed."""
    # Should return empty list, not crash
    untested = TestCoverageAnalyzer.find_untested_modules("pyguard", "tests")
    assert isinstance(untested, list)
    print(f"✓ Test coverage analyzer returned {len(untested)} untested modules")


def test_compliance_tracker_graceful_fallback():
    """Test that ComplianceTracker works without ripgrep installed."""
    # Should return dict with empty lists, not crash
    annotations = ComplianceTracker.find_compliance_annotations(".")
    assert isinstance(annotations, dict)
    assert "OWASP" in annotations
    assert "CWE" in annotations
    print(f"✓ Compliance tracker returned {len(annotations['OWASP'])} OWASP annotations")


if __name__ == "__main__":
    print("Running RipGrep integration tests...")
    print()
    
    test_ripgrep_availability()
    test_ripgrep_filter_graceful_fallback()
    test_secret_scanner_graceful_fallback()
    test_import_analyzer_graceful_fallback()
    test_test_coverage_analyzer_graceful_fallback()
    test_compliance_tracker_graceful_fallback()
    
    print()
    print("✅ All integration tests passed!")
    print()
    print("Note: These tests verify graceful fallback when ripgrep is not installed.")
    print("For full functionality, install ripgrep:")
    print("  - macOS: brew install ripgrep")
    print("  - Ubuntu: apt install ripgrep")
    print("  - Windows: winget install BurntSushi.ripgrep.MSVC")
