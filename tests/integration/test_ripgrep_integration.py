"""
Integration test for RipGrep features.

This test demonstrates that the RipGrep integration works correctly
with and without ripgrep installed.
"""

from pyguard.lib.compliance_tracker import ComplianceTracker
from pyguard.lib.import_analyzer import ImportAnalyzer
from pyguard.lib.ripgrep_filter import RipGrepFilter
from pyguard.lib.secret_scanner import SecretScanner
from pyguard.lib.test_coverage import TestCoverageAnalyzer


def test_ripgrep_availability():
    """Test that ripgrep availability detection works."""
    # Should return True or False, not crash
    available = RipGrepFilter.is_ripgrep_available()
    assert isinstance(available, bool)


def test_ripgrep_filter_graceful_fallback():
    """Test that RipGrepFilter works without ripgrep installed."""
    # Should return empty set, not crash
    result = RipGrepFilter.find_suspicious_files(".")
    assert isinstance(result, set)


def test_secret_scanner_graceful_fallback():
    """Test that SecretScanner works without ripgrep installed."""
    # Should return empty list, not crash
    findings = SecretScanner.scan_secrets(".")
    assert isinstance(findings, list)


def test_import_analyzer_graceful_fallback():
    """Test that ImportAnalyzer works without ripgrep installed."""
    # Should return empty list, not crash
    circular = ImportAnalyzer.find_circular_imports(".")
    assert isinstance(circular, list)

    god_modules = ImportAnalyzer.find_god_modules(".")
    assert isinstance(god_modules, list)


def test_test_coverage_analyzer_graceful_fallback():
    """Test that TestCoverageAnalyzer works without ripgrep installed."""
    # Should return empty list, not crash
    untested = TestCoverageAnalyzer.find_untested_modules("pyguard", "tests")
    assert isinstance(untested, list)


def test_compliance_tracker_graceful_fallback():
    """Test that ComplianceTracker works without ripgrep installed."""
    # Should return dict with empty lists, not crash
    annotations = ComplianceTracker.find_compliance_annotations(".")
    assert isinstance(annotations, dict)
    assert "OWASP" in annotations
    assert "CWE" in annotations


if __name__ == "__main__":
    test_ripgrep_availability()
    test_ripgrep_filter_graceful_fallback()
    test_secret_scanner_graceful_fallback()
    test_import_analyzer_graceful_fallback()
    test_test_coverage_analyzer_graceful_fallback()
    test_compliance_tracker_graceful_fallback()
