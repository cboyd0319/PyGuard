"""Tests for compliance reporter."""

import json

import pytest

from pyguard.lib.compliance_reporter import ComplianceReporter


class TestComplianceReporter:
    """Test compliance reporter functionality."""

    @pytest.fixture
    def reporter(self):
        """Create a compliance reporter."""
        return ComplianceReporter()

    @pytest.fixture
    def sample_issues(self):
        """Create sample security issues."""
        return [
            {
                "file": "app.py",
                "line": 10,
                "severity": "CRITICAL",
                "rule_id": "sql-injection",
                "message": "SQL injection vulnerability detected",
            },
            {
                "file": "config.py",
                "line": 5,
                "severity": "HIGH",
                "rule_id": "hardcoded-credentials",
                "message": "Hardcoded credentials found",
            },
            {
                "file": "utils.py",
                "line": 20,
                "severity": "MEDIUM",
                "rule_id": "weak-crypto",
                "message": "Weak cryptographic algorithm",
            },
            {
                "file": "models.py",
                "line": 15,
                "severity": "HIGH",
                "rule_id": "pii-exposure",
                "message": "PII data exposure risk",
            },
        ]

    def test_generate_html_report(self, reporter, sample_issues, tmp_path):
        """Test generating HTML compliance report."""
        output_file = tmp_path / "compliance.html"

        reporter.generate_html_report(sample_issues, output_file)

        assert output_file.exists()
        content = output_file.read_text()

        # Check for key HTML elements
        assert "<!DOCTYPE html>" in content
        assert "PyGuard Compliance Report" in content
        assert "OWASP" in content
        assert "PCI-DSS" in content
        assert "CRITICAL" in content

    def test_generate_json_report(self, reporter, sample_issues, tmp_path):
        """Test generating JSON compliance report."""
        output_file = tmp_path / "compliance.json"

        reporter.generate_json_report(sample_issues, output_file)

        assert output_file.exists()

        # Parse and validate JSON
        data = json.loads(output_file.read_text())

        assert "metadata" in data
        assert "summary" in data
        assert "frameworks" in data
        assert "issues" in data

        assert data["metadata"]["tool"] == "PyGuard"
        assert data["summary"]["total_issues"] == 4
        assert len(data["issues"]) == 4

    def test_organize_by_framework(self, reporter, sample_issues):
        """Test organizing issues by compliance framework."""
        frameworks = reporter._organize_by_framework(sample_issues)

        # SQL injection should map to multiple frameworks
        assert len(frameworks["OWASP"]) > 0
        assert len(frameworks["PCI-DSS"]) > 0
        assert len(frameworks["ISO27001"]) > 0

        # PII should map to privacy frameworks
        assert len(frameworks["HIPAA"]) > 0
        assert len(frameworks["GDPR"]) > 0
        assert len(frameworks["CCPA"]) > 0

    def test_generate_summary(self, reporter, sample_issues):
        """Test generating summary statistics."""
        summary = reporter._generate_summary(sample_issues)

        assert summary["total_issues"] == 4
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 2
        assert summary["by_severity"]["MEDIUM"] == 1
        assert summary["critical_high_count"] == 3

    def test_html_report_contains_all_frameworks(self, reporter, sample_issues, tmp_path):
        """Test that HTML report includes all relevant frameworks."""
        output_file = tmp_path / "compliance.html"

        reporter.generate_html_report(sample_issues, output_file, framework="ALL")

        content = output_file.read_text()

        # Check for framework sections
        frameworks = ["OWASP", "PCI-DSS", "HIPAA", "SOC2", "ISO27001", "NIST", "GDPR"]
        for framework in frameworks:
            # Framework name should appear in the report
            assert framework in content

    def test_html_report_includes_severity_badges(self, reporter, sample_issues, tmp_path):
        """Test that HTML report includes severity badges."""
        output_file = tmp_path / "compliance.html"

        reporter.generate_html_report(sample_issues, output_file)

        content = output_file.read_text()

        # Check for severity classes
        assert "badge critical" in content.lower()
        assert "badge high" in content.lower()
        assert "badge medium" in content.lower()

    def test_json_report_structure(self, reporter, sample_issues, tmp_path):
        """Test JSON report has correct structure."""
        output_file = tmp_path / "compliance.json"

        reporter.generate_json_report(sample_issues, output_file)

        data = json.loads(output_file.read_text())

        # Check metadata structure
        assert "generated_at" in data["metadata"]
        assert "tool" in data["metadata"]
        assert "version" in data["metadata"]

        # Check summary structure
        assert "total_issues" in data["summary"]
        assert "by_severity" in data["summary"]
        assert "critical_high_count" in data["summary"]

        # Check frameworks structure
        assert isinstance(data["frameworks"], dict)
        for framework_name, framework_issues in data["frameworks"].items():
            assert isinstance(framework_issues, list)

    def test_empty_issues_list(self, reporter, tmp_path):
        """Test handling empty issues list."""
        output_file = tmp_path / "compliance.html"

        reporter.generate_html_report([], output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "0 issues" in content or "Total Issues:</strong> 0" in content

    def test_html_report_css_styling(self, reporter, sample_issues, tmp_path):
        """Test that HTML report includes CSS styling."""
        output_file = tmp_path / "compliance.html"

        reporter.generate_html_report(sample_issues, output_file)

        content = output_file.read_text()

        # Check for CSS
        assert "<style>" in content
        assert "font-family" in content
        assert "color:" in content

    def test_framework_deduplication(self, reporter):
        """Test that duplicate issues in frameworks are removed."""
        duplicate_issues = [
            {
                "file": "app.py",
                "line": 10,
                "severity": "HIGH",
                "rule_id": "sql-injection",
                "message": "SQL injection",
            },
            {
                "file": "app.py",
                "line": 10,
                "severity": "HIGH",
                "rule_id": "sql-injection",
                "message": "SQL injection",
            },
        ]

        frameworks = reporter._organize_by_framework(duplicate_issues)

        # Should have only 1 unique issue per framework
        for framework_issues in frameworks.values():
            if framework_issues:
                # Count should be reasonable (not doubled)
                assert len(framework_issues) <= 1

    def test_severity_mapping(self, reporter):
        """Test that different severities are properly counted."""
        issues = [
            {"severity": "CRITICAL", "rule_id": "test1", "file": "a.py", "line": 1, "message": "Test"},
            {"severity": "HIGH", "rule_id": "test2", "file": "b.py", "line": 2, "message": "Test"},
            {"severity": "MEDIUM", "rule_id": "test3", "file": "c.py", "line": 3, "message": "Test"},
            {"severity": "LOW", "rule_id": "test4", "file": "d.py", "line": 4, "message": "Test"},
            {"severity": "INFO", "rule_id": "test5", "file": "e.py", "line": 5, "message": "Test"},
        ]

        summary = reporter._generate_summary(issues)

        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["MEDIUM"] == 1
        assert summary["by_severity"]["LOW"] == 1
        assert summary["by_severity"]["INFO"] == 1
