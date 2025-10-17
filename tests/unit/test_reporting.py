"""
Tests for reporting module.
"""

import json
from pathlib import Path

import pytest

from pyguard.lib.reporting import AnalysisMetrics, ConsoleReporter, JSONReporter, HTMLReporter


class TestAnalysisMetrics:
    """Test AnalysisMetrics dataclass."""

    def test_metrics_creation(self):
        """Test creating metrics object."""
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=9,
            files_with_issues=5,
            files_fixed=3,
            total_issues=15,
            security_issues=8,
            quality_issues=7,
            fixes_applied=10,
            analysis_time_seconds=5.5,
            avg_time_per_file_ms=611.1,
        )

        assert metrics.total_files == 10
        assert metrics.files_analyzed == 9
        assert metrics.files_with_issues == 5
        assert metrics.files_fixed == 3
        assert metrics.total_issues == 15
        assert metrics.security_issues == 8
        assert metrics.quality_issues == 7
        assert metrics.fixes_applied == 10
        assert metrics.analysis_time_seconds == 5.5
        assert metrics.avg_time_per_file_ms == 611.1


class TestConsoleReporter:
    """Test ConsoleReporter functionality."""

    def test_initialization_with_color(self):
        """Test reporter initialization with colors."""
        reporter = ConsoleReporter(use_color=True)
        assert reporter.use_color is True
        assert reporter.COLORS["RED"] != ""
        assert reporter.COLORS["GREEN"] != ""

    def test_initialization_without_color(self):
        """Test reporter initialization without colors."""
        reporter = ConsoleReporter(use_color=False)
        assert reporter.use_color is False
        assert reporter.COLORS["RED"] == ""
        assert reporter.COLORS["GREEN"] == ""

    def test_print_header(self, capsys):
        """Test printing header."""
        reporter = ConsoleReporter(use_color=False)
        reporter.print_header("Test Header")

        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert "=" in captured.out

    def test_print_section(self, capsys):
        """Test printing section."""
        reporter = ConsoleReporter(use_color=False)
        reporter.print_section("Test Section")

        captured = capsys.readouterr()
        assert "Test Section" in captured.out
        assert "-" in captured.out

    def test_print_metric(self, capsys):
        """Test printing metric."""
        reporter = ConsoleReporter(use_color=False)
        reporter.print_metric("Test Label", "Test Value", "GREEN")

        captured = capsys.readouterr()
        assert "Test Label" in captured.out
        assert "Test Value" in captured.out

    def test_print_summary(self, capsys):
        """Test printing full summary."""
        reporter = ConsoleReporter(use_color=False)
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=9,
            files_with_issues=5,
            files_fixed=3,
            total_issues=15,
            security_issues=8,
            quality_issues=7,
            fixes_applied=10,
            analysis_time_seconds=5.5,
            avg_time_per_file_ms=611.1,
        )

        reporter.print_summary(metrics)

        captured = capsys.readouterr()
        assert "PyGuard Analysis Summary" in captured.out
        assert "Total files" in captured.out
        assert "Security issues" in captured.out
        assert "10" in captured.out
        assert "15" in captured.out


class TestJSONReporter:
    """Test JSONReporter functionality."""

    def test_initialization(self):
        """Test JSON reporter initialization."""
        reporter = JSONReporter()
        assert reporter is not None

    def test_generate_report(self):
        """Test generating JSON report."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=5,
            files_analyzed=5,
            files_with_issues=2,
            files_fixed=1,
            total_issues=8,
            security_issues=3,
            quality_issues=5,
            fixes_applied=4,
            analysis_time_seconds=2.5,
            avg_time_per_file_ms=500.0,
        )

        issues = [
            {
                "file": "test.py",
                "line": 10,
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "Test issue",
            }
        ]

        fixes = [
            {
                "file": "test.py",
                "fix_type": "SQL_INJECTION_FIX",
                "description": "Changed to parameterized query",
            }
        ]

        report = reporter.generate_report(metrics, issues, fixes)

        assert "summary" in report
        assert "issues" in report
        assert "fixes" in report
        assert "generated_at" in report
        assert report["summary"]["total_files"] == 5
        assert report["summary"]["security_issues"] == 3
        assert len(report["issues"]) == 1
        assert len(report["fixes"]) == 1

    def test_save_report(self, tmp_path):
        """Test saving JSON report to file."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=1,
            files_analyzed=1,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=1000.0,
        )

        report = reporter.generate_report(metrics, [], [])
        output_file = tmp_path / "report.json"

        reporter.save_report(report, output_file)

        assert output_file.exists()

        # Verify file content
        with open(output_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            assert "summary" in loaded
            assert "issues" in loaded
            assert "fixes" in loaded


class TestHTMLReporter:
    """Test HTMLReporter functionality."""

    def test_initialization(self):
        """Test HTML reporter initialization."""
        reporter = HTMLReporter()
        assert reporter is not None

    def test_generate_report(self):
        """Test generating HTML report."""
        reporter = HTMLReporter()
        metrics = AnalysisMetrics(
            total_files=5,
            files_analyzed=5,
            files_with_issues=2,
            files_fixed=1,
            total_issues=8,
            security_issues=3,
            quality_issues=5,
            fixes_applied=4,
            analysis_time_seconds=2.5,
            avg_time_per_file_ms=500.0,
        )

        issues = [
            {
                "file": "test.py",
                "line": 10,
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "Test issue",
                "fix_suggestion": "Use parameterized queries",
            }
        ]

        fixes = [
            {
                "file": "test.py",
                "fix_type": "SQL_INJECTION_FIX",
                "description": "Changed to parameterized query",
            }
        ]

        html = reporter.generate_report(metrics, issues, fixes)

        assert "<html" in html.lower()
        assert "PyGuard" in html
        assert "SQL Injection" in html
        assert "test.py" in html
        assert "HIGH" in html

    def test_save_report(self, tmp_path):
        """Test saving HTML report to file."""
        reporter = HTMLReporter()
        metrics = AnalysisMetrics(
            total_files=1,
            files_analyzed=1,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=1000.0,
        )

        html = reporter.generate_report(metrics, [], [])
        output_file = tmp_path / "report.html"

        reporter.save_report(html, output_file)

        assert output_file.exists()

        # Verify file content
        with open(output_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "<html" in content.lower()
            assert "PyGuard" in content

    def test_html_has_severity_colors(self):
        """Test that HTML report includes severity-based styling."""
        reporter = HTMLReporter()
        metrics = AnalysisMetrics(
            total_files=3,
            files_analyzed=3,
            files_with_issues=3,
            files_fixed=0,
            total_issues=3,
            security_issues=3,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=333.0,
        )

        issues = [
            {
                "file": "test1.py",
                "line": 1,
                "severity": "HIGH",
                "category": "Test",
                "message": "High issue",
            },
            {
                "file": "test2.py",
                "line": 2,
                "severity": "MEDIUM",
                "category": "Test",
                "message": "Medium issue",
            },
            {
                "file": "test3.py",
                "line": 3,
                "severity": "LOW",
                "category": "Test",
                "message": "Low issue",
            },
        ]

        html = reporter.generate_report(metrics, issues, [])

        # Should contain all three issues
        assert "High issue" in html
        assert "Medium issue" in html
        assert "Low issue" in html
        assert "HIGH" in html
        assert "MEDIUM" in html
        assert "LOW" in html

    def test_empty_issues_report(self):
        """Test generating report with no issues."""
        reporter = HTMLReporter()
        metrics = AnalysisMetrics(
            total_files=5,
            files_analyzed=5,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=200.0,
        )

        html = reporter.generate_report(metrics, [], [])

        assert "<html" in html.lower()
        assert "PyGuard" in html
        # Should indicate no issues found
        assert "0" in html


class TestConsoleReporterAdvanced:
    """Advanced tests for ConsoleReporter edge cases."""

    def test_print_summary_no_issues(self, capsys):
        """Test printing summary when no issues found."""
        reporter = ConsoleReporter(use_color=False)
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=100.0,
        )

        reporter.print_summary(metrics)

        captured = capsys.readouterr()
        assert "[OK] No issues found" in captured.out or "clean" in captured.out.lower()

    def test_print_summary_with_fixes(self, capsys):
        """Test printing summary when fixes were applied."""
        reporter = ConsoleReporter(use_color=False)
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=5,
            files_fixed=5,
            total_issues=10,
            security_issues=5,
            quality_issues=5,
            fixes_applied=8,
            analysis_time_seconds=2.0,
            avg_time_per_file_ms=200.0,
        )

        reporter.print_summary(metrics)

        captured = capsys.readouterr()
        assert "fixes applied" in captured.out.lower() or "8" in captured.out

    def test_print_summary_without_fixes(self, capsys):
        """Test printing summary when issues found but no fixes."""
        reporter = ConsoleReporter(use_color=False)
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=5,
            files_fixed=0,
            total_issues=10,
            security_issues=5,
            quality_issues=5,
            fixes_applied=0,
            analysis_time_seconds=2.0,
            avg_time_per_file_ms=200.0,
        )

        reporter.print_summary(metrics)

        captured = capsys.readouterr()
        assert "Issues found" in captured.out or "--fix" in captured.out

    def test_print_issue_details(self, capsys):
        """Test printing individual issue details."""
        reporter = ConsoleReporter(use_color=False)
        
        reporter.print_issue_details(
            severity="HIGH",
            category="Security",
            message="SQL injection vulnerability",
            file_path="test.py",
            line_number=42,
            fix_suggestion="Use parameterized queries"
        )

        captured = capsys.readouterr()
        assert "HIGH" in captured.out
        assert "Security" in captured.out
        assert "SQL injection" in captured.out
        assert "test.py" in captured.out
        assert "42" in captured.out
        assert "Use parameterized queries" in captured.out

    def test_print_issue_details_no_fix(self, capsys):
        """Test printing issue details without fix suggestion."""
        reporter = ConsoleReporter(use_color=False)
        
        reporter.print_issue_details(
            severity="MEDIUM",
            category="Style",
            message="Line too long",
            file_path="long.py",
            line_number=10,
            fix_suggestion=None
        )

        captured = capsys.readouterr()
        assert "MEDIUM" in captured.out
        assert "Style" in captured.out
        assert "Line too long" in captured.out
        # Should not crash with None fix_suggestion


class TestJSONReporterAdvanced:
    """Advanced tests for JSONReporter edge cases."""

    def test_get_status_passed(self):
        """Test status determination when no issues."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=100.0,
        )

        status = reporter._get_status(metrics)
        assert status == "passed"

    def test_get_status_failed_security(self):
        """Test status determination when security issues exist."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=5,
            files_fixed=0,
            total_issues=10,
            security_issues=5,
            quality_issues=5,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=100.0,
        )

        status = reporter._get_status(metrics)
        assert status == "failed_security"

    def test_get_status_warning(self):
        """Test status determination when only quality issues exist."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=10,
            files_analyzed=10,
            files_with_issues=3,
            files_fixed=0,
            total_issues=5,
            security_issues=0,
            quality_issues=5,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=100.0,
        )

        status = reporter._get_status(metrics)
        assert status == "warning"

    def test_save_report_error_handling(self, tmp_path, monkeypatch):
        """Test save report handles write errors gracefully."""
        reporter = JSONReporter()
        metrics = AnalysisMetrics(
            total_files=1,
            files_analyzed=1,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=1000.0,
        )

        report = reporter.generate_report(metrics, [], [])
        
        # Try to write to a directory (should fail)
        output_dir = tmp_path / "subdir"
        output_dir.mkdir()
        
        # Should handle error gracefully, not crash
        reporter.save_report(report, output_dir)  # Trying to write to a directory


class TestHTMLReporterAdvanced:
    """Advanced tests for HTMLReporter edge cases."""

    def test_save_report_error_handling(self, tmp_path):
        """Test save report handles write errors gracefully."""
        reporter = HTMLReporter()
        metrics = AnalysisMetrics(
            total_files=1,
            files_analyzed=1,
            files_with_issues=0,
            files_fixed=0,
            total_issues=0,
            security_issues=0,
            quality_issues=0,
            fixes_applied=0,
            analysis_time_seconds=1.0,
            avg_time_per_file_ms=1000.0,
        )

        html = reporter.generate_report(metrics, [], [])
        
        # Try to write to a directory (should fail)
        output_dir = tmp_path / "subdir"
        output_dir.mkdir()
        
        # Should handle error gracefully, not crash
        reporter.save_report(html, output_dir)  # Trying to write to a directory
