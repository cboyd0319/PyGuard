"""
Unit tests for Compliance Tracker module.
"""

import subprocess
from unittest.mock import MagicMock, mock_open, patch

from pyguard.lib.compliance_tracker import ComplianceTracker


class TestComplianceTracker:
    """Test ComplianceTracker functionality."""

    def test_find_compliance_annotations_with_owasp(self):
        """Test finding OWASP references in code."""
        with patch("subprocess.run") as mock_run:
            # First call for OWASP, second for CWE
            mock_run.side_effect = [
                MagicMock(
                    stdout="src/auth.py:10:OWASP-ASVS-4.1\nsrc/crypto.py:25:OWASP Top 10 A3\n"
                ),
                MagicMock(stdout=""),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            assert len(result["OWASP"]) == 2
            assert result["OWASP"][0]["file"] == "src/auth.py"
            assert result["OWASP"][0]["line"] == 10
            assert "OWASP" in result["OWASP"][0]["reference"]

    def test_find_compliance_annotations_with_cwe(self):
        """Test finding CWE references in code."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout=""),
                MagicMock(stdout="src/sql.py:42:CWE-89\nsrc/xss.py:15:CWE-79\n"),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            assert len(result["CWE"]) == 2
            assert result["CWE"][0]["file"] == "src/sql.py"
            assert result["CWE"][0]["line"] == 42
            assert "CWE-89" in result["CWE"][0]["reference"]

    def test_find_compliance_annotations_no_results(self):
        """Test when no compliance annotations are found."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout=""),
                MagicMock(stdout=""),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            assert len(result["OWASP"]) == 0
            assert len(result["CWE"]) == 0

    def test_find_compliance_annotations_with_empty_lines(self):
        """Test handling of empty lines and malformed lines in CWE results."""
        with patch("subprocess.run") as mock_run:
            # Include empty lines and malformed lines (not enough colons)
            mock_run.side_effect = [
                MagicMock(stdout=""),
                MagicMock(stdout="src/sql.py:42:CWE-89\nmalformed\nsrc/xss.py:15:CWE-79\n"),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            # Should correctly handle empty lines, malformed lines, and extract both valid annotations
            assert len(result["CWE"]) == 2
            assert result["CWE"][0]["file"] == "src/sql.py"
            assert result["CWE"][1]["file"] == "src/xss.py"

    def test_find_compliance_annotations_timeout(self):
        """Test handling timeout during annotation search."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("rg", 60)):
            result = ComplianceTracker.find_compliance_annotations("/test/path")

            # Should return empty annotations
            assert result == {"OWASP": [], "CWE": [], "NIST": [], "PCI-DSS": []}

    def test_find_compliance_annotations_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = ComplianceTracker.find_compliance_annotations("/test/path")

            assert result == {"OWASP": [], "CWE": [], "NIST": [], "PCI-DSS": []}

    def test_generate_compliance_report(self):
        """Test generating compliance report file."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout="src/auth.py:10:OWASP-ASVS-4.1\n"),
                MagicMock(stdout="src/sql.py:42:CWE-89\n"),
            ]

            m = mock_open()  # Best Practice: Use 'with' statement  # Best Practice: Use 'with' statement
            with patch("builtins.open", m):
                ComplianceTracker.generate_compliance_report("/test/path", "test-report.md")

            # Verify file was opened for writing
            m.assert_called_once_with("test-report.md", "w")

            # Get written content
            handle = m()
            written_calls = [call.args[0] for call in handle.write.call_args_list]
            written_content = "".join(written_calls)

            # Verify report structure
            assert "# PyGuard Compliance Report" in written_content
            assert "## OWASP References" in written_content
            assert "## CWE References" in written_content

    def test_generate_compliance_report_with_counts(self):
        """Test that compliance report includes counts."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout="src/a.py:1:OWASP-1\nsrc/b.py:2:OWASP-2\nsrc/c.py:3:OWASP-3\n"),
                MagicMock(stdout="src/d.py:4:CWE-79\nsrc/e.py:5:CWE-89\n"),
            ]

            m = mock_open()  # Best Practice: Use 'with' statement  # Best Practice: Use 'with' statement
            with patch("builtins.open", m):
                ComplianceTracker.generate_compliance_report("/test/path")

            handle = m()
            written_content = "".join(call.args[0] for call in handle.write.call_args_list)

            # Should show counts
            assert "(3)" in written_content  # 3 OWASP
            assert "(2)" in written_content  # 2 CWE

    def test_find_compliance_annotations_malformed_line(self):
        """Test handling malformed output lines."""
        with patch("subprocess.run") as mock_run:
            # Some lines without proper format
            mock_run.side_effect = [
                MagicMock(stdout="malformed_line\nsrc/auth.py:10:OWASP-ASVS-4.1\n"),
                MagicMock(stdout=""),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            # Should only parse valid lines
            assert len(result["OWASP"]) == 1
            assert result["OWASP"][0]["file"] == "src/auth.py"

    def test_generate_compliance_report_default_output_path(self):
        """Test compliance report generation with default output path."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [MagicMock(stdout=""), MagicMock(stdout="")]

            m = mock_open()  # Best Practice: Use 'with' statement  # Best Practice: Use 'with' statement
            with patch("builtins.open", m):
                ComplianceTracker.generate_compliance_report("/test/path")

            # Should use default filename
            m.assert_called_once_with("compliance-report.md", "w")

    def test_find_compliance_annotations_structure(self):
        """Test the structure of returned annotations."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout="src/test.py:5:OWASP-A1\n"),
                MagicMock(stdout="src/test.py:10:CWE-79\n"),
            ]

            result = ComplianceTracker.find_compliance_annotations("/test/path")

            # Verify all expected keys exist
            assert "OWASP" in result
            assert "CWE" in result
            assert "NIST" in result
            assert "PCI-DSS" in result

            # Verify annotation structure
            if result["OWASP"]:
                ann = result["OWASP"][0]
                assert "file" in ann
                assert "line" in ann
                assert "reference" in ann
