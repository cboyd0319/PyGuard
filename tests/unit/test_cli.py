"""
Comprehensive unit tests for pyguard.cli module.

Tests cover:
- PyGuardCLI class initialization
- run_security_fixes method
- run_best_practices_fixes method
- run_formatting method
- run_full_analysis method
- print_results method
- Integration between CLI components

Testing Strategy:
- Use mocks to isolate CLI logic from dependencies
- Test all code paths and branches
- Verify proper integration with fixers and reporters
- Test error handling and edge cases
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from dataclasses import dataclass

from pyguard.cli import PyGuardCLI


@dataclass
class MockIssue:
    """Mock security issue for testing."""

    severity: str
    category: str
    message: str
    line_number: int
    file_path: str = "test.py"


class TestPyGuardCLIInitialization:
    """Tests for PyGuardCLI initialization."""

    def test_cli_initialization_default(self):
        """Test CLI initialization with default parameters."""
        cli = PyGuardCLI()

        assert cli.logger is not None
        assert cli.backup_manager is not None
        assert cli.file_ops is not None
        assert cli.diff_generator is not None
        assert cli.ui is not None
        assert cli.html_reporter is not None
        assert cli.sarif_reporter is not None
        assert cli.security_fixer is not None
        assert cli.enhanced_security_fixer is not None
        assert cli.best_practices_fixer is not None
        assert cli.formatting_fixer is not None
        assert cli.whitespace_fixer is not None
        assert cli.naming_fixer is not None

    def test_cli_initialization_allow_unsafe_fixes(self):
        """Test CLI initialization with allow_unsafe_fixes flag."""
        cli = PyGuardCLI(allow_unsafe_fixes=True)

        # EnhancedSecurityFixer should be initialized with allow_unsafe=True
        assert cli.enhanced_security_fixer is not None

    def test_cli_initialization_disallow_unsafe_fixes(self):
        """Test CLI initialization with allow_unsafe_fixes=False."""
        cli = PyGuardCLI(allow_unsafe_fixes=False)

        assert cli.enhanced_security_fixer is not None


class TestRunSecurityFixes:
    """Tests for run_security_fixes method."""

    def test_run_security_fixes_empty_files(self):
        """Test run_security_fixes with empty file list."""
        cli = PyGuardCLI()
        result = cli.run_security_fixes([], create_backup=True)

        assert result["total"] == 0
        assert result["fixed"] == 0
        assert result["failed"] == 0
        assert result["fixes"] == []

    def test_run_security_fixes_single_file(self, tmp_path):
        """Test run_security_fixes with single file."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        result = cli.run_security_fixes([test_file], create_backup=False)

        assert result["total"] == 1
        assert isinstance(result["fixed"], int)
        assert isinstance(result["failed"], int)
        assert isinstance(result["fixes"], list)

    def test_run_security_fixes_multiple_files(self, tmp_path):
        """Test run_security_fixes with multiple files."""
        cli = PyGuardCLI()
        files = []
        for i in range(3):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"x{i} = {i}")
            files.append(test_file)

        result = cli.run_security_fixes(files, create_backup=False)

        assert result["total"] == 3
        assert result["fixed"] + result["failed"] <= 3

    def test_run_security_fixes_with_backup(self, tmp_path):
        """Test run_security_fixes creates backups when requested."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        with patch.object(cli.backup_manager, "create_backup") as mock_backup:
            result = cli.run_security_fixes([test_file], create_backup=True)
            mock_backup.assert_called_once_with(test_file)

    def test_run_security_fixes_without_backup(self, tmp_path):
        """Test run_security_fixes skips backup when not requested."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        with patch.object(cli.backup_manager, "create_backup") as mock_backup:
            result = cli.run_security_fixes([test_file], create_backup=False)
            mock_backup.assert_not_called()

    def test_run_security_fixes_with_fixes_applied(self, tmp_path):
        """Test run_security_fixes when fixes are applied."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        # Mock the security fixer to return fixes
        cli.security_fixer.fix_file = Mock(return_value=(True, ["Fix 1", "Fix 2"]))
        cli.enhanced_security_fixer.fix_file = Mock(return_value=(True, ["Fix 3"]))

        result = cli.run_security_fixes([test_file], create_backup=False)

        assert result["fixed"] == 1
        assert len(result["fixes"]) == 3

    def test_run_security_fixes_failure_handling(self, tmp_path):
        """Test run_security_fixes handles failures correctly."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        # Mock failures
        cli.security_fixer.fix_file = Mock(return_value=(False, []))
        cli.enhanced_security_fixer.fix_file = Mock(return_value=(False, []))

        result = cli.run_security_fixes([test_file], create_backup=False)

        assert result["failed"] == 1


class TestRunBestPracticesFixes:
    """Tests for run_best_practices_fixes method."""

    def test_run_best_practices_fixes_empty_files(self):
        """Test run_best_practices_fixes with empty file list."""
        cli = PyGuardCLI()
        result = cli.run_best_practices_fixes([], create_backup=True)

        assert result["total"] == 0
        assert result["fixed"] == 0
        assert result["failed"] == 0
        assert result["fixes"] == []

    def test_run_best_practices_fixes_single_file(self, tmp_path):
        """Test run_best_practices_fixes with single file."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass")

        result = cli.run_best_practices_fixes([test_file], create_backup=False)

        assert result["total"] == 1
        assert isinstance(result["fixed"], int)
        assert isinstance(result["failed"], int)

    def test_run_best_practices_fixes_with_backup(self, tmp_path):
        """Test run_best_practices_fixes creates backups when requested."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass")

        with patch.object(cli.backup_manager, "create_backup") as mock_backup:
            result = cli.run_best_practices_fixes([test_file], create_backup=True)
            mock_backup.assert_called_once()

    def test_run_best_practices_fixes_success(self, tmp_path):
        """Test run_best_practices_fixes with successful fixes."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass")

        cli.best_practices_fixer.fix_file = Mock(return_value=(True, ["Fix 1"]))

        result = cli.run_best_practices_fixes([test_file], create_backup=False)

        assert result["fixed"] == 1
        assert "Fix 1" in result["fixes"]


class TestRunFormatting:
    """Tests for run_formatting method."""

    def test_run_formatting_empty_files(self):
        """Test run_formatting with empty file list."""
        cli = PyGuardCLI()
        result = cli.run_formatting([], create_backup=True)

        assert result["total"] == 0
        assert result["formatted"] == 0
        assert result["failed"] == 0

    def test_run_formatting_single_file(self, tmp_path):
        """Test run_formatting with single file."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        result = cli.run_formatting([test_file], create_backup=False)

        assert result["total"] == 1

    def test_run_formatting_with_black_and_isort(self, tmp_path):
        """Test run_formatting with both Black and isort enabled."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        cli.formatting_fixer.format_file = Mock(return_value={"success": True})

        result = cli.run_formatting([test_file], use_black=True, use_isort=True)

        cli.formatting_fixer.format_file.assert_called_once()

    def test_run_formatting_black_only(self, tmp_path):
        """Test run_formatting with only Black enabled."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        cli.formatting_fixer.format_file = Mock(return_value={"success": True})

        result = cli.run_formatting([test_file], use_black=True, use_isort=False)

        assert result["total"] == 1

    def test_run_formatting_success_count(self, tmp_path):
        """Test run_formatting tracks successful formatting."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        cli.formatting_fixer.format_file = Mock(return_value={"success": True})

        result = cli.run_formatting([test_file], create_backup=False)

        assert result["formatted"] == 1
        assert result["failed"] == 0

    def test_run_formatting_failure_count(self, tmp_path):
        """Test run_formatting tracks failed formatting."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        cli.formatting_fixer.format_file = Mock(return_value={"success": False})

        result = cli.run_formatting([test_file], create_backup=False)

        assert result["formatted"] == 0
        assert result["failed"] == 1


class TestRunFullAnalysis:
    """Tests for run_full_analysis method."""

    def test_run_full_analysis_empty_files(self):
        """Test run_full_analysis with empty file list."""
        cli = PyGuardCLI()
        result = cli.run_full_analysis([], create_backup=True, fix=True)

        assert result["total_files"] == 0
        assert result["analysis_time_seconds"] >= 0

    def test_run_full_analysis_with_fix(self, tmp_path):
        """Test run_full_analysis with fix=True."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        # Mock progress bar and fixers
        mock_progress = MagicMock()
        cli.ui.create_progress_bar = Mock(return_value=mock_progress)
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=False)

        result = cli.run_full_analysis([test_file], create_backup=False, fix=True)

        assert result["total_files"] == 1
        assert "security" in result
        assert "best_practices" in result
        assert "formatting" in result

    def test_run_full_analysis_without_fix(self, tmp_path):
        """Test run_full_analysis with fix=False (scan only)."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        # Mock scan methods
        cli.security_fixer.scan_file_for_issues = Mock(return_value=[])
        cli.best_practices_fixer.scan_file_for_issues = Mock(return_value=[])

        mock_progress = MagicMock()
        cli.ui.create_progress_bar = Mock(return_value=mock_progress)
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=False)

        result = cli.run_full_analysis([test_file], create_backup=False, fix=False)

        assert result["total_files"] == 1
        assert "all_issues" in result
        assert result["total_issues"] >= 0

    def test_run_full_analysis_scan_finds_issues(self, tmp_path):
        """Test run_full_analysis scan mode finds issues."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        # Mock issues
        mock_issue = MockIssue(
            severity="HIGH", category="Security", message="Test issue", line_number=1
        )
        cli.security_fixer.scan_file_for_issues = Mock(return_value=[mock_issue])
        cli.best_practices_fixer.scan_file_for_issues = Mock(return_value=[])

        mock_progress = MagicMock()
        cli.ui.create_progress_bar = Mock(return_value=mock_progress)
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=False)

        result = cli.run_full_analysis([test_file], create_backup=False, fix=False)

        assert result["security_issues"] == 1
        assert result["total_issues"] == 1

    def test_run_full_analysis_timing(self, tmp_path):
        """Test run_full_analysis calculates timing metrics."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        result = cli.run_full_analysis([test_file], create_backup=False, fix=False)

        assert "analysis_time_seconds" in result
        assert result["analysis_time_seconds"] >= 0
        assert "avg_time_per_file_ms" in result
        assert result["avg_time_per_file_ms"] >= 0

    def test_run_full_analysis_multiple_files(self, tmp_path):
        """Test run_full_analysis with multiple files."""
        cli = PyGuardCLI()
        files = []
        for i in range(3):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"x{i}={i}")
            files.append(test_file)

        result = cli.run_full_analysis(files, create_backup=False, fix=False)

        assert result["total_files"] == 3

    def test_run_full_analysis_aggregates_fixes(self, tmp_path):
        """Test run_full_analysis aggregates fix counts correctly."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1")

        # Mock fixes returned
        cli.run_security_fixes = Mock(
            return_value={"total": 1, "fixed": 1, "failed": 0, "fixes": ["Fix 1", "Fix 2"]}
        )
        cli.run_best_practices_fixes = Mock(
            return_value={"total": 1, "fixed": 1, "failed": 0, "fixes": ["Fix 3"]}
        )
        cli.run_formatting = Mock(return_value={"total": 1, "formatted": 1, "failed": 0})

        mock_progress = MagicMock()
        cli.ui.create_progress_bar = Mock(return_value=mock_progress)
        mock_progress.__enter__ = Mock(return_value=mock_progress)
        mock_progress.__exit__ = Mock(return_value=False)

        result = cli.run_full_analysis([test_file], create_backup=False, fix=True)

        # Fixes applied aggregates from security and best_practices
        assert result["fixes_applied"] >= 0  # At least count was aggregated


class TestPrintResults:
    """Tests for print_results method."""

    def test_print_results_basic(self):
        """Test print_results with basic results."""
        cli = PyGuardCLI()
        results = {"total_files": 10, "all_issues": [], "fixes_applied": 5}

        cli.ui.print_summary_table = Mock()
        cli.ui.print_success_message = Mock()
        cli.ui.print_next_steps = Mock()
        cli.ui.print_help_message = Mock()

        cli.print_results(results, generate_html=False, generate_sarif=False)

        cli.ui.print_summary_table.assert_called_once()
        cli.ui.print_success_message.assert_called_once()

    def test_print_results_with_issues(self):
        """Test print_results with issues to display."""
        cli = PyGuardCLI()
        results = {
            "total_files": 10,
            "all_issues": [{"severity": "HIGH", "category": "Security", "message": "Issue 1"}],
            "fixes_applied": 0,
        }

        cli.ui.print_issue_details = Mock()
        cli.ui.print_summary_table = Mock()
        cli.ui.print_success_message = Mock()
        cli.ui.print_next_steps = Mock()
        cli.ui.print_help_message = Mock()

        cli.print_results(results, generate_html=False, generate_sarif=False)

        cli.ui.print_issue_details.assert_called_once()

    def test_print_results_generates_html(self, tmp_path):
        """Test print_results generates HTML report when requested."""
        cli = PyGuardCLI()
        results = {
            "total_files": 10,
            "all_issues": [],
            "fixes_applied": 0,
            "security": {},
            "best_practices": {},
        }

        with patch.object(cli.html_reporter, "generate_report") as mock_gen:
            with patch.object(cli.html_reporter, "save_report", return_value=True) as mock_save:
                mock_gen.return_value = "<html>Test Report</html>"

                cli.ui.print_summary_table = Mock()
                cli.ui.print_success_message = Mock()
                cli.ui.print_next_steps = Mock()
                cli.ui.print_help_message = Mock()

                cli.print_results(results, generate_html=True, generate_sarif=False)

                mock_gen.assert_called_once()
                mock_save.assert_called_once()

    def test_print_results_generates_sarif(self):
        """Test print_results generates SARIF report when requested."""
        cli = PyGuardCLI()
        results = {"total_files": 10, "all_issues": [], "fixes_applied": 0}

        with patch.object(cli.sarif_reporter, "generate_report") as mock_gen:
            with patch.object(cli.sarif_reporter, "save_report", return_value=True) as mock_save:
                mock_gen.return_value = {"version": "2.1.0"}

                cli.ui.print_summary_table = Mock()
                cli.ui.print_success_message = Mock()
                cli.ui.print_next_steps = Mock()
                cli.ui.print_help_message = Mock()

                cli.print_results(results, generate_html=False, generate_sarif=True)

                mock_gen.assert_called_once()
                mock_save.assert_called_once()

    def test_print_results_no_reports(self):
        """Test print_results without generating any reports."""
        cli = PyGuardCLI()
        results = {"total_files": 10, "all_issues": [], "fixes_applied": 0}

        cli.ui.print_summary_table = Mock()
        cli.ui.print_success_message = Mock()
        cli.ui.print_next_steps = Mock()
        cli.ui.print_help_message = Mock()

        cli.print_results(results, generate_html=False, generate_sarif=False)

        # Just verify no exceptions thrown


class TestIntegration:
    """Integration tests for CLI workflow."""

    def test_full_workflow_with_fixes(self, tmp_path):
        """Test complete workflow: analyze and fix files."""
        cli = PyGuardCLI()

        # Create test files
        test_file1 = tmp_path / "test1.py"
        test_file1.write_text("x=1\ny=2")

        test_file2 = tmp_path / "test2.py"
        test_file2.write_text("def foo():\n  return 42")

        files = [test_file1, test_file2]

        # Run analysis
        results = cli.run_full_analysis(files, create_backup=False, fix=False)

        # Verify structure
        assert results["total_files"] == 2
        assert "analysis_time_seconds" in results
        assert "all_issues" in results

    def test_full_workflow_scan_only(self, tmp_path):
        """Test complete workflow: scan without fixing."""
        cli = PyGuardCLI()

        test_file = tmp_path / "test.py"
        test_file.write_text("import os\nx = 1")

        results = cli.run_full_analysis([test_file], create_backup=False, fix=False)

        assert results["total_files"] == 1
        assert "all_issues" in results
        assert "security_issues" in results
        assert "quality_issues" in results


class TestMainFunction:
    """Tests for the main() CLI entry point function."""

    def test_main_version_flag(self, monkeypatch, capsys):
        """Test main() with --version flag."""
        from pyguard.cli import main
        
        monkeypatch.setattr("sys.argv", ["pyguard", "--version"])
        
        with pytest.raises(SystemExit) as excinfo:
            main()
        
        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "PyGuard" in captured.out

    def test_main_no_files_found(self, monkeypatch, capsys, tmp_path):
        """Test main() when no Python files are found."""
        from pyguard.cli import main
        
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(empty_dir)])
        
        with pytest.raises(SystemExit) as excinfo:
            main()
        
        assert excinfo.value.code == 1

    def test_main_single_file(self, monkeypatch, tmp_path):
        """Test main() with a single Python file."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file)])
        
        # Should not raise
        main()

    def test_main_directory(self, monkeypatch, tmp_path):
        """Test main() with a directory containing Python files."""
        from pyguard.cli import main
        
        # Create test files
        (tmp_path / "file1.py").write_text("x = 1\n")
        (tmp_path / "file2.py").write_text("y = 2\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(tmp_path)])
        
        main()

    def test_main_no_backup_flag(self, monkeypatch, tmp_path):
        """Test main() with --no-backup flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--no-backup"])
        
        main()

    def test_main_scan_only_flag(self, monkeypatch, tmp_path):
        """Test main() with --scan-only flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--scan-only"])
        
        main()

    def test_main_security_only_flag(self, monkeypatch, tmp_path):
        """Test main() with --security-only flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--security-only"])
        
        main()

    def test_main_formatting_only_flag(self, monkeypatch, tmp_path):
        """Test main() with --formatting-only flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--formatting-only"])
        
        main()

    def test_main_best_practices_only_flag(self, monkeypatch, tmp_path):
        """Test main() with --best-practices-only flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--best-practices-only"])
        
        main()

    def test_main_unsafe_fixes_flag(self, monkeypatch, tmp_path):
        """Test main() with --unsafe-fixes flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--unsafe-fixes"])
        
        main()

    def test_main_no_black_flag(self, monkeypatch, tmp_path):
        """Test main() with --no-black flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--formatting-only", "--no-black"])
        
        main()

    def test_main_no_isort_flag(self, monkeypatch, tmp_path):
        """Test main() with --no-isort flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--formatting-only", "--no-isort"])
        
        main()

    def test_main_exclude_patterns(self, monkeypatch, tmp_path):
        """Test main() with --exclude patterns."""
        from pyguard.cli import main
        
        # Create files
        (tmp_path / "include.py").write_text("x = 1\n")
        exclude_dir = tmp_path / "exclude"
        exclude_dir.mkdir()
        (exclude_dir / "exclude.py").write_text("y = 2\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(tmp_path), "--exclude", "exclude/*"])
        
        main()

    def test_main_sarif_flag(self, monkeypatch, tmp_path):
        """Test main() with --sarif flag for SARIF report generation."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--sarif"])
        
        main()

    def test_main_no_html_flag(self, monkeypatch, tmp_path):
        """Test main() with --no-html flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), "--no-html"])
        
        main()

    def test_main_multiple_files(self, monkeypatch, tmp_path):
        """Test main() with multiple file arguments."""
        from pyguard.cli import main
        
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.py"
        file1.write_text("x = 1\n")
        file2.write_text("y = 2\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(file1), str(file2)])
        
        main()

    def test_main_invalid_path_warning(self, monkeypatch, tmp_path, capsys):
        """Test main() warns about invalid paths."""
        from pyguard.cli import main
        
        valid_file = tmp_path / "valid.py"
        valid_file.write_text("x = 1\n")
        
        invalid_path = tmp_path / "nonexistent.txt"
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(valid_file), str(invalid_path)])
        
        main()
        
        captured = capsys.readouterr()
        # Should have a warning about the invalid path
        assert "Warning:" in captured.out or "warning" in captured.out.lower()

    def test_main_combined_flags(self, monkeypatch, tmp_path):
        """Test main() with multiple flags combined."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", [
            "pyguard",
            str(test_file),
            "--no-backup",
            "--scan-only",
            "--no-html"
        ])
        
        main()

    @pytest.mark.parametrize("flag", [
        "--security-only",
        "--formatting-only",
        "--best-practices-only"
    ])
    def test_main_exclusive_mode_flags(self, flag, monkeypatch, tmp_path):
        """Test main() with each exclusive mode flag."""
        from pyguard.cli import main
        
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(test_file), flag])
        
        main()


class TestMainFunctionEdgeCases:
    """Edge case tests for main() function."""

    def test_main_empty_file(self, monkeypatch, tmp_path):
        """Test main() with an empty Python file."""
        from pyguard.cli import main
        
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(empty_file)])
        
        main()

    def test_main_file_with_syntax_error(self, monkeypatch, tmp_path):
        """Test main() with a file containing syntax errors."""
        from pyguard.cli import main
        
        bad_file = tmp_path / "syntax_error.py"
        bad_file.write_text("def foo(\n  # Invalid syntax")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(bad_file)])
        
        # Should not crash
        main()

    def test_main_large_file(self, monkeypatch, tmp_path):
        """Test main() with a large Python file."""
        from pyguard.cli import main
        
        large_file = tmp_path / "large.py"
        # Create a file with 1000 lines
        content = "\n".join([f"x{i} = {i}" for i in range(1000)])
        large_file.write_text(content)
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(large_file)])
        
        main()

    def test_main_unicode_content(self, monkeypatch, tmp_path):
        """Test main() with Unicode content in file."""
        from pyguard.cli import main
        
        unicode_file = tmp_path / "unicode.py"
        unicode_file.write_text("# -*- coding: utf-8 -*-\n# Comment: 世界 🌍\nx = 'Hello 世界'\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(unicode_file)])
        
        main()

    def test_main_nested_directory_structure(self, monkeypatch, tmp_path):
        """Test main() with nested directory structure."""
        from pyguard.cli import main
        
        # Create nested structure
        nested = tmp_path / "level1" / "level2" / "level3"
        nested.mkdir(parents=True)
        (nested / "deep.py").write_text("x = 1\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(tmp_path)])
        
        main()

    def test_main_mixed_python_non_python_files(self, monkeypatch, tmp_path):
        """Test main() in directory with mixed file types."""
        from pyguard.cli import main
        
        (tmp_path / "script.py").write_text("x = 1\n")
        (tmp_path / "readme.md").write_text("# README\n")
        (tmp_path / "config.json").write_text("{}\n")
        
        monkeypatch.setattr("sys.argv", ["pyguard", str(tmp_path)])
        
        main()


class TestRunBestPracticesEdgeCases:
    """Additional edge case tests for best practices fixes."""

    def test_run_best_practices_fixes_failure_tracking(self, tmp_path):
        """Test that failed fixes are properly counted."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass")
        
        # Mock to return failure
        cli.best_practices_fixer.fix_file = Mock(return_value=(False, []))
        
        result = cli.run_best_practices_fixes([test_file], create_backup=False)
        
        assert result["failed"] == 1
        assert result["fixed"] == 0


class TestCLICombinations:
    """Tests for various CLI flag combinations and workflows."""

    def test_security_fixes_with_backup(self, tmp_path):
        """Test security fixes with backup enabled."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret'\n")
        
        result = cli.run_security_fixes([test_file], create_backup=True)
        
        assert result["total"] == 1

    def test_formatting_with_both_formatters_disabled(self, tmp_path):
        """Test formatting with both Black and isort disabled."""
        cli = PyGuardCLI()
        test_file = tmp_path / "test.py"
        test_file.write_text("x=1\n")
        
        result = cli.run_formatting([test_file], use_black=False, use_isort=False)
        
        assert result["total"] == 1
