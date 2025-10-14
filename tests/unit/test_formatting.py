"""Tests for formatting module."""

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer


class TestFormattingFixer:
    """Tests for FormattingFixer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = FormattingFixer()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def create_temp_file(self, content: str) -> Path:
        """Create a temporary Python file."""
        temp_file = Path(self.temp_dir) / "test.py"
        temp_file.write_text(content)
        return temp_file

    @patch("subprocess.run")
    def test_format_with_black_success(self, mock_run):
        """Test successful Black formatting."""
        # Arrange
        mock_run.return_value = Mock(returncode=0, stdout="reformatted test.py")
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file)

        # Assert
        assert success is True
        assert output == "reformatted test.py"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_format_with_black_failure(self, mock_run):
        """Test Black formatting failure."""
        # Arrange
        mock_run.return_value = Mock(returncode=1, stderr="error: invalid syntax")
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file)

        # Assert
        assert success is False
        assert "error: invalid syntax" in output

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_format_with_black_not_installed(self, mock_run):
        """Test Black not installed error."""
        # Arrange
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file)

        # Assert
        assert success is False
        assert "not installed" in output

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("black", 30))
    def test_format_with_black_timeout(self, mock_run):
        """Test Black formatting timeout."""
        # Arrange
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file)

        # Assert
        assert success is False
        assert "timed out" in output

    @patch("subprocess.run", side_effect=Exception("Unknown error"))
    def test_format_with_black_exception(self, mock_run):
        """Test Black formatting exception."""
        # Arrange
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file)

        # Assert
        assert success is False
        assert "Error running Black" in output

    @patch("subprocess.run")
    def test_format_with_black_custom_line_length(self, mock_run):
        """Test Black formatting with custom line length."""
        # Arrange
        mock_run.return_value = Mock(returncode=0, stdout="reformatted test.py")
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_black(test_file, line_length=120)

        # Assert
        assert success is True
        # Check that line_length was passed
        call_args = mock_run.call_args[0][0]
        assert "--line-length" in call_args
        assert "120" in call_args

    @patch("subprocess.run")
    def test_format_with_autopep8_success(self, mock_run):
        """Test successful autopep8 formatting."""
        # Arrange
        mock_run.return_value = Mock(returncode=0, stdout="")
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_autopep8(test_file)

        # Assert
        assert success is True
        assert output == "Formatting applied"

    @patch("subprocess.run")
    def test_format_with_autopep8_aggressive(self, mock_run):
        """Test autopep8 with aggressive level."""
        # Arrange
        mock_run.return_value = Mock(returncode=0, stdout="")
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_autopep8(test_file, aggressive=2)

        # Assert
        assert success is True
        # Check aggressive flags were passed
        call_args = mock_run.call_args[0][0]
        assert call_args.count("--aggressive") == 2

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_format_with_autopep8_not_installed(self, mock_run):
        """Test autopep8 not installed error."""
        # Arrange
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_autopep8(test_file)

        # Assert
        assert success is False
        assert "not installed" in output

    @patch("subprocess.run", side_effect=Exception("Unknown error"))
    def test_format_with_autopep8_exception(self, mock_run):
        """Test autopep8 exception."""
        # Arrange
        test_file = self.create_temp_file("x=1")

        # Act
        success, output = self.fixer.format_with_autopep8(test_file)

        # Assert
        assert success is False
        assert "Error running autopep8" in output

    @patch("subprocess.run")
    def test_sort_imports_with_isort_success(self, mock_run):
        """Test successful isort."""
        # Arrange
        mock_run.return_value = Mock(returncode=0, stdout="Fixed imports")
        test_file = self.create_temp_file("import os\nimport sys")

        # Act
        success, output = self.fixer.sort_imports_with_isort(test_file)

        # Assert
        assert success is True

    @patch("subprocess.run")
    def test_sort_imports_with_isort_failure(self, mock_run):
        """Test isort failure."""
        # Arrange
        mock_run.return_value = Mock(returncode=1, stderr="error")
        test_file = self.create_temp_file("import os")

        # Act
        success, output = self.fixer.sort_imports_with_isort(test_file)

        # Assert
        assert success is False
        assert output == "error"

    @patch("subprocess.run", side_effect=FileNotFoundError())
    def test_sort_imports_with_isort_not_installed(self, mock_run):
        """Test isort not installed error."""
        # Arrange
        test_file = self.create_temp_file("import os")

        # Act
        success, output = self.fixer.sort_imports_with_isort(test_file)

        # Assert
        assert success is False
        assert "not installed" in output

    @patch("subprocess.run", side_effect=Exception("Unknown error"))
    def test_sort_imports_with_isort_exception(self, mock_run):
        """Test isort exception."""
        # Arrange
        test_file = self.create_temp_file("import os")

        # Act
        success, output = self.fixer.sort_imports_with_isort(test_file)

        # Assert
        assert success is False
        assert "Error running isort" in output

    @patch.object(FormattingFixer, "format_with_black")
    @patch.object(FormattingFixer, "sort_imports_with_isort")
    def test_format_file_with_defaults(self, mock_isort, mock_black):
        """Test format_file with default options."""
        # Arrange
        mock_isort.return_value = (True, "isort success")
        mock_black.return_value = (True, "black success")
        test_file = self.create_temp_file("x=1")

        # Act
        result = self.fixer.format_file(test_file)

        # Assert
        assert result["success"] is True
        assert "isort" in result["formatters_applied"]
        assert "black" in result["formatters_applied"]
        assert len(result["errors"]) == 0
        mock_isort.assert_called_once()
        mock_black.assert_called_once()

    @patch.object(FormattingFixer, "format_with_black")
    @patch.object(FormattingFixer, "sort_imports_with_isort")
    def test_format_file_isort_only(self, mock_isort, mock_black):
        """Test format_file with only isort."""
        # Arrange
        mock_isort.return_value = (True, "isort success")
        test_file = self.create_temp_file("x=1")

        # Act
        result = self.fixer.format_file(test_file, use_black=False)

        # Assert
        assert result["success"] is True
        assert "isort" in result["formatters_applied"]
        assert "black" not in result["formatters_applied"]
        mock_isort.assert_called_once()
        mock_black.assert_not_called()

    @patch.object(FormattingFixer, "format_with_black")
    @patch.object(FormattingFixer, "format_with_autopep8")
    @patch.object(FormattingFixer, "sort_imports_with_isort")
    def test_format_file_autopep8_only(self, mock_isort, mock_autopep8, mock_black):
        """Test format_file with autopep8 instead of black."""
        # Arrange
        mock_isort.return_value = (True, "isort success")
        mock_autopep8.return_value = (True, "autopep8 success")
        test_file = self.create_temp_file("x=1")

        # Act
        result = self.fixer.format_file(test_file, use_black=False, use_autopep8=True)

        # Assert
        assert result["success"] is True
        assert "autopep8" in result["formatters_applied"]
        assert "black" not in result["formatters_applied"]
        mock_autopep8.assert_called_once()
        mock_black.assert_not_called()

    @patch.object(FormattingFixer, "format_with_black")
    @patch.object(FormattingFixer, "sort_imports_with_isort")
    def test_format_file_with_errors(self, mock_isort, mock_black):
        """Test format_file when formatters fail."""
        # Arrange
        mock_isort.return_value = (False, "isort error")
        mock_black.return_value = (False, "black error")
        test_file = self.create_temp_file("x=1")

        # Act
        result = self.fixer.format_file(test_file)

        # Assert
        assert result["success"] is False
        assert len(result["errors"]) == 2
        assert any("isort" in e for e in result["errors"])
        assert any("black" in e for e in result["errors"])

    @patch.object(FormattingFixer, "format_file")
    def test_format_directory(self, mock_format_file):
        """Test format_directory."""
        # Arrange
        test_dir = Path(self.temp_dir)
        test_file1 = test_dir / "test1.py"
        test_file2 = test_dir / "test2.py"
        test_file1.write_text("x=1")
        test_file2.write_text("y=2")

        mock_format_file.side_effect = [
            {"success": True, "file": str(test_file1)},
            {"success": True, "file": str(test_file2)},
        ]

        # Act
        results = self.fixer.format_directory(test_dir)

        # Assert
        assert len(results) == 2
        assert all(r["success"] for r in results)
        assert mock_format_file.call_count == 2


class TestWhitespaceFixer:
    """Tests for WhitespaceFixer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.fixer = WhitespaceFixer()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fix_trailing_whitespace(self):
        """Test removing trailing whitespace."""
        # Arrange
        content = "line1   \nline2\t\nline3\n"

        # Act
        fixed, count = self.fixer.fix_trailing_whitespace(content)

        # Assert
        assert count == 2
        assert fixed == "line1\nline2\nline3\n"

    def test_fix_trailing_whitespace_no_changes(self):
        """Test no trailing whitespace to fix."""
        # Arrange
        content = "line1\nline2\nline3\n"

        # Act
        fixed, count = self.fixer.fix_trailing_whitespace(content)

        # Assert
        assert count == 0
        assert fixed == content

    def test_fix_blank_lines(self):
        """Test fixing excessive blank lines."""
        # Arrange
        content = "line1\n\n\n\nline2\n"

        # Act
        fixed, count = self.fixer.fix_blank_lines(content)

        # Assert
        assert count == 1
        assert fixed == "line1\n\n\nline2\n"

    def test_fix_blank_lines_no_changes(self):
        """Test no excessive blank lines."""
        # Arrange
        content = "line1\n\nline2\n"

        # Act
        fixed, count = self.fixer.fix_blank_lines(content)

        # Assert
        assert count == 0
        assert fixed == content

    def test_fix_line_endings_crlf_to_lf(self):
        """Test converting CRLF to LF."""
        # Arrange
        content = "line1\r\nline2\r\nline3\r\n"

        # Act
        fixed, changed = self.fixer.fix_line_endings(content)

        # Assert
        assert changed is True
        assert fixed == "line1\nline2\nline3\n"
        assert "\r\n" not in fixed

    def test_fix_line_endings_already_lf(self):
        """Test no line ending changes needed."""
        # Arrange
        content = "line1\nline2\nline3\n"

        # Act
        fixed, changed = self.fixer.fix_line_endings(content)

        # Assert
        assert changed is False
        assert fixed == content

    def test_fix_file_whitespace_all_issues(self):
        """Test fixing all whitespace issues in a file."""
        # Arrange
        temp_file = Path(self.temp_dir) / "test.py"
        content = "line1   \r\n\r\n\r\n\r\nline2\t\r\n"
        temp_file.write_text(content)

        # Act
        result = self.fixer.fix_file_whitespace(temp_file)

        # Assert
        assert result["success"] is True
        assert len(result["fixes"]) >= 2  # At least trailing whitespace and blank lines
        # Check for key phrases in the fixes (case-insensitive)
        fixes_text = " ".join(result["fixes"]).lower()
        assert "trailing whitespace" in fixes_text
        assert "blank" in fixes_text  # Could be "blank lines" or "excessive blank lines"

        # Verify file was actually fixed
        fixed_content = temp_file.read_text()
        assert "   " not in fixed_content
        assert "\r\n" not in fixed_content

    def test_fix_file_whitespace_no_issues(self):
        """Test file with no whitespace issues."""
        # Arrange
        temp_file = Path(self.temp_dir) / "test.py"
        content = "line1\nline2\nline3\n"
        temp_file.write_text(content)

        # Act
        result = self.fixer.fix_file_whitespace(temp_file)

        # Assert
        assert result["success"] is True
        assert len(result["fixes"]) == 0

    def test_fix_file_whitespace_read_error(self):
        """Test handling file read error."""
        # Arrange
        temp_file = Path(self.temp_dir) / "nonexistent.py"

        # Act
        result = self.fixer.fix_file_whitespace(temp_file)

        # Assert
        assert result["success"] is False
        assert "error" in result

    @patch.object(WhitespaceFixer, "fix_trailing_whitespace")
    @patch.object(WhitespaceFixer, "fix_blank_lines")
    @patch.object(WhitespaceFixer, "fix_line_endings")
    def test_fix_file_whitespace_write_error(
        self, mock_line_endings, mock_blank_lines, mock_trailing
    ):
        """Test handling file write error."""
        # Arrange
        temp_file = Path(self.temp_dir) / "test.py"
        temp_file.write_text("line1\n")

        # Mock fixes that would change content
        mock_trailing.return_value = ("line1", 1)
        mock_blank_lines.return_value = ("line1", 0)
        mock_line_endings.return_value = ("line1", False)

        # Mock write to fail
        with patch.object(self.fixer.file_ops, "write_file", return_value=False):
            # Act
            result = self.fixer.fix_file_whitespace(temp_file)

            # Assert
            assert result["success"] is False
            assert "error" in result
