"""Tests for git diff analyzer."""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from pyguard.lib.git_diff_analyzer import DiffStats, GitDiffAnalyzer


class TestGitDiffAnalyzer:
    """Test git diff analyzer functionality."""

    @pytest.fixture
    def mock_git_repo(self, tmp_path):
        """Create a mock git repository."""
        # Mock successful git repo validation
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            analyzer = GitDiffAnalyzer(repo_path=tmp_path)
        return analyzer

    def test_init_validates_git_repo(self, tmp_path):
        """Test that analyzer validates git repository on init."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")

            with pytest.raises(ValueError, match="Not a git repository"):
                GitDiffAnalyzer(repo_path=tmp_path)

    def test_get_changed_files_with_diff_spec(self, mock_git_repo, tmp_path):
        """Test getting changed files with diff specification."""
        # Create test files
        test_file = tmp_path / "test.py"
        test_file.write_text("print('test')")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="test.py\nother.txt\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(diff_spec="main..feature")

            # Should only return Python files
            assert len(files) == 1
            assert files[0].name == "test.py"

    def test_get_changed_files_python_only(self, mock_git_repo, tmp_path):
        """Test filtering to Python files only."""
        # Create test files
        (tmp_path / "script.py").write_text("print('test')")
        (tmp_path / "readme.md").write_text("# README")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="script.py\nreadme.md\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(
                diff_spec="HEAD~1",
                python_only=True,
            )

            assert len(files) == 1
            assert files[0].suffix == ".py"

    def test_get_changed_files_include_all(self, mock_git_repo, tmp_path):
        """Test getting all changed files (not just Python)."""
        # Create test files
        (tmp_path / "script.py").write_text("print('test')")
        (tmp_path / "readme.md").write_text("# README")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="script.py\nreadme.md\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(
                diff_spec="HEAD~1",
                python_only=False,
            )

            assert len(files) == 2

    def test_get_staged_files(self, mock_git_repo, tmp_path):
        """Test getting staged files."""
        (tmp_path / "staged.py").write_text("# staged")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="staged.py\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(include_staged=True)

            assert len(files) == 1
            assert files[0].name == "staged.py"

    def test_get_unstaged_files(self, mock_git_repo, tmp_path):
        """Test getting unstaged files."""
        (tmp_path / "unstaged.py").write_text("# unstaged")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="unstaged.py\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(include_unstaged=True)

            assert len(files) == 1
            assert files[0].name == "unstaged.py"

    def test_get_diff_stats(self, mock_git_repo, tmp_path):
        """Test getting diff statistics."""
        # Create test files
        (tmp_path / "file1.py").write_text("# test1")
        (tmp_path / "file2.py").write_text("# test2")

        with patch("subprocess.run") as mock_run:
            # get_diff_stats calls get_changed_files (1 call) then numstat (1 call)
            mock_run.side_effect = [
                # get_changed_files -> _get_diff_files
                MagicMock(returncode=0, stdout="file1.py\nfile2.py\n", stderr=""),
                # numstat call
                MagicMock(returncode=0, stdout="10\t5\tfile1.py\n20\t3\tfile2.py\n", stderr=""),
            ]

            stats = mock_git_repo.get_diff_stats("main..feature")

            assert stats.python_files == 2
            assert stats.added_lines == 30
            assert stats.deleted_lines == 8

    def test_get_diff_stats_with_binary_files(self, mock_git_repo):
        """Test diff stats handles binary files correctly."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="file.py\nimage.png\n", stderr=""),
                MagicMock(returncode=0, stdout="10\t5\tfile.py\n-\t-\timage.png\n", stderr=""),
            ]

            stats = mock_git_repo.get_diff_stats("HEAD~1")

            # Should handle binary file gracefully
            assert stats.added_lines == 10
            assert stats.deleted_lines == 5

    def test_get_current_branch(self, mock_git_repo):
        """Test getting current branch name."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="feature-branch\n",
                stderr="",
            )

            branch = mock_git_repo.get_current_branch()

            assert branch == "feature-branch"

    def test_get_current_branch_error(self, mock_git_repo):
        """Test handling error when getting branch name."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")

            branch = mock_git_repo.get_current_branch()

            assert branch == "unknown"

    def test_compare_security_posture(self, mock_git_repo):
        """Test comparing security posture between branches."""
        with patch("subprocess.run") as mock_run:
            # Mock git commands
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="feature\n", stderr=""),  # current branch
                MagicMock(returncode=0, stdout="file1.py\n", stderr=""),  # changed files
                MagicMock(returncode=0, stdout="file1.py\n", stderr=""),  # diff files for stats
                MagicMock(returncode=0, stdout="50\t10\tfile1.py\n", stderr=""),  # numstat
            ]

            result = mock_git_repo.compare_security_posture("main", "feature")

            assert result["base_branch"] == "main"
            assert result["compare_branch"] == "feature"
            assert result["diff_spec"] == "main..feature"
            assert "changed_files" in result
            assert "stats" in result

    def test_filters_nonexistent_files(self, mock_git_repo, tmp_path):
        """Test that analyzer filters out files that don't exist."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="nonexistent.py\nalso_missing.py\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(diff_spec="HEAD~1")

            # Should return empty list since files don't exist
            assert len(files) == 0

    def test_handles_git_error_gracefully(self, mock_git_repo):
        """Test handling git command errors gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")

            files = mock_git_repo.get_changed_files(diff_spec="invalid..spec")

            # Should return empty list on error
            assert len(files) == 0

    def test_deduplicates_files(self, mock_git_repo, tmp_path):
        """Test that duplicate files are deduplicated."""
        test_file = tmp_path / "duplicate.py"
        test_file.write_text("# test")

        with patch("subprocess.run") as mock_run:
            # Return same file multiple times
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="duplicate.py\nduplicate.py\n",
                stderr="",
            )

            files = mock_git_repo.get_changed_files(
                include_staged=True,
                include_unstaged=True,
            )

            # Should only include once
            assert len(files) == 1


class TestDiffStats:
    """Test DiffStats dataclass."""

    def test_diff_stats_creation(self):
        """Test creating DiffStats."""
        stats = DiffStats(
            total_changed_files=10,
            python_files=8,
            added_lines=100,
            deleted_lines=50,
            modified_files=[Path("file1.py"), Path("file2.py")],
        )

        assert stats.total_changed_files == 10
        assert stats.python_files == 8
        assert stats.added_lines == 100
        assert stats.deleted_lines == 50
        assert len(stats.modified_files) == 2
