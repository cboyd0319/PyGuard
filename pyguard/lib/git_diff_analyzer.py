"""
Git Diff Analysis for PyGuard.

Analyzes only changed files in git diffs, PRs, and branches.
Critical for PR-based workflows and efficient CI/CD scanning.
"""

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
from typing import Any

from pyguard.lib.core import PyGuardLogger


@dataclass
class DiffStats:
    """Statistics about the diff analysis."""

    total_changed_files: int
    python_files: int
    added_lines: int
    deleted_lines: int
    modified_files: list[Path]


class GitDiffAnalyzer:
    """
    Analyzer for git diffs to identify changed Python files.
    
    Supports:
    - Comparing branches (main..feature-branch)
    - Analyzing staged changes
    - Analyzing working directory changes
    - PR-specific analysis
    """

    def __init__(self, repo_path: Path | None = None):
        """
        Initialize git diff analyzer.
        
        Args:
            repo_path: Path to git repository (defaults to current directory)
        """
        self.logger = PyGuardLogger()
        self.repo_path = repo_path or Path.cwd()
        self._validate_git_repo()

    def _validate_git_repo(self) -> None:
        """Validate that we're in a git repository."""
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise ValueError(
                f"Not a git repository: {self.repo_path}. "
                "Initialize git with 'git init' or use a different directory."
            ) from e

    def get_changed_files(
        self,
        diff_spec: str | None = None,
        include_staged: bool = False,
        include_unstaged: bool = False,
        python_only: bool = True,
    ) -> list[Path]:
        """
        Get list of changed files based on diff specification.
        
        Args:
            diff_spec: Git diff specification (e.g., "main..feature", "HEAD~1", "v1.0..HEAD")
            include_staged: Include staged changes
            include_unstaged: Include unstaged changes
            python_only: Only return Python files
        
        Returns:
            List of changed file paths
        """
        changed_files: set[Path] = set()

        # Get diff files based on specification
        if diff_spec:
            files = self._get_diff_files(diff_spec)
            changed_files.update(files)

        if include_staged:
            files = self._get_staged_files()
            changed_files.update(files)

        if include_unstaged:
            files = self._get_unstaged_files()
            changed_files.update(files)

        # Filter to Python files if requested
        if python_only:
            changed_files = {f for f in changed_files if f.suffix == ".py"}

        # Convert to absolute paths and filter out non-existent files
        result = []
        for file_path in changed_files:
            abs_path = (self.repo_path / file_path).resolve()
            if abs_path.exists() and abs_path.is_file():
                result.append(abs_path)

        return sorted(result)

    def _get_diff_files(self, diff_spec: str) -> set[Path]:
        """Get files changed in a git diff specification."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", diff_spec],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            files = set()
            for line in result.stdout.strip().split("\n"):
                if line:
                    files.add(Path(line))

            return files

        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Failed to get diff files for '{diff_spec}': {e}",
                category="Git",
            )
            return set()

    def _get_staged_files(self) -> set[Path]:
        """Get staged (cached) files."""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            files = set()
            for line in result.stdout.strip().split("\n"):
                if line:
                    files.add(Path(line))

            return files

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get staged files: {e}", category="Git")
            return set()

    def _get_unstaged_files(self) -> set[Path]:
        """Get unstaged (working directory) changes."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            files = set()
            for line in result.stdout.strip().split("\n"):
                if line:
                    files.add(Path(line))

            return files

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get unstaged files: {e}", category="Git")
            return set()

    def get_diff_stats(self, diff_spec: str) -> DiffStats:
        """
        Get statistics about the diff.
        
        Args:
            diff_spec: Git diff specification
        
        Returns:
            DiffStats with information about the changes
        """
        files = self.get_changed_files(diff_spec, python_only=False)
        python_files = [f for f in files if f.suffix == ".py"]

        # Get line count statistics
        added_lines = 0
        deleted_lines = 0

        try:
            result = subprocess.run(
                ["git", "diff", "--numstat", diff_spec],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            for line in result.stdout.strip().split("\n"):
                if line:
                    # Format: added\tdeleted\tfilename
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        try:
                            added_lines += int(parts[0])
                            deleted_lines += int(parts[1])
                        except ValueError:
                            # Binary files show '-' instead of numbers
                            pass

        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to get diff stats: {e}", category="Git")

        # Note: files are already Path objects (relative to repo), convert to absolute
        abs_files = []
        for f in files:
            if f.is_absolute():
                abs_files.append(f)
            else:
                abs_files.append((self.repo_path / f).resolve())

        return DiffStats(
            total_changed_files=len(files),
            python_files=len(python_files),
            added_lines=added_lines,
            deleted_lines=deleted_lines,
            modified_files=abs_files,
        )

    def get_current_branch(self) -> str:
        """Get the current git branch name."""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "unknown"

    def compare_security_posture(
        self,
        base_branch: str,
        compare_branch: str | None = None,
    ) -> dict[str, Any]:
        """
        Compare security posture between branches.
        
        This is a placeholder for future implementation that would:
        1. Scan base branch for issues
        2. Scan compare branch for issues
        3. Identify newly introduced vulnerabilities
        4. Identify fixed vulnerabilities
        
        Args:
            base_branch: Base branch to compare against (e.g., "main")
            compare_branch: Branch to compare (defaults to current branch)
        
        Returns:
            Dictionary with comparison results
        """
        compare_branch = compare_branch or self.get_current_branch()

        diff_spec = f"{base_branch}..{compare_branch}"
        changed_files = self.get_changed_files(diff_spec)
        stats = self.get_diff_stats(diff_spec)

        return {
            "base_branch": base_branch,
            "compare_branch": compare_branch,
            "diff_spec": diff_spec,
            "changed_files": [str(f) for f in changed_files],
            "stats": {
                "total_files": stats.total_changed_files,
                "python_files": stats.python_files,
                "added_lines": stats.added_lines,
                "deleted_lines": stats.deleted_lines,
            },
            "note": "Full security comparison requires integration with PyGuard scanner",
        }
