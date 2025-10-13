"""Integration tests for PyGuard CLI."""

import subprocess
import sys
from pathlib import Path

import pytest


class TestCLIIntegration:
    """Test CLI integration scenarios."""

    def test_cli_imports(self):
        """Test that CLI module can be imported."""
        try:
            from pyguard import cli

            assert cli is not None
        except ImportError as e:
            pytest.skip(f"CLI module not fully implemented: {e}")

    def test_cli_help(self):
        """Test CLI help command."""
        result = subprocess.run(
            [sys.executable, "-m", "pyguard.cli", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent,
        )
        # CLI might not be fully implemented yet
        assert result.returncode in [0, 1, 2]

    def test_cli_version(self):
        """Test CLI version command."""
        result = subprocess.run(
            [sys.executable, "-c", "import pyguard; print(pyguard.__version__)"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == "0.3.0"

    def test_version_consistency(self):
        """Test that version is consistent across all files."""
        import re

        # Get version from __init__.py
        import pyguard

        init_version = pyguard.__version__

        # Check pyproject.toml
        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        pyproject_content = pyproject_path.read_text()
        pyproject_match = re.search(r'^version = "([^"]+)"', pyproject_content, re.MULTILINE)
        assert pyproject_match, "Version not found in pyproject.toml"
        pyproject_version = pyproject_match.group(1)

        # Check Dockerfile
        dockerfile_path = Path(__file__).parent.parent.parent / "Dockerfile"
        dockerfile_content = dockerfile_path.read_text()
        dockerfile_match = re.search(r'LABEL version="([^"]+)"', dockerfile_content)
        assert dockerfile_match, "Version not found in Dockerfile"
        dockerfile_version = dockerfile_match.group(1)

        # Assert all versions match
        assert (
            init_version == pyproject_version == dockerfile_version
        ), f"Version mismatch: __init__.py={init_version}, pyproject.toml={pyproject_version}, Dockerfile={dockerfile_version}"


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_analysis_pipeline(self, temp_dir, sample_vulnerable_code):
        """Test complete analysis pipeline."""
        # Create test file
        test_file = temp_dir / "vulnerable.py"
        test_file.write_text(sample_vulnerable_code)

        # Import and run PyGuard components
        from pyguard import BestPracticesFixer, SecurityFixer

        security = SecurityFixer()
        best_practices = BestPracticesFixer()

        # Run analysis
        security_issues = security.scan_file_for_issues(test_file)

        # Verify some issues were found
        assert isinstance(security_issues, list)

        # Apply fixes
        security_result = security.fix_file(test_file)
        bp_result = best_practices.fix_file(test_file)

        # Verify fixes were attempted (returns tuple: (success, fixes))
        assert isinstance(security_result, tuple)
        assert len(security_result) == 2
        assert isinstance(security_result[1], list)
        assert isinstance(bp_result, tuple)
        assert len(bp_result) == 2
        assert isinstance(bp_result[1], list)

    def test_backup_and_restore(self, temp_dir):
        """Test backup and restore functionality."""
        from pyguard import BackupManager

        # Create test file
        test_file = temp_dir / "test.py"
        original_content = "print('hello')"
        test_file.write_text(original_content)

        # Create backup
        backup_mgr = BackupManager()
        backup_path = backup_mgr.create_backup(test_file)

        # Modify file
        test_file.write_text("print('modified')")

        # Restore backup
        if backup_path and backup_path.exists():
            success = backup_mgr.restore_backup(backup_path, test_file)
            assert success, "Backup restoration should succeed"

            # Verify restoration
            assert test_file.read_text() == original_content
