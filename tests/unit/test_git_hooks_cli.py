"""Tests for git hooks CLI."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyguard.git_hooks_cli import main


class TestGitHooksCLI(unittest.TestCase):
    """Test cases for git hooks CLI."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.test_dir)

        # Initialize git repository
        subprocess.run(["git", "init"], cwd=self.repo_path, capture_output=True, check=True)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("sys.argv", ["pyguard-hooks", "--version"])
    def test_version_flag(self):
        """Test --version flag."""
        with self.assertRaises(SystemExit) as cm:
            main()
        # argparse exits with 0 for --version
        self.assertEqual(cm.exception.code, 0)

    @patch("sys.argv", ["pyguard-hooks"])
    def test_no_command_shows_help(self):
        """Test that no command shows help and exits."""
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    @patch("sys.argv", ["pyguard-hooks", "install", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.install_hook")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_install_command_success(self, mock_logger_info, mock_install):
        """Test install command with success."""
        mock_install.return_value = True

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_install.assert_called_once_with("pre-commit", False)
        mock_logger_info.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "install", "--path", "/tmp/fake-repo", "--force"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.install_hook")
    @patch("pyguard.lib.core.PyGuardLogger.error")
    def test_install_command_failure(self, mock_logger_error, mock_install):
        """Test install command with failure."""
        mock_install.return_value = False

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        mock_install.assert_called_once_with("pre-commit", True)
        mock_logger_error.assert_called()

    @patch(
        "sys.argv", ["pyguard-hooks", "install", "--type", "pre-push", "--path", "/tmp/fake-repo"]
    )
    @patch("pyguard.lib.git_hooks.GitHooksManager.install_hook")
    @patch("pyguard.lib.core.PyGuardLogger.error")
    def test_install_command_value_error(self, mock_logger_error, mock_install):
        """Test install command raising ValueError."""
        mock_install.side_effect = ValueError("Test error")

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        mock_logger_error.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "uninstall", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.uninstall_hook")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_uninstall_command_success(self, mock_logger_info, mock_uninstall):
        """Test uninstall command with success."""
        mock_uninstall.return_value = True

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_uninstall.assert_called_once_with("pre-commit")
        mock_logger_info.assert_called()

    @patch(
        "sys.argv", ["pyguard-hooks", "uninstall", "--type", "pre-push", "--path", "/tmp/fake-repo"]
    )
    @patch("pyguard.lib.git_hooks.GitHooksManager.uninstall_hook")
    @patch("pyguard.lib.core.PyGuardLogger.error")
    def test_uninstall_command_failure(self, mock_logger_error, mock_uninstall):
        """Test uninstall command with failure."""
        mock_uninstall.return_value = False

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        mock_uninstall.assert_called_once_with("pre-push")
        mock_logger_error.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "list", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.list_hooks")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_list_command_no_hooks(self, mock_logger_info, mock_list):
        """Test list command with no hooks installed."""
        mock_list.return_value = []

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_list.assert_called_once()
        mock_logger_info.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "list", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.list_hooks")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_list_command_with_hooks(self, mock_logger_info, mock_list):
        """Test list command with hooks installed."""
        mock_list.return_value = [
            {
                "name": "pre-commit",
                "path": "/tmp/fake-repo/.git/hooks/pre-commit",
                "pyguard": True,
                "executable": True,
            },
            {
                "name": "pre-push",
                "path": "/tmp/fake-repo/.git/hooks/pre-push",
                "pyguard": False,
                "executable": True,
            },
        ]

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_list.assert_called_once()
        # Should be called multiple times (once for header, once for each hook)
        self.assertGreaterEqual(mock_logger_info.call_count, 3)

    @patch("sys.argv", ["pyguard-hooks", "validate", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.validate_hook")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_validate_command_valid(self, mock_logger_info, mock_validate):
        """Test validate command with valid hook."""
        mock_validate.return_value = {"valid": True, "issues": []}

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_validate.assert_called_once_with("pre-commit")
        mock_logger_info.assert_called()

    @patch(
        "sys.argv", ["pyguard-hooks", "validate", "--type", "pre-push", "--path", "/tmp/fake-repo"]
    )
    @patch("pyguard.lib.git_hooks.GitHooksManager.validate_hook")
    @patch("pyguard.lib.core.PyGuardLogger.error")
    def test_validate_command_invalid(self, mock_logger_error, mock_validate):
        """Test validate command with invalid hook."""
        mock_validate.return_value = {
            "valid": False,
            "issues": ["Hook is not executable", "Hook content invalid"],
        }

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        mock_validate.assert_called_once_with("pre-push")
        mock_logger_error.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "test", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.test_hook")
    @patch("pyguard.lib.core.PyGuardLogger.info")
    def test_test_command_success(self, mock_logger_info, mock_test):
        """Test test command with success."""
        mock_test.return_value = True

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 0)
        mock_test.assert_called_once_with("pre-commit")
        mock_logger_info.assert_called()

    @patch("sys.argv", ["pyguard-hooks", "test", "--type", "pre-push", "--path", "/tmp/fake-repo"])
    @patch("pyguard.lib.git_hooks.GitHooksManager.test_hook")
    @patch("pyguard.lib.core.PyGuardLogger.error")
    def test_test_command_failure(self, mock_logger_error, mock_test):
        """Test test command with failure."""
        mock_test.return_value = False

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        mock_test.assert_called_once_with("pre-push")
        mock_logger_error.assert_called()


if __name__ == "__main__":
    unittest.main()
