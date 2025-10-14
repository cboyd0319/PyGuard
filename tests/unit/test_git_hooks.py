"""Tests for git hooks integration."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from pyguard.lib.git_hooks import (
    GitHooksManager,
    install_git_hooks,
    uninstall_git_hooks,
    validate_git_hooks,
)


class TestGitHooksManager(unittest.TestCase):
    """Test cases for GitHooksManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory with a git repository
        self.test_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.test_dir)
        
        # Initialize git repository
        subprocess.run(
            ["git", "init"],
            cwd=self.repo_path,
            capture_output=True,
            check=True
        )
        
        self.manager = GitHooksManager(self.repo_path)

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_init(self):
        """Test GitHooksManager initialization."""
        self.assertIsNotNone(self.manager.repo_path)
        self.assertIsNotNone(self.manager.git_dir)
        self.assertIsNotNone(self.manager.hooks_dir)

    def test_init_with_custom_path(self):
        """Test initialization with custom repository path."""
        manager = GitHooksManager(self.repo_path)
        self.assertEqual(manager.repo_path, self.repo_path)

    def test_find_git_dir(self):
        """Test finding .git directory."""
        git_dir = self.manager._find_git_dir()
        self.assertIsNotNone(git_dir)
        self.assertTrue(git_dir.exists())
        self.assertEqual(git_dir.name, ".git")

    def test_find_git_dir_in_subdirectory(self):
        """Test finding .git directory from subdirectory."""
        subdir = self.repo_path / "subdir"
        subdir.mkdir()
        
        manager = GitHooksManager(subdir)
        git_dir = manager._find_git_dir()
        
        self.assertIsNotNone(git_dir)
        self.assertTrue(git_dir.exists())

    def test_is_git_repository(self):
        """Test checking if directory is a git repository."""
        self.assertTrue(self.manager.is_git_repository())

    def test_is_not_git_repository(self):
        """Test checking non-git directory."""
        non_git_dir = tempfile.mkdtemp()
        try:
            manager = GitHooksManager(Path(non_git_dir))
            self.assertFalse(manager.is_git_repository())
        finally:
            shutil.rmtree(non_git_dir, ignore_errors=True)

    def test_install_hook_creates_file(self):
        """Test that install_hook creates hook file."""
        success = self.manager.install_hook("pre-commit")
        self.assertTrue(success)
        
        hook_path = self.manager.hooks_dir / "pre-commit"
        self.assertTrue(hook_path.exists())

    def test_install_hook_makes_executable(self):
        """Test that installed hook is executable."""
        self.manager.install_hook("pre-commit")
        
        hook_path = self.manager.hooks_dir / "pre-commit"
        self.assertTrue(os.access(hook_path, os.X_OK))

    def test_install_hook_contains_pyguard(self):
        """Test that installed hook contains PyGuard reference."""
        self.manager.install_hook("pre-commit")
        
        hook_path = self.manager.hooks_dir / "pre-commit"
        content = hook_path.read_text()
        
        self.assertIn("PyGuard", content)
        self.assertIn("pyguard", content)

    def test_install_hook_fails_without_force(self):
        """Test that installing over existing hook fails without force."""
        # Install first time
        self.manager.install_hook("pre-commit")
        
        # Try to install again without force
        success = self.manager.install_hook("pre-commit", force=False)
        self.assertFalse(success)

    def test_install_hook_succeeds_with_force(self):
        """Test that installing over existing hook succeeds with force."""
        # Install first time
        self.manager.install_hook("pre-commit")
        
        # Install again with force
        success = self.manager.install_hook("pre-commit", force=True)
        self.assertTrue(success)

    def test_install_hook_raises_for_non_git_repo(self):
        """Test that install_hook raises error for non-git repository."""
        non_git_dir = tempfile.mkdtemp()
        try:
            manager = GitHooksManager(Path(non_git_dir))
            with self.assertRaises(ValueError):
                manager.install_hook("pre-commit")
        finally:
            shutil.rmtree(non_git_dir, ignore_errors=True)

    def test_install_pre_push_hook(self):
        """Test installing pre-push hook."""
        success = self.manager.install_hook("pre-push")
        self.assertTrue(success)
        
        hook_path = self.manager.hooks_dir / "pre-push"
        self.assertTrue(hook_path.exists())
        self.assertTrue(os.access(hook_path, os.X_OK))

    def test_generate_hook_script_pre_commit(self):
        """Test generating pre-commit hook script."""
        script = self.manager._generate_hook_script("pre-commit")
        
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("PyGuard", script)
        self.assertIn("pyguard", script)
        self.assertIn("--scan-only", script)

    def test_generate_hook_script_pre_push(self):
        """Test generating pre-push hook script."""
        script = self.manager._generate_hook_script("pre-push")
        
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("PyGuard", script)
        self.assertIn("pyguard", script)

    def test_generate_hook_script_unsupported_type(self):
        """Test that unsupported hook type raises error."""
        with self.assertRaises(ValueError):
            self.manager._generate_hook_script("unsupported-type")

    def test_uninstall_hook(self):
        """Test uninstalling a hook."""
        # Install hook first
        self.manager.install_hook("pre-commit")
        
        # Uninstall it
        success = self.manager.uninstall_hook("pre-commit")
        self.assertTrue(success)
        
        # Verify it's removed
        hook_path = self.manager.hooks_dir / "pre-commit"
        self.assertFalse(hook_path.exists())

    def test_uninstall_nonexistent_hook(self):
        """Test uninstalling non-existent hook."""
        success = self.manager.uninstall_hook("pre-commit")
        self.assertFalse(success)

    def test_uninstall_non_pyguard_hook(self):
        """Test that uninstall refuses to remove non-PyGuard hooks."""
        # Create a non-PyGuard hook
        hook_path = self.manager.hooks_dir / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("#!/bin/bash\necho 'Custom hook'\n")
        
        # Try to uninstall
        success = self.manager.uninstall_hook("pre-commit")
        self.assertFalse(success)
        
        # Verify hook still exists
        self.assertTrue(hook_path.exists())

    def test_list_hooks_empty(self):
        """Test listing hooks when none are installed."""
        hooks = self.manager.list_hooks()
        # Filter out any .sample hooks
        non_sample_hooks = [h for h in hooks if not h["name"].endswith(".sample")]
        self.assertEqual(len(non_sample_hooks), 0)

    def test_list_hooks_with_pyguard_hook(self):
        """Test listing hooks with PyGuard hook installed."""
        self.manager.install_hook("pre-commit")
        
        hooks = self.manager.list_hooks()
        pyguard_hooks = [h for h in hooks if h["pyguard"]]
        
        self.assertEqual(len(pyguard_hooks), 1)
        self.assertEqual(pyguard_hooks[0]["name"], "pre-commit")
        self.assertTrue(pyguard_hooks[0]["executable"])

    def test_list_hooks_with_multiple_hooks(self):
        """Test listing multiple hooks."""
        self.manager.install_hook("pre-commit")
        self.manager.install_hook("pre-push")
        
        hooks = self.manager.list_hooks()
        pyguard_hooks = [h for h in hooks if h["pyguard"]]
        
        self.assertEqual(len(pyguard_hooks), 2)
        hook_names = [h["name"] for h in pyguard_hooks]
        self.assertIn("pre-commit", hook_names)
        self.assertIn("pre-push", hook_names)

    def test_validate_hook_not_installed(self):
        """Test validating non-existent hook."""
        result = self.manager.validate_hook("pre-commit")
        
        self.assertFalse(result["exists"])
        self.assertFalse(result["valid"])
        self.assertIn("does not exist", result["issues"][0])

    def test_validate_hook_installed(self):
        """Test validating installed hook."""
        self.manager.install_hook("pre-commit")
        
        result = self.manager.validate_hook("pre-commit")
        
        self.assertTrue(result["exists"])
        self.assertTrue(result["executable"])
        self.assertTrue(result["is_pyguard"])

    def test_validate_hook_not_executable(self):
        """Test validating non-executable hook."""
        # Install hook
        self.manager.install_hook("pre-commit")
        
        # Make it non-executable
        hook_path = self.manager.hooks_dir / "pre-commit"
        hook_path.chmod(0o644)
        
        result = self.manager.validate_hook("pre-commit")
        
        self.assertTrue(result["exists"])
        self.assertFalse(result["executable"])
        self.assertIn("not executable", result["issues"][0])

    def test_validate_hook_non_pyguard(self):
        """Test validating non-PyGuard hook."""
        # Create a non-PyGuard hook
        hook_path = self.manager.hooks_dir / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("#!/bin/bash\necho 'Custom hook'\n")
        hook_path.chmod(0o755)
        
        result = self.manager.validate_hook("pre-commit")
        
        self.assertTrue(result["exists"])
        self.assertTrue(result["executable"])
        self.assertFalse(result["is_pyguard"])
        self.assertIn("not a PyGuard hook", result["issues"][0])

    @patch("shutil.which")
    def test_validate_hook_pyguard_not_in_path(self, mock_which):
        """Test validating hook when pyguard command is not available."""
        mock_which.return_value = None
        
        self.manager.install_hook("pre-commit")
        result = self.manager.validate_hook("pre-commit")
        
        self.assertIn("not found in PATH", result["issues"][0])

    @patch("subprocess.run")
    def test_test_hook_success(self, mock_run):
        """Test running hook test successfully."""
        # Install hook
        self.manager.install_hook("pre-commit")
        
        # Mock successful execution
        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")
        
        success = self.manager.test_hook("pre-commit")
        self.assertTrue(success)

    @patch("subprocess.run")
    def test_test_hook_failure(self, mock_run):
        """Test running hook test that fails."""
        # Install hook
        self.manager.install_hook("pre-commit")
        
        # Mock failed execution
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error")
        
        success = self.manager.test_hook("pre-commit")
        self.assertFalse(success)

    @patch("subprocess.run")
    def test_test_hook_timeout(self, mock_run):
        """Test running hook test that times out."""
        # Install hook
        self.manager.install_hook("pre-commit")
        
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired("test", 60)
        
        success = self.manager.test_hook("pre-commit")
        self.assertFalse(success)


class TestGitHooksHelperFunctions(unittest.TestCase):
    """Test cases for git hooks helper functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.test_dir)
        
        # Initialize git repository
        subprocess.run(
            ["git", "init"],
            cwd=self.repo_path,
            capture_output=True,
            check=True
        )

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_install_git_hooks(self):
        """Test install_git_hooks helper function."""
        success = install_git_hooks(self.repo_path)
        self.assertTrue(success)
        
        # Verify hook exists
        hooks_dir = self.repo_path / ".git" / "hooks"
        hook_path = hooks_dir / "pre-commit"
        self.assertTrue(hook_path.exists())

    def test_uninstall_git_hooks(self):
        """Test uninstall_git_hooks helper function."""
        # Install first
        install_git_hooks(self.repo_path)
        
        # Uninstall
        success = uninstall_git_hooks(self.repo_path)
        self.assertTrue(success)
        
        # Verify hook removed
        hooks_dir = self.repo_path / ".git" / "hooks"
        hook_path = hooks_dir / "pre-commit"
        self.assertFalse(hook_path.exists())

    def test_validate_git_hooks(self):
        """Test validate_git_hooks helper function."""
        # Install hook
        install_git_hooks(self.repo_path)
        
        # Validate
        result = validate_git_hooks(self.repo_path)
        
        self.assertTrue(result["exists"])
        self.assertTrue(result["executable"])
        self.assertTrue(result["is_pyguard"])


if __name__ == "__main__":
    unittest.main()
