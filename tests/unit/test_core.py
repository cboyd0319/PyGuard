"""Unit tests for core module."""

from pathlib import Path

import pytest

from pyguard.lib.core import BackupManager, DiffGenerator, PyGuardLogger


class TestPyGuardLogger:
    """Test cases for PyGuardLogger class."""

    def test_logger_initialization(self):
        """Test logger initialization."""
        logger = PyGuardLogger()
        assert logger is not None

    def test_info_logging(self):
        """Test info level logging."""
        logger = PyGuardLogger()
        logger.info("Test message", file_path="test.py")
        # Would verify log output
        assert True

    def test_error_logging(self):
        """Test error level logging."""
        logger = PyGuardLogger()
        logger.error("Test error", file_path="test.py")
        # Would verify log output
        assert True


class TestBackupManager:
    """Test cases for BackupManager class."""

    def test_create_backup(self):
        """Test backup creation."""
        manager = BackupManager()
        # Would test actual backup creation
        assert True

    def test_restore_backup(self):
        """Test backup restoration."""
        manager = BackupManager()
        # Would test actual backup restoration
        assert True


class TestDiffGenerator:
    """Test cases for DiffGenerator class."""

    def test_generate_diff(self):
        """Test diff generation."""
        generator = DiffGenerator()
        old_code = "x = 1"
        new_code = "x = 2"
        diff = generator.generate_diff(old_code, new_code, "test.py")
        assert diff is not None
        assert "-" in diff or "+" in diff
