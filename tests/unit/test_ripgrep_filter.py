"""
Unit tests for RipGrep filter module.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyguard.lib.ripgrep_filter import RipGrepFilter


class TestRipGrepFilter:
    """Test RipGrepFilter functionality."""

    def test_is_ripgrep_available_when_installed(self):
        """Test ripgrep availability check when installed."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert RipGrepFilter.is_ripgrep_available() is True

    def test_is_ripgrep_available_when_not_installed(self):
        """Test ripgrep availability check when not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            assert RipGrepFilter.is_ripgrep_available() is False

    def test_is_ripgrep_available_when_timeout(self):
        """Test ripgrep availability check when timeout occurs."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 5)):
            assert RipGrepFilter.is_ripgrep_available() is False

    def test_find_suspicious_files_with_matches(self):
        """Test finding suspicious files when matches exist."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='file1.py\nfile2.py\nfile3.py\n', returncode=0
            )

            result = RipGrepFilter.find_suspicious_files('/test/path')

            assert result == {'file1.py', 'file2.py', 'file3.py'}
            mock_run.assert_called_once()

    def test_find_suspicious_files_with_no_matches(self):
        """Test finding suspicious files when no matches exist."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='', returncode=0)

            result = RipGrepFilter.find_suspicious_files('/test/path')

            assert result == set()

    def test_find_suspicious_files_with_custom_patterns(self):
        """Test finding suspicious files with custom patterns."""
        custom_patterns = [r'eval\(', r'exec\(']

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='test.py\n', returncode=0)

            result = RipGrepFilter.find_suspicious_files('/test/path', patterns=custom_patterns)

            assert 'test.py' in result
            # Verify custom patterns were used
            call_args = mock_run.call_args[0][0]
            assert 'eval\\(|exec\\(' in call_args

    def test_find_suspicious_files_timeout(self):
        """Test handling timeout during file search."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 60)):
            result = RipGrepFilter.find_suspicious_files('/test/path')

            assert result == set()

    def test_find_suspicious_files_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = RipGrepFilter.find_suspicious_files('/test/path')

            assert result == set()

    def test_security_patterns_defined(self):
        """Test that security patterns are defined."""
        assert len(RipGrepFilter.SECURITY_PATTERNS) > 0
        assert r'\beval\s*\(' in RipGrepFilter.SECURITY_PATTERNS
        assert r'\bexec\s*\(' in RipGrepFilter.SECURITY_PATTERNS

    def test_find_suspicious_files_removes_empty_strings(self):
        """Test that empty strings are removed from results."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='file1.py\n\n\nfile2.py\n', returncode=0)

            result = RipGrepFilter.find_suspicious_files('/test/path')

            assert result == {'file1.py', 'file2.py'}
            assert '' not in result
