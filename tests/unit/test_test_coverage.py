"""
Unit tests for Test Coverage Analyzer module.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyguard.lib.test_coverage import TestCoverageAnalyzer


class TestTestCoverageAnalyzer:
    """Test TestCoverageAnalyzer functionality."""

    def test_find_untested_modules_with_missing_tests(self):
        """Test finding untested modules when tests are missing."""
        with patch('subprocess.run') as mock_run:
            # First call returns source files, second returns test files
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\nsrc/module_b.py\nsrc/module_c.py\n'),
                MagicMock(stdout='tests/test_module_a.py\n'),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert 'src/module_b.py' in result
            assert 'src/module_c.py' in result
            assert 'src/module_a.py' not in result

    def test_find_untested_modules_all_tested(self):
        """Test when all modules have tests."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\nsrc/module_b.py\n'),
                MagicMock(
                    stdout='tests/test_module_a.py\ntests/test_module_b.py\n'
                ),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert len(result) == 0

    def test_find_untested_modules_ignores_init(self):
        """Test that __init__.py files are ignored."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/__init__.py\nsrc/module_a.py\n'),
                MagicMock(stdout='tests/test_module_a.py\n'),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            # __init__.py should not be in untested list
            assert not any('__init__.py' in path for path in result)

    def test_find_untested_modules_timeout(self):
        """Test handling timeout during analysis."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 60)):
            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert result == []

    def test_find_untested_modules_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert result == []

    def test_calculate_test_coverage_ratio_perfect(self):
        """Test coverage ratio calculation with 100% coverage."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\nsrc/module_b.py\n'),
                MagicMock(
                    stdout='tests/test_module_a.py\ntests/test_module_b.py\n'
                ),
            ]

            with patch.object(Path, 'rglob') as mock_rglob:
                mock_rglob.return_value = [Path('src/module_a.py'), Path('src/module_b.py')]

                ratio = TestCoverageAnalyzer.calculate_test_coverage_ratio('src', 'tests')

                assert ratio == 100.0

    def test_calculate_test_coverage_ratio_partial(self):
        """Test coverage ratio calculation with partial coverage."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\nsrc/module_b.py\nsrc/module_c.py\n'),
                MagicMock(stdout='tests/test_module_a.py\n'),
            ]

            with patch.object(Path, 'rglob') as mock_rglob:
                mock_rglob.return_value = [
                    Path('src/module_a.py'),
                    Path('src/module_b.py'),
                    Path('src/module_c.py'),
                ]

                ratio = TestCoverageAnalyzer.calculate_test_coverage_ratio('src', 'tests')

                # 1 out of 3 tested = 33.33%
                assert 30 < ratio < 40

    def test_calculate_test_coverage_ratio_zero_files(self):
        """Test coverage ratio when there are no source files."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout=''),
                MagicMock(stdout=''),
            ]

            with patch.object(Path, 'rglob') as mock_rglob:
                mock_rglob.return_value = []

                ratio = TestCoverageAnalyzer.calculate_test_coverage_ratio('src', 'tests')

                assert ratio == 0

    def test_find_untested_modules_alternative_test_naming(self):
        """Test finding tests with alternative naming conventions."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\n'),
                MagicMock(stdout='tests/module_a_test.py\n'),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            # Should recognize module_a_test.py as a test for module_a.py
            assert 'src/module_a.py' not in result

    def test_find_untested_modules_empty_source(self):
        """Test with empty source directory."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout=''),
                MagicMock(stdout=''),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert result == []

    def test_find_untested_modules_empty_tests(self):
        """Test with no test files."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(stdout='src/module_a.py\nsrc/module_b.py\n'),
                MagicMock(stdout=''),
            ]

            result = TestCoverageAnalyzer.find_untested_modules('src', 'tests')

            assert 'src/module_a.py' in result
            assert 'src/module_b.py' in result
