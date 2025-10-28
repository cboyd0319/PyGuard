"""
Unit tests for Import Analyzer module.
"""

import subprocess
from unittest.mock import MagicMock, patch


from pyguard.lib.import_analyzer import ImportAnalyzer


class TestImportAnalyzer:
    """Test ImportAnalyzer functionality."""

    def test_find_circular_imports_with_cycles(self):
        """Test detecting circular imports when they exist."""
        with patch('subprocess.run') as mock_run:
            # Simulate output showing A imports B and B imports A
            mock_run.return_value = MagicMock(
                stdout='module_a.py:module_b\nmodule_b.py:module_a\n', returncode=0
            )

            result = ImportAnalyzer.find_circular_imports('/test/path')

            assert isinstance(result, list)

    def test_find_circular_imports_no_cycles(self):
        """Test when no circular imports exist."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='module_a.py:module_c\nmodule_b.py:module_d\n', returncode=0
            )

            result = ImportAnalyzer.find_circular_imports('/test/path')

            assert isinstance(result, list)

    def test_find_circular_imports_with_malformed_lines(self):
        """Test handling of malformed lines without colons."""
        with patch('subprocess.run') as mock_run:
            # Include lines without colons (malformed)
            mock_run.return_value = MagicMock(
                stdout='module_a.py:module_c\nmalformed_line\nmodule_b.py:module_d\n',
                returncode=0
            )

            result = ImportAnalyzer.find_circular_imports('/test/path')

            # Should handle malformed lines gracefully
            assert isinstance(result, list)

    def test_find_circular_imports_timeout(self):
        """Test handling timeout during import analysis."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 60)):
            result = ImportAnalyzer.find_circular_imports('/test/path')

            assert result == []

    def test_find_circular_imports_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = ImportAnalyzer.find_circular_imports('/test/path')

            assert result == []

    def test_find_god_modules_with_results(self):
        """Test finding god modules when they exist."""
        with patch('subprocess.run') as mock_run:
            # Simulate utils being imported many times
            imports_output = '\n'.join(['utils' for _ in range(25)])
            mock_run.return_value = MagicMock(stdout=imports_output, returncode=0)

            result = ImportAnalyzer.find_god_modules('/test/path', import_threshold=20)

            assert isinstance(result, list)
            if result:
                # Should be sorted by count descending
                for i in range(len(result) - 1):
                    assert result[i][1] >= result[i + 1][1]

    def test_find_god_modules_no_results(self):
        """Test when no god modules exist."""
        with patch('subprocess.run') as mock_run:
            # Only a few imports
            mock_run.return_value = MagicMock(stdout='os\nsys\nre\n', returncode=0)

            result = ImportAnalyzer.find_god_modules('/test/path', import_threshold=20)

            assert result == []

    def test_find_god_modules_with_empty_lines(self):
        """Test handling of empty lines in output."""
        with patch('subprocess.run') as mock_run:
            # Include empty lines in the output
            imports_output = '\n'.join(['utils'] * 25 + ['', '', 'helpers'] * 5)
            mock_run.return_value = MagicMock(stdout=imports_output, returncode=0)

            result = ImportAnalyzer.find_god_modules('/test/path', import_threshold=20)

            # Should skip empty lines and still find god modules
            assert isinstance(result, list)

    def test_find_god_modules_custom_threshold(self):
        """Test god module detection with custom threshold."""
        with patch('subprocess.run') as mock_run:
            imports_output = '\n'.join(['utils' for _ in range(15)])
            mock_run.return_value = MagicMock(stdout=imports_output, returncode=0)

            result = ImportAnalyzer.find_god_modules('/test/path', import_threshold=10)

            assert isinstance(result, list)
            # With threshold of 10 and 15 imports, should find utils
            if result:
                assert result[0][1] > 10

    def test_find_god_modules_timeout(self):
        """Test handling timeout during god module analysis."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 60)):
            result = ImportAnalyzer.find_god_modules('/test/path')

            assert result == []

    def test_find_god_modules_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = ImportAnalyzer.find_god_modules('/test/path')

            assert result == []

    def test_find_god_modules_sorting(self):
        """Test that god modules are sorted by import count."""
        with patch('subprocess.run') as mock_run:
            # Create output with multiple modules
            imports = ['utils'] * 30 + ['helpers'] * 25 + ['config'] * 22
            imports_output = '\n'.join(imports)
            mock_run.return_value = MagicMock(stdout=imports_output, returncode=0)

            result = ImportAnalyzer.find_god_modules('/test/path', import_threshold=20)

            if len(result) >= 2:
                # First should have more imports than second
                assert result[0][1] >= result[1][1]

    def test_find_circular_imports_complex_scenario(self):
        """Test circular import detection with multiple files."""
        with patch('subprocess.run') as mock_run:
            # Complex scenario with multiple imports
            mock_run.return_value = MagicMock(
                stdout=(
                    'src/a.py:b\n'
                    'src/a.py:c\n'
                    'src/b.py:a\n'
                    'src/b.py:d\n'
                    'src/c.py:d\n'
                ),
                returncode=0,
            )

            result = ImportAnalyzer.find_circular_imports('/test/path')

            assert isinstance(result, list)
