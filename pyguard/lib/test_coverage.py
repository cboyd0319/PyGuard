"""
Find Python modules without test coverage using ripgrep.

Analyzes test coverage by comparing source files to test files.
"""

import subprocess
from pathlib import Path
from typing import List


class TestCoverageAnalyzer:
    """
    Find modules without test coverage using ripgrep.
    """

    @staticmethod
    def find_untested_modules(src_dir: str, test_dir: str = 'tests') -> List[str]:
        """
        Find source files without corresponding test files.

        Args:
            src_dir: Source directory to analyze
            test_dir: Test directory to check for test files

        Returns:
            List of untested module paths
        """
        try:
            # Find all source Python files
            src_result = subprocess.run(
                ['rg', '--files', '--type', 'py', src_dir],
                capture_output=True,
                text=True,
                timeout=60,
            )

            src_files = src_result.stdout.strip().split('\n')

            # Find all test files
            test_result = subprocess.run(
                ['rg', '--files', '--type', 'py', test_dir],
                capture_output=True,
                text=True,
                timeout=60,
            )

            test_files = set(test_result.stdout.strip().split('\n'))

            untested = []
            for src_file in src_files:
                if src_file and src_file != '__init__.py':
                    # Generate expected test filename
                    base_name = Path(src_file).stem
                    expected_tests = [
                        f'{test_dir}/test_{base_name}.py',
                        f'{test_dir}/{base_name}_test.py',
                    ]

                    if not any(test_file in test_files for test_file in expected_tests):
                        untested.append(src_file)

            return untested

        except subprocess.TimeoutExpired:
            print("Warning: Test coverage analysis timeout")
            return []
        except FileNotFoundError:
            # ripgrep not available
            return []

    @staticmethod
    def calculate_test_coverage_ratio(src_dir: str, test_dir: str = 'tests') -> float:
        """
        Calculate percentage of modules with tests.

        Args:
            src_dir: Source directory to analyze
            test_dir: Test directory to check for test files

        Returns:
            Test coverage ratio as a percentage
        """
        untested = TestCoverageAnalyzer.find_untested_modules(src_dir, test_dir)

        src_count = len(list(Path(src_dir).rglob('*.py')))
        tested_count = src_count - len(untested)

        return (tested_count / src_count * 100) if src_count > 0 else 0
