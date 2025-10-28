"""
Code formatting fixes for Python.

Integrates with black, isort, autopep8 for automated formatting.
"""

import re
import subprocess
from pathlib import Path
from typing import Any

from pyguard.lib.core import FileOperations, PyGuardLogger


class FormattingFixer:
    """Automatically format Python code using industry-standard tools."""

    def __init__(self):
        """Initialize formatting fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def format_with_black(self, file_path: Path, line_length: int = 100) -> tuple[bool, str]:
        """
        Format file with Black.

        Args:
            file_path: Path to Python file
            line_length: Maximum line length

        Returns:
            Tuple of (success, output message)
        """
        try:
            result = subprocess.run(
                ["black", "--line-length", str(line_length), str(file_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.success(
                    "Formatted with Black",
                    category="Formatting",
                    file_path=str(file_path),
                )
                return True, result.stdout

            self.logger.warning(
                f"Black formatting had issues: {result.stderr}",
                category="Formatting",
                file_path=str(file_path),
            )
            return False, result.stderr

        except FileNotFoundError:
            error_msg = "Black is not installed. Run: pip install black"
            self.logger.error(error_msg, category="Formatting")
            return False, error_msg
        except subprocess.TimeoutExpired:
            error_msg = "Black formatting timed out"
            self.logger.error(error_msg, category="Formatting", file_path=str(file_path))
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running Black: {e!s}"
            self.logger.error(error_msg, category="Formatting", file_path=str(file_path))
            return False, error_msg

    def format_with_autopep8(self, file_path: Path, aggressive: int = 1) -> tuple[bool, str]:
        """
        Format file with autopep8.

        Args:
            file_path: Path to Python file
            aggressive: Aggressiveness level (0-2)

        Returns:
            Tuple of (success, output message)
        """
        try:
            args = ["autopep8", "--in-place"]

            if aggressive > 0:
                args.extend(["--aggressive"] * aggressive)

            args.append(str(file_path))

            result = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.success(
                    "Formatted with autopep8",
                    category="Formatting",
                    file_path=str(file_path),
                )
                return True, "Formatting applied"

            return False, result.stderr

        except FileNotFoundError:
            error_msg = "autopep8 is not installed. Run: pip install autopep8"
            self.logger.error(error_msg, category="Formatting")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running autopep8: {e!s}"
            self.logger.error(error_msg, category="Formatting", file_path=str(file_path))
            return False, error_msg

    def sort_imports_with_isort(self, file_path: Path) -> tuple[bool, str]:
        """
        Sort imports with isort.

        Args:
            file_path: Path to Python file

        Returns:
            Tuple of (success, output message)
        """
        try:
            result = subprocess.run(
                ["isort", str(file_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.success(
                    "Sorted imports with isort",
                    category="Formatting",
                    file_path=str(file_path),
                )
                return True, result.stdout

            return False, result.stderr

        except FileNotFoundError:
            error_msg = "isort is not installed. Run: pip install isort"
            self.logger.error(error_msg, category="Formatting")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running isort: {e!s}"
            self.logger.error(error_msg, category="Formatting", file_path=str(file_path))
            return False, error_msg

    def format_file(
        self,
        file_path: Path,
        use_black: bool = True,
        use_isort: bool = True,
        use_autopep8: bool = False,
    ) -> dict[str, Any]:
        """
        Format a Python file using specified formatters.

        Args:
            file_path: Path to Python file
            use_black: Whether to use Black
            use_isort: Whether to use isort
            use_autopep8: Whether to use autopep8

        Returns:
            Dictionary with formatting results
        """
        formatters_applied: list[str] = []
        errors: list[str] = []
        success_flag = True

        # Sort imports first (if using isort)
        if use_isort:
            success, output = self.sort_imports_with_isort(file_path)
            if success:
                formatters_applied.append("isort")
            else:
                errors.append(f"isort: {output}")
                success_flag = False

        # Format with autopep8 (if requested, before Black)
        if use_autopep8 and not use_black:
            success, output = self.format_with_autopep8(file_path)
            if success:
                formatters_applied.append("autopep8")
            else:
                errors.append(f"autopep8: {output}")
                success_flag = False

        # Format with Black (recommended)
        if use_black:
            success, output = self.format_with_black(file_path)
            if success:
                formatters_applied.append("black")
            else:
                errors.append(f"black: {output}")
                success_flag = False

        return {
            "file": str(file_path),
            "success": success_flag,
            "formatters_applied": formatters_applied,
            "errors": errors,
        }

    def format_directory(
        self,
        directory: Path,
        exclude_patterns: list[str] | None = None,
        **format_options,
    ) -> list[dict[str, Any]]:
        """
        Format all Python files in a directory.

        Args:
            directory: Directory to format
            exclude_patterns: Patterns to exclude
            **format_options: Options to pass to format_file

        Returns:
            List of formatting results
        """
        python_files = self.file_ops.find_python_files(directory, exclude_patterns)
        results = []

        for file_path in python_files:
            result = self.format_file(file_path, **format_options)
            results.append(result)

        # Summary
        successful = sum(1 for r in results if r["success"])
        self.logger.info(
            f"Formatted {successful}/{len(results)} files successfully",
            category="Formatting",
        )

        return results


class WhitespaceFixer:
    """Fix whitespace and indentation issues."""

    def __init__(self):
        """Initialize whitespace fixer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def fix_trailing_whitespace(self, content: str) -> tuple[str, int]:
        """
        Remove trailing whitespace from lines.

        Args:
            content: File content

        Returns:
            Tuple of (fixed content, number of lines fixed)
        """
        lines = content.split("\n")
        fixed_count = 0

        for i, line in enumerate(lines):
            if line.endswith(" ") or line.endswith("\t"):
                lines[i] = line.rstrip()
                fixed_count += 1

        return "\n".join(lines), fixed_count

    def fix_blank_lines(self, content: str) -> tuple[str, int]:
        """
        Fix excessive blank lines (PEP 8: max 2 consecutive).

        Args:
            content: File content

        Returns:
            Tuple of (fixed content, number of fixes)
        """
        # Replace 3+ consecutive blank lines with 2

        original_content = content
        content = re.sub(r"\n\n\n+", "\n\n\n", content)

        fixes = 0 if content == original_content else 1
        return content, fixes

    def fix_line_endings(self, content: str) -> tuple[str, bool]:
        """
        Ensure consistent line endings (LF).

        Args:
            content: File content

        Returns:
            Tuple of (fixed content, whether changes were made)
        """
        if "\r\n" in content:
            return content.replace("\r\n", "\n"), True
        return content, False

    def fix_file_whitespace(self, file_path: Path) -> dict[str, Any]:
        """
        Fix all whitespace issues in a file.

        Args:
            file_path: Path to Python file

        Returns:
            Dictionary with fix results
        """
        content = self.file_ops.read_file(file_path)
        if content is None:
            return {"success": False, "error": "Could not read file"}

        original_content = content
        fixes = []

        # Fix trailing whitespace
        content, count = self.fix_trailing_whitespace(content)
        if count > 0:
            fixes.append(f"Removed trailing whitespace from {count} lines")

        # Fix blank lines
        content, count = self.fix_blank_lines(content)
        if count > 0:
            fixes.append("Fixed excessive blank lines")

        # Fix line endings
        content, changed = self.fix_line_endings(content)
        if changed:
            fixes.append("Normalized line endings to LF")

        # Write back if changes were made
        if content != original_content:
            success = self.file_ops.write_file(file_path, content)
            if success:
                self.logger.success(
                    f"Fixed whitespace issues: {', '.join(fixes)}",
                    category="Formatting",
                    file_path=str(file_path),
                )
                return {"success": True, "fixes": fixes}
            return {"success": False, "error": "Could not write file"}

        return {"success": True, "fixes": []}
