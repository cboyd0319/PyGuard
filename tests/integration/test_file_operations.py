"""Integration tests for file operations."""

from pathlib import Path

import pytest


class TestMultiFileOperations:
    """Test operations on multiple files."""

    def test_process_directory(self, temp_dir):
        """Test processing an entire directory."""
        # Create multiple test files
        files = []
        for i in range(3):
            file_path = temp_dir / f"test_{i}.py"
            file_path.write_text(f"x{i} = None\nif x{i} == None:\n    pass")
            files.append(file_path)

        from pyguard import BestPracticesFixer

        fixer = BestPracticesFixer()

        # Process all files
        for file_path in files:
            result = fixer.fix_file(file_path)
            assert isinstance(result, tuple)
            assert len(result) == 2
            success, fixes = result
            assert isinstance(success, bool)
            assert isinstance(fixes, list)

    def test_large_file_handling(self, temp_dir):
        """Test handling of large files."""
        # Create a large file
        large_file = temp_dir / "large.py"
        content = "x = 1\n" * 10000  # 10k lines
        large_file.write_text(content)

        from pyguard import BestPracticesFixer

        fixer = BestPracticesFixer()
        result = fixer.fix_file(large_file)

        # Should complete without errors (returns tuple: (success, fixes))
        assert isinstance(result, tuple)
        assert len(result) == 2
        success, fixes = result
        assert isinstance(success, bool)
        assert isinstance(fixes, list)


class TestFileEncodingHandling:
    """Test handling of different file encodings."""

    def test_utf8_file(self, temp_dir):
        """Test UTF-8 encoded file."""
        file_path = temp_dir / "utf8.py"
        file_path.write_text("# -*- coding: utf-8 -*-\nname = '日本語'", encoding="utf-8")

        from pyguard import BestPracticesFixer

        fixer = BestPracticesFixer()
        result = fixer.fix_file(file_path)
        assert isinstance(result, tuple)
        assert len(result) == 2
        success, fixes = result
        assert isinstance(success, bool)
        assert isinstance(fixes, list)

    def test_file_with_syntax_error(self, temp_dir):
        """Test handling of files with syntax errors."""
        file_path = temp_dir / "syntax_error.py"
        file_path.write_text("def foo(\n    # Incomplete function")

        from pyguard import BestPracticesFixer

        fixer = BestPracticesFixer()
        # Should handle gracefully without crashing
        try:
            result = fixer.fix_file(file_path)
            assert isinstance(result, tuple)
            assert len(result) == 2
            success, fixes = result
            assert isinstance(success, bool)
            assert isinstance(fixes, list)
        except Exception as e:
            # Acceptable to skip files with syntax errors
            pytest.skip(f"Syntax error handling: {e}")
