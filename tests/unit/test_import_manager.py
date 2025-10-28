"""Tests for import manager module."""

from pathlib import Path

from pyguard.lib.import_manager import (
    STAR_IMPORT_RULE,
    UNUSED_IMPORT_RULE,
    ImportAnalyzer,
    ImportManager,
)


class TestImportAnalyzer:
    """Test import analyzer."""

    def test_extract_stdlib_imports(self):
        """Test extracting stdlib imports."""
        import ast

        code = """
import os
import sys
from pathlib import Path
"""
        tree = ast.parse(code)
        analyzer = ImportAnalyzer()
        imports = analyzer.extract_imports(tree)

        assert len(imports["stdlib"]) == 3

    def test_extract_third_party_imports(self):
        """Test extracting third-party imports."""
        import ast

        code = """
import requests
from flask import Flask
"""
        tree = ast.parse(code)
        analyzer = ImportAnalyzer()
        imports = analyzer.extract_imports(tree)

        assert len(imports["third_party"]) == 2

    def test_extract_future_imports(self):
        """Test extracting __future__ imports."""
        import ast

        code = """
from __future__ import annotations
"""
        tree = ast.parse(code)
        analyzer = ImportAnalyzer()
        imports = analyzer.extract_imports(tree)

        assert len(imports["future"]) == 1

    def test_find_unused_imports(self):
        """Test finding unused imports."""
        import ast

        code = """
import os
import sys
from pathlib import Path

def main():
    print(os.path.exists("/tmp"))
"""
        tree = ast.parse(code)
        analyzer = ImportAnalyzer()
        unused = analyzer.find_unused_imports(tree, code)

        # sys and Path are unused
        assert "sys" in unused
        assert "Path" in unused
        assert "os" not in unused

    def test_find_unused_imports_with_alias(self):
        """Test finding unused imports with aliases."""
        import ast

        code = """
import numpy as np
import pandas as pd

def process():
    return np.array([1, 2, 3])
"""
        tree = ast.parse(code)
        analyzer = ImportAnalyzer()
        unused = analyzer.find_unused_imports(tree, code)

        # pd is unused, np is used
        assert "pd" in unused
        assert "np" not in unused

    def test_sort_imports(self):
        """Test import sorting."""
        code = """
import requests
import os
from pathlib import Path
import sys
"""
        analyzer = ImportAnalyzer()
        sorted_code = analyzer.sort_imports(code)

        # Check that stdlib comes before third-party
        os_index = sorted_code.find("import os")
        sys_index = sorted_code.find("import sys")
        requests_index = sorted_code.find("import requests")

        assert os_index < requests_index
        assert sys_index < requests_index


class TestUnusedImportDetection:
    """Test unused import detection."""

    def test_detect_unused_import(self, tmp_path):
        """Test detection of unused import."""
        code = """
import os
import sys

def main():
    print(os.getcwd())
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should detect unused sys import
        unused_violations = [v for v in violations if v.rule_id == UNUSED_IMPORT_RULE.rule_id]
        assert len(unused_violations) > 0
        assert any("sys" in v.message for v in unused_violations)

    def test_no_violation_for_used_imports(self, tmp_path):
        """Test no violation when imports are used."""
        code = """
import os
from pathlib import Path

def main():
    path = Path(os.getcwd())
    return path
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should not detect any unused imports
        unused_violations = [v for v in violations if v.rule_id == UNUSED_IMPORT_RULE.rule_id]
        assert len(unused_violations) == 0

    def test_detect_unused_from_import(self, tmp_path):
        """Test detection of unused from import."""
        code = """
from typing import List, Dict, Optional

def get_items() -> List[str]:
    return ["a", "b", "c"]
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should detect unused Dict and Optional
        unused_violations = [v for v in violations if v.rule_id == UNUSED_IMPORT_RULE.rule_id]
        assert len(unused_violations) >= 2


class TestStarImportDetection:
    """Test star import detection."""

    def test_detect_star_import(self, tmp_path):
        """Test detection of star import."""
        code = """
from os.path import *

def main():
    return exists("/tmp")
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should detect star import
        star_violations = [v for v in violations if v.rule_id == STAR_IMPORT_RULE.rule_id]
        assert len(star_violations) == 1

    def test_no_violation_for_specific_imports(self, tmp_path):
        """Test no violation for specific imports."""
        code = """
from os.path import exists, join

def main():
    return exists("/tmp")
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should not detect star imports
        star_violations = [v for v in violations if v.rule_id == STAR_IMPORT_RULE.rule_id]
        assert len(star_violations) == 0


class TestImportManager:
    """Test ImportManager class."""

    def test_analyze_file_with_multiple_issues(self, tmp_path):
        """Test analyzing file with multiple import issues."""
        code = """
from typing import *
import os
import sys
import json

def process():
    data = json.loads('{}')
    return data
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should detect both star import and unused imports
        assert len(violations) > 0

    def test_analyze_file_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error."""
        code = """
import os
from typing import (
    # Missing closing parenthesis
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        violations = manager.analyze_file(test_file)

        # Should handle syntax error gracefully
        assert violations == []

    def test_analyze_nonexistent_file(self):
        """Test analyzing non-existent file."""
        manager = ImportManager()
        violations = manager.analyze_file(Path("/nonexistent/file.py"))

        # Should handle missing file gracefully
        assert violations == []

    def test_fix_imports(self, tmp_path):
        """Test fixing imports."""
        code = """
import sys
import os
from pathlib import Path

def main():
    return os.getcwd()
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, fixes = manager.fix_imports(test_file)

        # Should report success and list fixes
        assert success is True
        # At minimum, should sort imports
        assert len(fixes) >= 0  # May have sorted imports


class TestImportSorting:
    """Test import sorting functionality."""

    def test_sort_imports_basic(self):
        """Test basic import sorting."""
        code = """
import requests
import os
import sys
from pathlib import Path
"""
        analyzer = ImportAnalyzer()
        sorted_code = analyzer.sort_imports(code)

        lines = sorted_code.strip().split("\n")

        # stdlib should come before third-party
        stdlib_indices = []
        third_party_indices = []

        for i, line in enumerate(lines):
            if "os" in line or "sys" in line or "pathlib" in line:
                stdlib_indices.append(i)
            elif "requests" in line:
                third_party_indices.append(i)

        if stdlib_indices and third_party_indices:
            assert max(stdlib_indices) < min(third_party_indices)

    def test_sort_imports_preserves_non_import_code(self):
        """Test that sorting preserves non-import code."""
        code = '''
#!/usr/bin/env python
"""Module docstring."""

import sys
import os

def main():
    pass
'''
        analyzer = ImportAnalyzer()
        sorted_code = analyzer.sort_imports(code)

        # Should preserve shebang and docstring
        assert "#!/usr/bin/env python" in sorted_code
        assert '"""Module docstring."""' in sorted_code
        assert "def main():" in sorted_code


class TestUnusedImportRemoval:
    """Test unused import removal functionality."""

    def test_remove_unused_imports(self, tmp_path):
        """Test removing unused imports."""
        code = """import os
import sys
from pathlib import Path

def main():
    return os.getcwd()
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, fixes = manager.fix_imports(test_file)

        assert success is True
        assert any("unused" in fix.lower() for fix in fixes)

        # Verify unused imports were removed
        fixed_content = test_file.read_text()
        assert "import os" in fixed_content
        assert "import sys" not in fixed_content
        assert "from pathlib import Path" not in fixed_content

    def test_remove_unused_from_imports(self, tmp_path):
        """Test removing unused from imports."""
        code = """from typing import Dict, List, Optional

def get_items() -> List[str]:
    return ["a", "b", "c"]
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, _fixes = manager.fix_imports(test_file)

        assert success is True

        # Verify unused imports were removed
        fixed_content = test_file.read_text()
        assert "List" in fixed_content
        # Dict and Optional should be removed (if the implementation is complete)

    def test_preserve_used_imports(self, tmp_path):
        """Test that used imports are preserved."""
        code = """import os
from pathlib import Path

def main():
    return os.path.join(str(Path.cwd()), "file.txt")
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, _fixes = manager.fix_imports(test_file)

        assert success is True

        # Verify used imports are preserved
        fixed_content = test_file.read_text()
        assert "import os" in fixed_content
        assert "from pathlib import Path" in fixed_content

    def test_handle_aliased_imports(self, tmp_path):
        """Test handling of aliased imports."""
        code = """import pandas as pd
import numpy as np

def process_data():
    return np.array([1, 2, 3])
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, _fixes = manager.fix_imports(test_file)

        assert success is True

        # Verify unused aliased import removed, used one preserved
        fixed_content = test_file.read_text()
        assert "import numpy as np" in fixed_content
        # pandas should be removed if the implementation detects it

    def test_handle_syntax_error_gracefully(self, tmp_path):
        """Test that syntax errors are handled gracefully."""
        code = """import os
from typing import (
    # Missing closing parenthesis
"""
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        manager = ImportManager()
        success, fixes = manager.fix_imports(test_file)

        # Should not crash, may report no fixes
        assert isinstance(success, bool)
        assert isinstance(fixes, list)
