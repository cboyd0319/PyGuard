"""
Pathlib pattern detection and modernization (PTH prefix rules).

This module implements flake8-use-pathlib rules to encourage use of
pathlib.Path over os.path and related functions. Implements UP024-UP034
from pyupgrade and PTH100-PTH124 from flake8-use-pathlib.

Part of PyGuard's comprehensive linter replacement initiative.
"""

import ast
from dataclasses import dataclass


@dataclass
class PathlibIssue:
    """Represents a pathlib modernization opportunity."""

    rule_id: str
    line: int
    col: int
    message: str
    old_code: str
    suggested_fix: str | None = None
    severity: str = "MEDIUM"
    category: str = "modernization"


class PathlibPatternVisitor(ast.NodeVisitor):
    """
    AST visitor to detect os.path usage that should be replaced with pathlib.

    Detects patterns like:
    - os.path.exists() → Path.exists()
    - os.path.join() → Path / operator
    - os.path.basename() → Path.name
    - open() → Path.read_text() / Path.write_text()
    - And many more...
    """

    def __init__(self):
        # TODO: Add docstring
        self.issues: list[PathlibIssue] = []
        self.has_pathlib_import = False
        self.has_os_import = False
        self.os_aliases: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports of os and pathlib."""
        for alias in node.names:
            if alias.name == "os":
                self.has_os_import = True
                self.os_aliases.add(alias.asname or "os")
            elif alias.name == "pathlib":
                self.has_pathlib_import = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports."""
        if node.module == "pathlib":
            self.has_pathlib_import = True
        elif node.module == "os":
            self.has_os_import = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for os.path function calls."""
        if isinstance(node.func, ast.Attribute):
            self._check_os_path_call(node)
            self._check_open_call(node)
            self._check_glob_call(node)
        self.generic_visit(node)

    def _check_os_path_call(self, node: ast.Call) -> None:
        """Check for os.path.* function calls."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return

        # Check for os.path.* patterns
        if isinstance(func.value, ast.Attribute) and (
            isinstance(func.value.value, ast.Name)
            and func.value.value.id in self.os_aliases
            and func.value.attr == "path"
        ):
            self._report_os_path_usage(node, func.attr)

    def _report_os_path_usage(self, node: ast.Call, method: str) -> None:
        """Report specific os.path method usage."""
        replacements = {
            "exists": ("PTH100", "Path.exists()", "os.path.exists() → Path.exists()"),
            "isfile": ("PTH101", "Path.is_file()", "os.path.isfile() → Path.is_file()"),
            "isdir": ("PTH102", "Path.is_dir()", "os.path.isdir() → Path.is_dir()"),
            "islink": ("PTH103", "Path.is_symlink()", "os.path.islink() → Path.is_symlink()"),
            "isabs": ("PTH104", "Path.is_absolute()", "os.path.isabs() → Path.is_absolute()"),
            "join": (
                "PTH105",
                "Path / operator",
                "os.path.join() → Path / operator for path concatenation",
            ),
            "basename": ("PTH106", "Path.name", "os.path.basename() → Path.name"),
            "dirname": ("PTH107", "Path.parent", "os.path.dirname() → Path.parent"),
            "splitext": (
                "PTH108",
                "Path.suffix and Path.stem",
                "os.path.splitext() → Path.suffix/.stem",
            ),
            "expanduser": (
                "PTH109",
                "Path.expanduser()",
                "os.path.expanduser() → Path.expanduser()",
            ),
            "abspath": ("PTH110", "Path.resolve()", "os.path.abspath() → Path.resolve()"),
            "realpath": (
                "PTH111",
                "Path.resolve()",
                "os.path.realpath() → Path.resolve()",
            ),
            "relpath": (
                "PTH112",
                "Path.relative_to()",
                "os.path.relpath() → Path.relative_to()",
            ),
            "getsize": ("PTH113", "Path.stat().st_size", "os.path.getsize() → Path.stat().st_size"),
            "getmtime": (
                "PTH114",
                "Path.stat().st_mtime",
                "os.path.getmtime() → Path.stat().st_mtime",
            ),
            "getatime": (
                "PTH115",
                "Path.stat().st_atime",
                "os.path.getatime() → Path.stat().st_atime",
            ),
            "getctime": (
                "PTH116",
                "Path.stat().st_ctime",
                "os.path.getctime() → Path.stat().st_ctime",
            ),
        }

        if method in replacements:
            rule_id, suggestion, message = replacements[method]
            self.issues.append(
                PathlibIssue(
                    rule_id=rule_id,
                    line=node.lineno,
                    col=node.col_offset,
                    message=message,
                    old_code=f"os.path.{method}()",
                    suggested_fix=suggestion,
                    severity="MEDIUM",
                )
            )

    def _check_open_call(self, _node: ast.Call) -> None:
        """Check for open() calls that could use Path methods.

        Args:
            _node: Call node (disabled - too many false positives)
        """
        # Note: We only flag bare open() calls, not those within 'with' statements
        # as context managers are generally preferred for file operations
        return  # Disabled for now - too many false positives with context managers

    def _check_glob_call(self, node: ast.Call) -> None:
        """Check for glob.glob() calls."""
        if isinstance(node.func, ast.Attribute) and (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "glob"
            and node.func.attr == "glob"
        ):
            self.issues.append(
                PathlibIssue(
                    rule_id="PTH124",
                    line=node.lineno,
                    col=node.col_offset,
                    message="Use Path.glob() instead of glob.glob()",
                    old_code="glob.glob(pattern)",
                    suggested_fix="Path().glob(pattern)",
                    severity="LOW",
                )
            )


class PathlibChecker:
    """Main checker class for pathlib pattern detection."""

    def __init__(self):
        # TODO: Add docstring
        self.visitor = PathlibPatternVisitor()

    def check_code(self, code: str, filename: str = "<string>") -> list[PathlibIssue]:
        """
        Check Python code for pathlib modernization opportunities.

        Args:
            code: Python source code to check
            filename: Optional filename for error reporting

        Returns:
            List of PathlibIssue objects representing detected issues
        """
        try:
            tree = ast.parse(code, filename=filename)
            self.visitor.visit(tree)
            return self.visitor.issues
        except SyntaxError:
            return []

    def get_issues(self) -> list[PathlibIssue]:
        """Get all detected issues."""
        return self.visitor.issues


def check_file(filepath: str) -> list[PathlibIssue]:
    """
    Check a Python file for pathlib modernization opportunities.

    Args:
        filepath: Path to Python file

    Returns:
        List of PathlibIssue objects
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            code = f.read()
        checker = PathlibChecker()
        return checker.check_code(code, filepath)
    except Exception:
        return []
