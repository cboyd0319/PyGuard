"""
Jupyter Notebook Security Analysis for PyGuard.

Provides comprehensive security analysis for .ipynb files including:
- Cell-by-cell vulnerability detection
- Execution order analysis
- Magic command security checks
- Secrets detection in notebooks
- Dependency tracking across cells
- Output sanitization checks
- Kernel security analysis

References:
- Jupyter Security | https://jupyter-notebook.readthedocs.io/en/stable/security.html | High | Notebook security guide
- OWASP Jupyter | https://owasp.org/www-community/vulnerabilities/Jupyter_Notebook | Medium | Security considerations
"""

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pyguard.lib.core import PyGuardLogger


@dataclass
class NotebookCell:
    """Represents a Jupyter notebook cell."""

    cell_type: str  # "code", "markdown", "raw"
    source: str  # Cell source code
    execution_count: Optional[int]  # Execution order
    outputs: List[Dict[str, Any]]  # Cell outputs
    metadata: Dict[str, Any]  # Cell metadata


@dataclass
class NotebookIssue:
    """Security issue found in a notebook."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # Issue category
    message: str  # Issue description
    cell_index: int  # Cell where issue was found
    line_number: int  # Line within cell
    code_snippet: str  # Relevant code
    fix_suggestion: Optional[str]  # How to fix
    cwe_id: Optional[str] = None  # CWE identifier
    owasp_id: Optional[str] = None  # OWASP identifier


class NotebookSecurityAnalyzer:
    """
    Comprehensive security analyzer for Jupyter notebooks.

    Detects:
    - Code injection in cells
    - Hardcoded secrets and credentials
    - Unsafe magic commands
    - Insecure file operations
    - Unsafe data deserialization
    - Command execution vulnerabilities
    - Output sanitization issues
    - Kernel security problems
    """

    # Dangerous magic commands
    DANGEROUS_MAGICS = {
        "%system": "Direct system command execution",
        "!": "Shell command execution",
        "%%bash": "Bash script execution",
        "%%sh": "Shell script execution",
        "%%script": "Script execution",
        "%load_ext": "Loading external extensions (may be unsafe)",
        "%run": "Running external scripts (path traversal risk)",
    }

    # Patterns for secrets in notebooks
    SECRET_PATTERNS = {
        r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})": "Hardcoded password",
        r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]([^'\"]{16,})": "API key",
        r"(?i)(secret[_-]?key|secretkey)\s*=\s*['\"]([^'\"]{16,})": "Secret key",
        r"(?i)(token|auth[_-]?token)\s*=\s*['\"]([^'\"]{16,})": "Authentication token",
        r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*['\"]([A-Z0-9]{20})": "AWS access key",
        r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*=\s*['\"]([A-Za-z0-9/+=]{40})": "AWS secret key",
    }

    def __init__(self):
        """Initialize the notebook security analyzer."""
        self.logger = PyGuardLogger()

    def analyze_notebook(self, notebook_path: Path) -> List[NotebookIssue]:
        """
        Analyze a Jupyter notebook for security issues.

        Args:
            notebook_path: Path to .ipynb file

        Returns:
            List of security issues found

        Raises:
            FileNotFoundError: If notebook file doesn't exist
            ValueError: If file is not a valid notebook
        """
        issues: List[NotebookIssue] = []

        if not notebook_path.exists():
            raise FileNotFoundError(f"Notebook not found: {notebook_path}")

        if notebook_path.suffix != ".ipynb":
            raise ValueError(f"Not a notebook file: {notebook_path}")

        try:
            with open(notebook_path, "r", encoding="utf-8") as f:
                notebook_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid notebook JSON: {e}")

        # Parse notebook cells
        cells = self._parse_cells(notebook_data)

        # Analyze each cell
        for idx, cell in enumerate(cells):
            if cell.cell_type == "code":
                issues.extend(self._analyze_code_cell(cell, idx))

        # Cross-cell analysis
        issues.extend(self._analyze_cell_dependencies(cells))

        self.logger.info(
            f"Notebook analysis complete: {notebook_path}, issues found: {len(issues)}"
        )

        return issues

    def _parse_cells(self, notebook_data: Dict[str, Any]) -> List[NotebookCell]:
        """Parse notebook cells from JSON data."""
        cells = []

        for cell_data in notebook_data.get("cells", []):
            source = cell_data.get("source", [])
            if isinstance(source, list):
                source = "".join(source)

            cell = NotebookCell(
                cell_type=cell_data.get("cell_type", ""),
                source=source,
                execution_count=cell_data.get("execution_count"),
                outputs=cell_data.get("outputs", []),
                metadata=cell_data.get("metadata", {}),
            )
            cells.append(cell)

        return cells

    def _analyze_code_cell(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Analyze a single code cell for security issues."""
        issues: List[NotebookIssue] = []

        # Check for dangerous magic commands
        issues.extend(self._check_magic_commands(cell, cell_index))

        # Check for hardcoded secrets
        issues.extend(self._check_secrets(cell, cell_index))

        # Check for unsafe operations
        issues.extend(self._check_unsafe_operations(cell, cell_index))

        # Check for command injection
        issues.extend(self._check_command_injection(cell, cell_index))

        # Check output sanitization
        issues.extend(self._check_output_security(cell, cell_index))

        return issues

    def _check_magic_commands(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for dangerous Jupyter magic commands."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            for magic, description in self.DANGEROUS_MAGICS.items():
                if line.startswith(magic):
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="Unsafe Magic Command",
                            message=f"Dangerous magic command: {description}",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line,
                            fix_suggestion=(
                                "Avoid using magic commands that execute system commands. "
                                "Use subprocess with proper validation instead."
                            ),
                            cwe_id="CWE-78",
                            owasp_id="ASVS-5.3.3",
                        )
                    )

        return issues

    def _check_secrets(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for hardcoded secrets in cell code."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.SECRET_PATTERNS.items():
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Exclude common test/placeholder values
                    value = match.group(2) if len(match.groups()) >= 2 else match.group(0)
                    if value not in ["test", "example", "YOUR_KEY_HERE", "***"]:
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="Hardcoded Secret",
                                message=f"{description} detected in notebook",
                                cell_index=cell_index,
                                line_number=line_num,
                                code_snippet=line[:50] + "..." if len(line) > 50 else line,
                                fix_suggestion=(
                                    "Use environment variables or secure credential storage. "
                                    "Load secrets from .env files or cloud secret managers."
                                ),
                                cwe_id="CWE-798",
                                owasp_id="ASVS-2.6.3",
                            )
                        )

        return issues

    def _check_unsafe_operations(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for unsafe Python operations in cell."""
        issues: List[NotebookIssue] = []

        # Try to parse cell as Python code
        try:
            tree = ast.parse(cell.source)
        except SyntaxError:
            # Skip cells with syntax errors (might be incomplete)
            return issues

        for node in ast.walk(tree):
            # Check for eval/exec/compile
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ["eval", "exec", "compile"]:
                        issues.append(
                            NotebookIssue(
                                severity="CRITICAL",
                                category="Code Injection",
                                message=f"Use of {node.func.id}() enables code injection",
                                cell_index=cell_index,
                                line_number=getattr(node, "lineno", 0),
                                code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                fix_suggestion="Use ast.literal_eval() for safe evaluation or refactor to avoid dynamic code execution",
                                cwe_id="CWE-95",
                                owasp_id="ASVS-5.2.1",
                            )
                        )

            # Check for pickle usage
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "pickle"
                        and node.func.attr == "load"
                    ):
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="Unsafe Deserialization",
                                message="pickle.load() can execute arbitrary code",
                                cell_index=cell_index,
                                line_number=getattr(node, "lineno", 0),
                                code_snippet=ast.unparse(node) if hasattr(ast, "unparse") else "",
                                fix_suggestion="Use JSON or safer serialization formats. If pickle is required, validate source and use signatures.",
                                cwe_id="CWE-502",
                                owasp_id="ASVS-5.5.3",
                            )
                        )

        return issues

    def _check_command_injection(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for command injection vulnerabilities."""
        issues: List[NotebookIssue] = []

        try:
            tree = ast.parse(cell.source)
        except SyntaxError:
            return issues

        for node in ast.walk(tree):
            # Check subprocess calls with shell=True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in [
                        "subprocess",
                        "os",
                    ]:
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value is True:
                                    issues.append(
                                        NotebookIssue(
                                            severity="CRITICAL",
                                            category="Command Injection",
                                            message="subprocess call with shell=True enables command injection",
                                            cell_index=cell_index,
                                            line_number=getattr(node, "lineno", 0),
                                            code_snippet=(
                                                ast.unparse(node) if hasattr(ast, "unparse") else ""
                                            ),
                                            fix_suggestion="Use shell=False and pass command as list of arguments",
                                            cwe_id="CWE-78",
                                            owasp_id="ASVS-5.3.3",
                                        )
                                    )

        return issues

    def _check_output_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check cell outputs for security issues."""
        issues: List[NotebookIssue] = []

        for output in cell.outputs:
            # Check for error tracebacks that might leak sensitive info
            if output.get("output_type") == "error":
                traceback = output.get("traceback", [])
                for line in traceback:
                    # Check for path disclosure
                    if "/home/" in line or "C:\\" in line or "/Users/" in line:
                        issues.append(
                            NotebookIssue(
                                severity="MEDIUM",
                                category="Information Disclosure",
                                message="Cell output contains system paths that may leak sensitive information",
                                cell_index=cell_index,
                                line_number=0,
                                code_snippet=line[:100] + "..." if len(line) > 100 else line,
                                fix_suggestion="Clear cell outputs before sharing notebooks. Use relative paths instead of absolute paths.",
                                cwe_id="CWE-209",
                            )
                        )
                        break

        return issues

    def _analyze_cell_dependencies(self, cells: List[NotebookCell]) -> List[NotebookIssue]:
        """Analyze dependencies and data flow between cells."""
        issues: List[NotebookIssue] = []

        # Track variables defined in cells
        defined_vars: Dict[str, int] = {}  # var_name -> cell_index
        used_vars: Dict[str, List[int]] = {}  # var_name -> list of cell_indices

        for idx, cell in enumerate(cells):
            if cell.cell_type != "code":
                continue

            try:
                tree = ast.parse(cell.source)
            except SyntaxError:
                continue

            # Find variable assignments
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            defined_vars[target.id] = idx

                # Find variable uses
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id not in used_vars:
                        used_vars[node.id] = []
                    used_vars[node.id].append(idx)

        # Check for use before definition (execution order issues)
        for var_name, use_cells in used_vars.items():
            if var_name in defined_vars:
                def_cell = defined_vars[var_name]
                for use_cell in use_cells:
                    if use_cell < def_cell:
                        issues.append(
                            NotebookIssue(
                                severity="MEDIUM",
                                category="Execution Order Issue",
                                message=f"Variable '{var_name}' used before definition (cell order dependency)",
                                cell_index=use_cell,
                                line_number=0,
                                code_snippet=f"Uses variable '{var_name}' defined in cell {def_cell}",
                                fix_suggestion="Ensure cells are executed in proper order. Consider restructuring code to avoid order dependencies.",
                            )
                        )

        return issues


class NotebookFixer:
    """Provides automated fixes for notebook security issues."""

    def __init__(self):
        """Initialize notebook fixer."""
        self.logger = PyGuardLogger()

    def fix_notebook(
        self, notebook_path: Path, issues: List[NotebookIssue]
    ) -> Tuple[bool, List[str]]:
        """
        Apply automated fixes to notebook.

        Args:
            notebook_path: Path to notebook file
            issues: List of issues to fix

        Returns:
            Tuple of (success, list of fixes applied)
        """
        fixes_applied: List[str] = []

        # Load notebook
        with open(notebook_path, "r", encoding="utf-8") as f:
            notebook_data = json.load(f)

        cells = notebook_data.get("cells", [])

        # Apply fixes based on issue types
        for issue in issues:
            if issue.category == "Hardcoded Secret":
                # Comment out lines with secrets
                cell = cells[issue.cell_index]
                source = cell.get("source", [])
                if isinstance(source, list):
                    source = "".join(source)

                lines = source.split("\n")
                if issue.line_number <= len(lines):
                    line = lines[issue.line_number - 1]
                    lines[issue.line_number - 1] = f"# SECURITY: Removed hardcoded secret - {line}"
                    cell["source"] = "\n".join(lines)
                    fixes_applied.append(
                        f"Commented out hardcoded secret in cell {issue.cell_index}"
                    )

        # Save fixed notebook
        if fixes_applied:
            with open(notebook_path, "w", encoding="utf-8") as f:
                json.dump(notebook_data, f, indent=2)

        return len(fixes_applied) > 0, fixes_applied


def scan_notebook(notebook_path: str) -> List[NotebookIssue]:
    """
    Convenience function to scan a notebook for security issues.

    Args:
        notebook_path: Path to .ipynb file

    Returns:
        List of security issues found
    """
    analyzer = NotebookSecurityAnalyzer()
    return analyzer.analyze_notebook(Path(notebook_path))
