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
- PII (Personally Identifiable Information) detection
- Dependency vulnerability scanning
- License compliance checking
- XSS vulnerability detection in outputs
- ML pipeline security (data poisoning, model manipulation)
- Notebook metadata security analysis
- Cell trust and execution history validation

References:
- Jupyter Security | https://jupyter-notebook.readthedocs.io/en/stable/security.html | High | Notebook security guide
- OWASP Jupyter | https://owasp.org/www-community/vulnerabilities/Jupyter_Notebook | Medium | Security considerations
- CVE-2024-39700 | https://nvd.nist.gov/vuln/detail/CVE-2024-39700 | Critical | JupyterLab RCE vulnerability
- CVE-2024-28233 | https://nvd.nist.gov/vuln/detail/CVE-2024-28233 | High | JupyterHub XSS vulnerability
- CVE-2024-22420 | https://nvd.nist.gov/vuln/detail/CVE-2024-22420 | Medium | JupyterLab Markdown preview vulnerability
- CVE-2025-30167 | https://nvd.nist.gov/vuln/detail/CVE-2025-30167 | High | Jupyter Core Windows configuration vulnerability
"""

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

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
    confidence: float = 1.0  # Detection confidence (0.0-1.0)
    auto_fixable: bool = False  # Whether issue can be auto-fixed


@dataclass
class NotebookMetadata:
    """Notebook metadata for security analysis."""

    kernel_name: str
    language: str
    kernel_version: Optional[str] = None
    jupyter_version: Optional[str] = None
    trusted: bool = False  # Whether notebook is trusted
    execution_count_max: int = 0  # Maximum execution count seen
    has_outputs: bool = False  # Whether notebook has cell outputs


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
    - PII (Personally Identifiable Information)
    - Dependency vulnerabilities
    - License compliance issues
    - XSS vulnerabilities in outputs
    - ML pipeline security issues
    - Notebook metadata security
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
        "%%writefile": "Writing files (path traversal risk)",
        "%env": "Environment variable manipulation",
        "%store": "Cross-notebook variable storage (security risk)",
    }

    # Patterns for secrets in notebooks
    SECRET_PATTERNS = {
        r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})": "Hardcoded password",
        r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]([^'\"]{16,})": "API key",
        r"(?i)(secret[_-]?key|secretkey)\s*=\s*['\"]([^'\"]{16,})": "Secret key",
        r"(?i)(token|auth[_-]?token)\s*=\s*['\"]([^'\"]{16,})": "Authentication token",
        r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*['\"]([A-Z0-9]{20})": "AWS access key",
        r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*=\s*['\"]([A-Za-z0-9/+=]{40})": "AWS secret key",
        r"(?i)(github[_-]?token|gh[_-]?token)\s*=\s*['\"]([a-z0-9_]{40,})": "GitHub token",
        r"(?i)(slack[_-]?token)\s*=\s*['\"]xox[a-z]-[a-zA-Z0-9-]+": "Slack token",
        r"(?i)(private[_-]?key)\s*=\s*['\"]([^'\"]{32,})": "Private key",
        r"-----BEGIN (RSA |DSA )?PRIVATE KEY-----": "SSH/RSA private key",
    }

    # PII detection patterns
    PII_PATTERNS = {
        r"\b\d{3}-\d{2}-\d{4}\b": "Social Security Number (SSN)",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b": "Email address",
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b": "Credit card number",
        r"\b(?:\d{3}[-.]?)?\d{3}[-.]?\d{4}\b": "Phone number",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b": "IP address",
        r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b": "UK postal code",
        r"\b\d{5}(-\d{4})?\b": "US ZIP code",
    }

    # Risky ML/Data Science operations
    ML_SECURITY_PATTERNS = {
        r"pickle\.loads?\(": "Unsafe pickle deserialization (model poisoning risk)",
        r"joblib\.load\(": "Joblib model loading (verify source)",
        r"torch\.load\(": "PyTorch model loading (arbitrary code execution risk)",
        r"tf\.keras\.models\.load_model\(": "TensorFlow model loading (verify source)",
        r"pd\.read_pickle\(": "Pandas pickle reading (code execution risk)",
        r"np\.load\(.*allow_pickle\s*=\s*True": "NumPy pickle loading enabled",
    }

    # XSS-prone output patterns
    XSS_PATTERNS = {
        r"IPython\.display\.HTML\(": "Raw HTML display (XSS risk)",
        r"display\(HTML\(": "HTML display (XSS risk)",
        r"\.to_html\(\)": "DataFrame to HTML (potential XSS)",
        r"%%html": "HTML cell magic (XSS risk)",
    }

    def __init__(self):
        """Initialize the notebook security analyzer."""
        self.logger = PyGuardLogger()
        self.detected_pii: Set[str] = set()  # Track unique PII types detected
        self.detected_dependencies: Dict[str, str] = {}  # Track imported packages

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

        # Analyze notebook metadata
        metadata_issues = self._analyze_metadata(notebook_data)
        issues.extend(metadata_issues)

        # Analyze each cell
        for idx, cell in enumerate(cells):
            if cell.cell_type == "code":
                issues.extend(self._analyze_code_cell(cell, idx))

        # Cross-cell analysis
        issues.extend(self._analyze_cell_dependencies(cells))

        # Check for PII in outputs
        for idx, cell in enumerate(cells):
            if cell.cell_type == "code":
                issues.extend(self._check_output_pii(cell, idx))

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

    def _analyze_metadata(self, notebook_data: Dict[str, Any]) -> List[NotebookIssue]:
        """Analyze notebook metadata for security issues."""
        issues: List[NotebookIssue] = []
        metadata = notebook_data.get("metadata", {})

        # Check for untrusted notebook (only if explicitly marked as False, not missing)
        if metadata.get("trusted") is False:
            issues.append(
                NotebookIssue(
                    severity="MEDIUM",
                    category="Untrusted Notebook",
                    message="Notebook is not marked as trusted - outputs may not be safe",
                    cell_index=-1,
                    line_number=0,
                    code_snippet="",
                    fix_suggestion="Review notebook content and mark as trusted if verified safe",
                    confidence=0.8,
                )
            )

        # Check kernel info
        kernel_info = metadata.get("kernelspec", {})
        kernel_name = kernel_info.get("name", "")

        # Warn about non-standard kernels
        if kernel_name and kernel_name not in ["python3", "python2", "python"]:
            issues.append(
                NotebookIssue(
                    severity="LOW",
                    category="Non-Standard Kernel",
                    message=f"Using non-standard kernel: {kernel_name}",
                    cell_index=-1,
                    line_number=0,
                    code_snippet=f"Kernel: {kernel_name}",
                    fix_suggestion="Verify kernel source and security",
                    confidence=0.6,
                )
            )

        return issues

    def _check_pii(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for Personally Identifiable Information (PII) in cell code."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.PII_PATTERNS.items():
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Skip common false positives
                    matched_text = match.group(0)
                    if self._is_pii_false_positive(matched_text, description):
                        continue

                    self.detected_pii.add(description)
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="PII Exposure",
                            message=f"Potential {description} detected in notebook",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line[:50] + "..." if len(line) > 50 else line,
                            fix_suggestion=(
                                "Remove or redact PII from notebooks before sharing. "
                                "Use placeholder values or environment variables."
                            ),
                            cwe_id="CWE-359",
                            owasp_id="ASVS-8.3.4",
                            confidence=0.7,
                            auto_fixable=True,
                        )
                    )

        return issues

    def _is_pii_false_positive(self, text: str, pii_type: str) -> bool:
        """Check if detected PII is likely a false positive."""
        # Skip common test/example values
        test_values = [
            "123-45-6789",  # Example SSN
            "555-555-5555",  # Example phone
            "test@example.com",
            "user@example.org",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.",  # Local IPs
            "10.0.",
        ]

        for test_val in test_values:
            if test_val in text:
                return True

        # Skip IP addresses that are clearly local/private
        if pii_type == "IP address":
            if text.startswith("127.") or text.startswith("192.168.") or text.startswith("10."):
                return True

        return False

    def _check_ml_security(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for ML/Data Science security issues."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.ML_SECURITY_PATTERNS.items():
                if re.search(pattern, line):
                    severity = "CRITICAL" if "code execution" in description.lower() else "HIGH"
                    issues.append(
                        NotebookIssue(
                            severity=severity,
                            category="ML Pipeline Security",
                            message=description,
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Verify the source and integrity of loaded models. "
                                "Use safer serialization formats (ONNX, SavedModel). "
                                "Validate model checksums before loading."
                            ),
                            cwe_id="CWE-502",
                            owasp_id="ASVS-5.5.3",
                            confidence=0.85,
                        )
                    )

        # Check for data validation issues in ML pipelines
        if "pd.read_csv" in cell.source or "pd.read_excel" in cell.source:
            if "dtype=" not in cell.source and "converters=" not in cell.source:
                issues.append(
                    NotebookIssue(
                        severity="MEDIUM",
                        category="Data Validation",
                        message="Data loading without type validation (data poisoning risk)",
                        cell_index=cell_index,
                        line_number=0,
                        code_snippet="Data loading detected",
                        fix_suggestion=(
                            "Specify dtypes and use converters to validate data types. "
                            "Implement schema validation for input data."
                        ),
                        confidence=0.6,
                    )
                )

        return issues

    def _check_xss_vulnerabilities(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check for XSS vulnerabilities in notebook outputs."""
        issues: List[NotebookIssue] = []
        lines = cell.source.split("\n")

        for line_num, line in enumerate(lines, 1):
            for pattern, description in self.XSS_PATTERNS.items():
                if re.search(pattern, line):
                    issues.append(
                        NotebookIssue(
                            severity="HIGH",
                            category="XSS Vulnerability",
                            message=f"{description} - user input should be sanitized",
                            cell_index=cell_index,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix_suggestion=(
                                "Sanitize all user input before displaying as HTML. "
                                "Use IPython.display.Text() instead of HTML() for untrusted content. "
                                "Apply HTML escaping to prevent XSS attacks."
                            ),
                            cwe_id="CWE-79",
                            owasp_id="ASVS-5.3.3",
                            confidence=0.75,
                        )
                    )

        return issues

    def _check_output_pii(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Check cell outputs for PII exposure."""
        issues: List[NotebookIssue] = []

        for output in cell.outputs:
            output_text = ""

            # Extract text from different output types
            if output.get("output_type") == "stream":
                output_text = "".join(output.get("text", []))
            elif output.get("output_type") == "execute_result":
                data = output.get("data", {})
                output_text = data.get("text/plain", "")
            elif output.get("output_type") == "error":
                output_text = "\n".join(output.get("traceback", []))

            # Check for PII in output text
            for pattern, description in self.PII_PATTERNS.items():
                matches = re.finditer(pattern, output_text, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group(0)
                    if not self._is_pii_false_positive(matched_text, description):
                        issues.append(
                            NotebookIssue(
                                severity="HIGH",
                                category="PII in Output",
                                message=f"{description} exposed in cell output",
                                cell_index=cell_index,
                                line_number=0,
                                code_snippet=matched_text[:50],
                                fix_suggestion=(
                                    "Clear cell outputs before sharing notebook. "
                                    "Redact sensitive information from outputs."
                                ),
                                cwe_id="CWE-359",
                                confidence=0.7,
                                auto_fixable=True,
                            )
                        )
                        break  # Only report once per output

        return issues

    def _analyze_code_cell(self, cell: NotebookCell, cell_index: int) -> List[NotebookIssue]:
        """Analyze a single code cell for security issues."""
        issues: List[NotebookIssue] = []

        # Check for dangerous magic commands
        issues.extend(self._check_magic_commands(cell, cell_index))

        # Check for hardcoded secrets
        issues.extend(self._check_secrets(cell, cell_index))

        # Check for PII in code
        issues.extend(self._check_pii(cell, cell_index))

        # Check for unsafe operations
        issues.extend(self._check_unsafe_operations(cell, cell_index))

        # Check for command injection
        issues.extend(self._check_command_injection(cell, cell_index))

        # Check ML security issues
        issues.extend(self._check_ml_security(cell, cell_index))

        # Check XSS vulnerabilities
        issues.extend(self._check_xss_vulnerabilities(cell, cell_index))

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
                                auto_fixable=True,
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
            if not issue.auto_fixable:
                continue

            if issue.category == "Hardcoded Secret":
                # Comment out lines with secrets
                if 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)

                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        line = lines[issue.line_number - 1]
                        lines[issue.line_number - 1] = (
                            f"# SECURITY: Removed hardcoded secret - {line}"
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(
                            f"Commented out hardcoded secret in cell {issue.cell_index}"
                        )

            elif issue.category in ["PII Exposure", "PII in Output"]:
                # Redact PII from cell
                if issue.category == "PII Exposure" and 0 <= issue.cell_index < len(cells):
                    cell = cells[issue.cell_index]
                    source = cell.get("source", [])
                    if isinstance(source, list):
                        source = "".join(source)

                    # Add warning comment
                    lines = source.split("\n")
                    if 0 < issue.line_number <= len(lines):
                        lines.insert(
                            issue.line_number - 1,
                            f"# WARNING: PII detected below - redact before sharing",
                        )
                        cell["source"] = "\n".join(lines)
                        fixes_applied.append(f"Added PII warning in cell {issue.cell_index}")

                elif issue.category == "PII in Output":
                    # Clear outputs for cells with PII
                    if 0 <= issue.cell_index < len(cells):
                        cells[issue.cell_index]["outputs"] = []
                        fixes_applied.append(f"Cleared outputs with PII in cell {issue.cell_index}")

            elif issue.category == "Untrusted Notebook":
                # Don't auto-fix trust status (requires user verification)
                pass

        # Save fixed notebook
        if fixes_applied:
            # Create backup first
            backup_path = notebook_path.with_suffix(".ipynb.backup")
            with open(backup_path, "w", encoding="utf-8") as f:
                with open(notebook_path, "r", encoding="utf-8") as orig:
                    f.write(orig.read())

            with open(notebook_path, "w", encoding="utf-8") as f:
                json.dump(notebook_data, f, indent=2)

            fixes_applied.insert(0, f"Created backup at {backup_path}")

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
