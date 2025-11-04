"""
PyGuard Programmatic API.

This module provides a clean, high-level API for using PyGuard programmatically
in Python applications, IDEs, and CI/CD systems.

Example usage:
    >>> from pyguard.api import PyGuardAPI
    >>> api = PyGuardAPI()
    >>> results = api.analyze_file("mycode.py")
    >>> print(f"Found {len(results.issues)} issues")
    >>> 
    >>> if results.has_critical_issues():
    ...     print("Critical security issues found!")
    ...     for issue in results.critical_issues:
    ...         print(f"  {issue.category}: {issue.message}")

API Stability:
    This API follows semantic versioning. Breaking changes will only occur
    in major version updates (e.g., 1.x -> 2.x).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.core import FileOperations, PyGuardLogger


class Severity(Enum):
    """Issue severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AnalysisResult:
    """
    Results from a PyGuard analysis.

    Attributes:
        issues: List of all issues found
        file_path: Path to the analyzed file
        execution_time_ms: Time taken for analysis in milliseconds
        lines_analyzed: Number of lines analyzed
    """

    issues: list[SecurityIssue | CodeQualityIssue] = field(default_factory=list)
    file_path: str | None = None
    execution_time_ms: float = 0.0
    lines_analyzed: int = 0

    @property
    def critical_issues(self) -> list[SecurityIssue | CodeQualityIssue]:
        """Get all CRITICAL severity issues."""
        return [i for i in self.issues if i.severity == "CRITICAL"]

    @property
    def high_issues(self) -> list[SecurityIssue | CodeQualityIssue]:
        """Get all HIGH severity issues."""
        return [i for i in self.issues if i.severity == "HIGH"]

    @property
    def medium_issues(self) -> list[SecurityIssue | CodeQualityIssue]:
        """Get all MEDIUM severity issues."""
        return [i for i in self.issues if i.severity == "MEDIUM"]

    @property
    def low_issues(self) -> list[SecurityIssue | CodeQualityIssue]:
        """Get all LOW severity issues."""
        return [i for i in self.issues if i.severity == "LOW"]

    @property
    def info_issues(self) -> list[SecurityIssue | CodeQualityIssue]:
        """Get all INFO severity issues."""
        return [i for i in self.issues if i.severity == "INFO"]

    def has_critical_issues(self) -> bool:
        """Check if any critical issues were found."""
        return len(self.critical_issues) > 0

    def has_issues(self, min_severity: Severity = Severity.INFO) -> bool:
        """
        Check if issues of at least the specified severity were found.

        Args:
            min_severity: Minimum severity level to check for

        Returns:
            True if issues at or above the severity level exist
        """
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_index = severity_order.index(min_severity.value)

        for issue in self.issues:
            if issue.severity in severity_order:
                issue_index = severity_order.index(issue.severity)
                if issue_index >= min_index:
                    return True
        return False

    def get_issues_by_category(self, category: str) -> list[SecurityIssue | CodeQualityIssue]:
        """
        Get all issues of a specific category.

        Args:
            category: Category name (e.g., "SQL Injection", "XSS")

        Returns:
            List of issues in the specified category
        """
        return [i for i in self.issues if i.category == category]

    def get_issues_by_cwe(self, cwe_id: str) -> list[SecurityIssue | CodeQualityIssue]:
        """
        Get all issues matching a specific CWE ID.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")

        Returns:
            List of issues with the specified CWE ID
        """
        return [i for i in self.issues if hasattr(i, 'cwe_id') and i.cwe_id == cwe_id]

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis result to dictionary format."""
        return {
            "file_path": self.file_path,
            "execution_time_ms": self.execution_time_ms,
            "lines_analyzed": self.lines_analyzed,
            "total_issues": len(self.issues),
            "critical_issues": len(self.critical_issues),
            "high_issues": len(self.high_issues),
            "medium_issues": len(self.medium_issues),
            "low_issues": len(self.low_issues),
            "info_issues": len(self.info_issues),
            "issues": [
                {
                    "severity": i.severity,
                    "category": i.category,
                    "message": i.message,
                    "line_number": i.line_number,
                    "column": i.column,
                    "code_snippet": i.code_snippet,
                    "fix_suggestion": i.fix_suggestion,
                    "owasp_id": getattr(i, 'owasp_id', ''),
                    "cwe_id": getattr(i, 'cwe_id', ''),
                }
                for i in self.issues
            ],
        }


class PyGuardAPI:
    """
    High-level API for PyGuard analysis.

    This class provides a simple interface for analyzing Python code
    programmatically. It handles all the complexity of file I/O,
    AST parsing, and analysis orchestration.

    Example:
        >>> api = PyGuardAPI()
        >>> results = api.analyze_file("mycode.py")
        >>> if results.has_critical_issues():
        ...     print("Security issues found!")
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize PyGuard API.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """
        Analyze a single Python file.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            AnalysisResult containing all findings

        Raises:
            FileNotFoundError: If the file doesn't exist
            SyntaxError: If the file has invalid Python syntax
        """
        import time

        start_time = time.perf_counter()

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            # Read file content
            content = self.file_ops.read_file(file_path)
            if content is None:
                return AnalysisResult(
                    issues=[],
                    file_path=str(file_path),
                    execution_time_ms=0.0,
                    lines_analyzed=0,
                )
            source_lines = content.splitlines()
            lines_analyzed = len(source_lines)

            # Analyze
            analyzer = ASTAnalyzer()
            security_issues, quality_issues = analyzer.analyze_code(content)

            # Combine all issues
            all_issues = security_issues + quality_issues

            # Collect results
            execution_time_ms = (time.perf_counter() - start_time) * 1000

            return AnalysisResult(
                issues=all_issues,
                file_path=str(file_path),
                execution_time_ms=execution_time_ms,
                lines_analyzed=lines_analyzed,
            )

        except SyntaxError as e:
            self.logger.error(f"Syntax error in {file_path}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")
            raise

    def analyze_code(self, code: str, filename: str = "<string>") -> AnalysisResult:
        """
        Analyze Python code from a string.

        Args:
            code: Python code to analyze
            filename: Optional filename for error messages

        Returns:
            AnalysisResult containing all findings

        Raises:
            SyntaxError: If the code has invalid Python syntax
        """
        import time

        start_time = time.perf_counter()

        try:
            source_lines = code.splitlines()
            lines_analyzed = len(source_lines)

            analyzer = ASTAnalyzer()
            security_issues, quality_issues = analyzer.analyze_code(code)

            # Combine all issues
            all_issues = security_issues + quality_issues

            execution_time_ms = (time.perf_counter() - start_time) * 1000

            return AnalysisResult(
                issues=all_issues,
                file_path=filename,
                execution_time_ms=execution_time_ms,
                lines_analyzed=lines_analyzed,
            )

        except SyntaxError as e:
            self.logger.error(f"Syntax error in {filename}: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error analyzing {filename}: {e}")
            raise

    def analyze_directory(
        self, directory: str | Path, pattern: str = "**/*.py", recursive: bool = True
    ) -> list[AnalysisResult]:
        """
        Analyze all Python files in a directory.

        Args:
            directory: Path to the directory to analyze
            pattern: Glob pattern for finding Python files (default: **/*.py)
            recursive: Whether to search recursively (default: True)

        Returns:
            List of AnalysisResult for each file analyzed
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        results = []
        glob_method = directory.rglob if recursive else directory.glob

        for file_path in glob_method(pattern):
            if file_path.is_file():
                try:
                    result = self.analyze_file(file_path)
                    results.append(result)
                except Exception as e:
                    self.logger.warning(f"Skipping {file_path}: {e}")
                    continue

        return results

    def generate_report(
        self, results: AnalysisResult | list[AnalysisResult], format: str = "json"
    ) -> str:
        """
        Generate a report from analysis results.

        Args:
            results: Single result or list of results
            format: Report format ('json', 'html', 'sarif')

        Returns:
            Report as a string

        Raises:
            ValueError: If format is not supported
        """
        if not isinstance(results, list):
            results = [results]

        if format not in ["json", "html", "sarif"]:
            raise ValueError(f"Unsupported format: {format}. Use 'json', 'html', or 'sarif'.")

        # Aggregate all issues
        all_issues = []
        for result in results:
            all_issues.extend(result.issues)

        if format == "json":
            import json

            issues_data = [
                {
                    "severity": issue.severity,
                    "category": issue.category,
                    "message": issue.message,
                    "line_number": issue.line_number,
                    "column": issue.column,
                    "code_snippet": issue.code_snippet,
                    "fix_suggestion": issue.fix_suggestion,
                    "cwe_id": getattr(issue, 'cwe_id', ''),
                    "owasp_id": getattr(issue, 'owasp_id', ''),
                }
                for issue in all_issues
            ]

            # Import version from main package
            from pyguard import __version__

            report_data = {
                "tool": "pyguard",
                "version": __version__,
                "timestamp": datetime.now(UTC).isoformat(),
                "total_issues": len(all_issues),
                "issues": issues_data,
            }

            return json.dumps(report_data, indent=2)

        elif format == "html":
            # Generate simple HTML report
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PyGuard Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .issue {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #fbc02d; }}
        .severity {{ font-weight: bold; padding: 5px 10px; border-radius: 3px; color: white; }}
        .severity.critical {{ background-color: #d32f2f; }}
        .severity.high {{ background-color: #f57c00; }}
        .severity.medium {{ background-color: #fbc02d; color: #333; }}
    </style>
</head>
<body>
    <h1>PyGuard Analysis Report</h1>
    <p>Total Issues: {len(all_issues)}</p>
    <hr>
"""
            for issue in all_issues:
                severity_class = issue.severity.lower()
                cwe_id = getattr(issue, 'cwe_id', '')
                html += f"""
    <div class="issue {severity_class}">
        <span class="severity {severity_class}">{issue.severity}</span>
        <h3>{issue.category}</h3>
        <p>{issue.message}</p>
        <p><strong>Line:</strong> {issue.line_number}</p>
        {f'<p><strong>Fix:</strong> {issue.fix_suggestion}</p>' if issue.fix_suggestion else ''}
        {f'<p><strong>CWE:</strong> {cwe_id}</p>' if cwe_id else ''}
    </div>
"""
            html += """
</body>
</html>
"""
            return html

        elif format == "sarif":
            # Import version from main package
            from pyguard import __version__
            from pyguard.lib.sarif_reporter import SARIFReporter

            # SARIF reporter expects a list of files, so we'll create a simple one
            sarif_reporter = SARIFReporter()
            # Generate SARIF format manually
            import json

            sarif_data = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "PyGuard",
                                "version": __version__,
                                "informationUri": "https://github.com/cboyd0319/PyGuard",
                            }
                        },
                        "results": [
                            {
                                "ruleId": getattr(issue, 'cwe_id', '') or issue.category,
                                "level": "error"
                                if issue.severity in ["CRITICAL", "HIGH"]
                                else "warning",
                                "message": {"text": issue.message},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "file:///."},
                                            "region": {"startLine": issue.line_number},
                                        }
                                    }
                                ],
                            }
                            for issue in all_issues
                        ],
                    }
                ],
            }

            return json.dumps(sarif_data, indent=2)

        return ""


# Convenience functions for quick analysis
def analyze_file(file_path: str | Path) -> AnalysisResult:
    """
    Quick analysis of a single file.

    Args:
        file_path: Path to Python file

    Returns:
        AnalysisResult with findings
    """
    api = PyGuardAPI()
    return api.analyze_file(file_path)


def analyze_code(code: str) -> AnalysisResult:
    """
    Quick analysis of Python code string.

    Args:
        code: Python code to analyze

    Returns:
        AnalysisResult with findings
    """
    api = PyGuardAPI()
    return api.analyze_code(code)
