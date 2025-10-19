"""
Jupyter Notebook Security Analyzer for PyGuard.

World-class security analysis for .ipynb files with ML/AI-aware detection
and intelligent auto-fix capabilities.

This module integrates with PyGuard's main security analyzer to provide
comprehensive notebook security scanning. The actual implementation is in
pyguard.lib.notebook_security.

For detailed usage, see:
- pyguard.lib.notebook_security.NotebookSecurityAnalyzer
- pyguard.lib.notebook_security.NotebookFixer
- pyguard.lib.notebook_security.scan_notebook

Example:
    >>> from pyguard.lib.notebook_security import scan_notebook
    >>> issues = scan_notebook('notebook.ipynb')
    >>> critical = [i for i in issues if i.severity == "CRITICAL"]
    >>> print(f"Found {len(critical)} critical issues")
"""

# Re-export the main notebook security classes for convenience
from pyguard.lib.notebook_security import (
    NotebookSecurityAnalyzer as _BaseNotebookSecurityAnalyzer,
    NotebookFixer,
    NotebookIssue,
    NotebookCell,
    scan_notebook,
    generate_notebook_sarif,
)
from pathlib import Path
from typing import List

# Type aliases for backward compatibility
NotebookFinding = NotebookIssue

# Check if nbformat is available
try:
    import nbformat
    NBFORMAT_AVAILABLE = True
except ImportError:
    NBFORMAT_AVAILABLE = False

# Wrapper class for analysis results
class NotebookAnalysisResult:
    """Wrapper for notebook analysis results to provide a consistent interface."""
    
    def __init__(self, findings: list, notebook_path: Path = None):
        """Initialize with a list of findings and optionally notebook metadata."""
        self.findings = findings
        self.cell_count = 0
        self.code_cell_count = 0
        self.execution_count_valid = True
        
        # If notebook path provided, extract metadata
        if notebook_path and notebook_path.exists():
            try:
                import json
                with open(notebook_path, 'r', encoding='utf-8') as f:
                    notebook_data = json.load(f)
                    cells = notebook_data.get('cells', [])
                    self.cell_count = len(cells)
                    self.code_cell_count = sum(1 for c in cells if c.get('cell_type') == 'code')
                    
                    # Check execution order validity
                    exec_counts = [
                        c.get('execution_count') 
                        for c in cells 
                        if c.get('cell_type') == 'code' and c.get('execution_count') is not None
                    ]
                    if exec_counts:
                        # Valid if execution counts are monotonically increasing
                        self.execution_count_valid = all(
                            exec_counts[i] <= exec_counts[i+1] 
                            for i in range(len(exec_counts)-1)
                        )
            except (json.JSONDecodeError, IOError):
                pass
    
    def total_count(self) -> int:
        """Return total number of findings."""
        return len(self.findings)
    
    def critical_count(self) -> int:
        """Return number of critical findings."""
        return len([f for f in self.findings if f.severity == 'CRITICAL'])
    
    def high_count(self) -> int:
        """Return number of high severity findings."""
        return len([f for f in self.findings if f.severity == 'HIGH'])
    
    def medium_count(self) -> int:
        """Return number of medium severity findings."""
        return len([f for f in self.findings if f.severity == 'MEDIUM'])
    
    def low_count(self) -> int:
        """Return number of low severity findings."""
        return len([f for f in self.findings if f.severity == 'LOW'])

# Wrapper class for NotebookSecurityAnalyzer to return NotebookAnalysisResult
class NotebookSecurityAnalyzer(_BaseNotebookSecurityAnalyzer):
    """
    Extended NotebookSecurityAnalyzer that returns NotebookAnalysisResult objects.
    
    This wrapper provides backward compatibility with tests that expect
    NotebookAnalysisResult instead of plain lists.
    """
    
    @property
    def secret_patterns(self):
        """Expose SECRET_PATTERNS as secret_patterns for compatibility."""
        return self.SECRET_PATTERNS
    
    @property
    def dangerous_functions(self):
        """Return list of dangerous functions for compatibility."""
        # List common dangerous functions
        return ['eval', 'exec', 'compile', 'pickle.load', 'torch.load', 'yaml.load']
    
    def _get_function_name(self, node) -> str:
        """
        Extract function name from AST node for compatibility with tests.
        
        Args:
            node: AST Call node
            
        Returns:
            Function name as string (e.g., 'eval' or 'pickle.load')
        """
        import ast
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function like pickle.load
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return ""
    
    def generate_sarif_report(self, results: List['NotebookAnalysisResult']) -> dict:
        """
        Generate SARIF report from analysis results for compatibility.
        
        Args:
            results: List of NotebookAnalysisResult objects
            
        Returns:
            SARIF report dictionary
        """
        # Collect all findings from all results
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        # Use the parent class's SARIF generation if available
        # Otherwise create a minimal SARIF structure
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PyGuard Notebook Analyzer",
                        "version": "1.0.0"
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id if hasattr(finding, 'rule_id') else "NOTEBOOK-001",
                        "message": {"text": finding.message},
                        "level": finding.severity.lower() if hasattr(finding, 'severity') else "warning"
                    }
                    for finding in all_findings
                ]
            }]
        }
    
    def analyze_notebook(self, notebook_path: Path):
        """
        Analyze a Jupyter notebook for security issues.
        
        Args:
            notebook_path: Path to .ipynb file
            
        Returns:
            NotebookAnalysisResult containing the list of issues found
        """
        issues = super().analyze_notebook(notebook_path)
        return NotebookAnalysisResult(issues, notebook_path)

__all__ = [
    'NotebookSecurityAnalyzer',
    'NotebookFixer',
    'NotebookIssue',
    'NotebookFinding',
    'NotebookAnalysisResult',
    'NotebookCell',
    'scan_notebook',
    'generate_notebook_sarif',
    'NBFORMAT_AVAILABLE',
]
