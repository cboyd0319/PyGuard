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
    
    def __init__(self, findings: list):
        """Initialize with a list of findings."""
        self.findings = findings
    
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
    
    def analyze_notebook(self, notebook_path: Path):
        """
        Analyze a Jupyter notebook for security issues.
        
        Args:
            notebook_path: Path to .ipynb file
            
        Returns:
            NotebookAnalysisResult containing the list of issues found
        """
        issues = super().analyze_notebook(notebook_path)
        return NotebookAnalysisResult(issues)

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
