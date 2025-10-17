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
    NotebookSecurityAnalyzer,
    NotebookFixer,
    NotebookIssue,
    NotebookCell,
    scan_notebook,
    generate_notebook_sarif,
)

__all__ = [
    'NotebookSecurityAnalyzer',
    'NotebookFixer',
    'NotebookIssue',
    'NotebookCell',
    'scan_notebook',
    'generate_notebook_sarif',
]
