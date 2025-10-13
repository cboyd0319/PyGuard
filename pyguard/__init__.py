"""
PyGuard - Python QA and Auto-Fix Tool

A comprehensive Python code quality, security, and formatting tool with automated fixes.
Now with AST-based analysis, parallel processing, and advanced reporting.
"""

__version__ = "0.3.0"
__author__ = "Chad Boyd"
__license__ = "MIT"

from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.core import BackupManager, DiffGenerator, PyGuardLogger
from pyguard.lib.formatting import FormattingFixer
from pyguard.lib.parallel import BatchProcessor, ParallelProcessor
from pyguard.lib.reporting import AnalysisMetrics, ConsoleReporter, HTMLReporter, JSONReporter
from pyguard.lib.sarif_reporter import SARIFReporter
from pyguard.lib.security import SecurityFixer
from pyguard.lib.ui import EnhancedConsole, ModernHTMLReporter

__all__ = [
    "PyGuardLogger",
    "BackupManager",
    "DiffGenerator",
    "SecurityFixer",
    "BestPracticesFixer",
    "FormattingFixer",
    "ASTAnalyzer",
    "SecurityIssue",
    "CodeQualityIssue",
    "AnalysisCache",
    "ConfigCache",
    "ParallelProcessor",
    "BatchProcessor",
    "ConsoleReporter",
    "JSONReporter",
    "HTMLReporter",
    "SARIFReporter",
    "AnalysisMetrics",
    "EnhancedConsole",
    "ModernHTMLReporter",
]
