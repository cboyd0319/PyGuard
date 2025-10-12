"""
PyGuard - Python QA and Auto-Fix Tool

A comprehensive Python code quality, security, and formatting tool with automated fixes.
Now with AST-based analysis, parallel processing, and advanced reporting.
"""

__version__ = "0.3.0"
__author__ = "Chad Boyd"
__license__ = "MIT"

from pyguard.lib.core import PyGuardLogger, BackupManager, DiffGenerator
from pyguard.lib.security import SecurityFixer
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.formatting import FormattingFixer
from pyguard.lib.ast_analyzer import ASTAnalyzer, SecurityIssue, CodeQualityIssue
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.parallel import ParallelProcessor, BatchProcessor
from pyguard.lib.reporting import ConsoleReporter, JSONReporter, HTMLReporter, AnalysisMetrics

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
    "AnalysisMetrics",
]
