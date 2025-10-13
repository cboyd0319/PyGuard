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
from pyguard.lib.code_simplification import CodeSimplificationFixer, SimplificationIssue
from pyguard.lib.core import BackupManager, DiffGenerator, PyGuardLogger
from pyguard.lib.formatting import FormattingFixer
from pyguard.lib.import_manager import ImportAnalyzer, ImportManager
from pyguard.lib.modern_python import ModernPythonFixer, ModernizationIssue
from pyguard.lib.naming_conventions import NamingConventionFixer, NamingIssue
from pyguard.lib.parallel import BatchProcessor, ParallelProcessor
from pyguard.lib.performance_checks import PerformanceFixer, PerformanceIssue
from pyguard.lib.reporting import AnalysisMetrics, ConsoleReporter, HTMLReporter, JSONReporter
from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleExecutor,
    RuleRegistry,
    RuleSeverity,
    RuleViolation,
)
from pyguard.lib.sarif_reporter import SARIFReporter
from pyguard.lib.security import SecurityFixer
from pyguard.lib.string_operations import StringIssue, StringOperationsFixer, StringOperationsVisitor
from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules
from pyguard.lib.bugbear import BugbearChecker, BugbearVisitor, BUGBEAR_RULES
from pyguard.lib.exception_handling import ExceptionHandlingChecker, ExceptionHandlingVisitor, EXCEPTION_HANDLING_RULES
from pyguard.lib.type_checker import TypeChecker, TypeInferenceEngine
from pyguard.lib.ui import EnhancedConsole, ModernHTMLReporter
from pyguard.lib.unused_code import UnusedCodeFixer, UnusedCodeIssue

__all__ = [
    "PyGuardLogger",
    "BackupManager",
    "DiffGenerator",
    "SecurityFixer",
    "BestPracticesFixer",
    "FormattingFixer",
    "ModernPythonFixer",
    "CodeSimplificationFixer",
    "PerformanceFixer",
    "UnusedCodeFixer",
    "NamingConventionFixer",
    "ASTAnalyzer",
    "SecurityIssue",
    "CodeQualityIssue",
    "ModernizationIssue",
    "SimplificationIssue",
    "PerformanceIssue",
    "UnusedCodeIssue",
    "NamingIssue",
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
    # Rule Engine
    "Rule",
    "RuleCategory",
    "RuleSeverity",
    "RuleViolation",
    "RuleRegistry",
    "RuleExecutor",
    "FixApplicability",
    # Type Checking
    "TypeChecker",
    "TypeInferenceEngine",
    # Import Management
    "ImportManager",
    "ImportAnalyzer",
    # String Operations
    "StringIssue",
    "StringOperationsFixer",
    "StringOperationsVisitor",
    # PEP 8 Comprehensive
    "PEP8Checker",
    "PEP8Rules",
    # Bugbear - Common Mistakes
    "BugbearChecker",
    "BugbearVisitor",
    "BUGBEAR_RULES",
    # Exception Handling
    "ExceptionHandlingChecker",
    "ExceptionHandlingVisitor",
    "EXCEPTION_HANDLING_RULES",
]
