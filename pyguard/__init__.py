"""
PyGuard - Python QA and Auto-Fix Tool

A comprehensive Python code quality, security, and formatting tool with automated fixes.
Now with AST-based analysis, parallel processing, and advanced reporting.
"""

__version__ = "0.6.0"
__author__ = "Chad Boyd"  # pyguard: disable=CWE-798
__license__ = "MIT"

# High-level API
from pyguard.api import (
    AnalysisResult,
    PyGuardAPI,
    Severity,
    analyze_code,
    analyze_file,
)

# Low-level components
from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.bugbear import BUGBEAR_RULES, BugbearChecker, BugbearVisitor
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.ci_integration import (
    CIIntegrationGenerator,
    PreCommitHookGenerator,
    generate_ci_config,
    install_pre_commit_hook,
)
from pyguard.lib.code_simplification import CodeSimplificationFixer, SimplificationIssue
from pyguard.lib.core import BackupManager, DiffGenerator, PyGuardLogger
from pyguard.lib.custom_rules import (
    CustomRule,
    CustomRuleEngine,
    create_rule_engine_from_config,
)
from pyguard.lib.debugging_patterns import (
    DEBUGGING_RULES,
    DebuggingPatternChecker,
    DebuggingPatternVisitor,
)
from pyguard.lib.dependency_analyzer import (
    DependencyGraphAnalyzer,
    analyze_project_dependencies,
)
from pyguard.lib.exception_handling import (
    EXCEPTION_HANDLING_RULES,
    ExceptionHandlingChecker,
    ExceptionHandlingVisitor,
)
from pyguard.lib.formatting import FormattingFixer
from pyguard.lib.import_manager import ImportAnalyzer, ImportManager
from pyguard.lib.modern_python import ModernizationIssue, ModernPythonFixer
from pyguard.lib.naming_conventions import NamingConventionFixer, NamingIssue
from pyguard.lib.parallel import BatchProcessor, ParallelProcessor
from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules
from pyguard.lib.performance_checks import PerformanceFixer, PerformanceIssue
from pyguard.lib.performance_profiler import (
    PerformanceOptimizationSuggester,
    PerformanceProfiler,
    analyze_performance,
)
from pyguard.lib.reporting import (
    AnalysisMetrics,
    ConsoleReporter,
    HTMLReporter,
    JSONReporter,
)
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
from pyguard.lib.string_operations import (
    StringIssue,
    StringOperationsFixer,
    StringOperationsVisitor,
)
from pyguard.lib.type_checker import TypeChecker, TypeInferenceEngine
from pyguard.lib.ui import EnhancedConsole, ModernHTMLReporter
from pyguard.lib.unused_code import UnusedCodeFixer, UnusedCodeIssue
from pyguard.lib.xss_detection import (
    XSS_RULES,
    XSSDetector,
    check_xss_vulnerabilities,
    detect_xss_patterns,
)

__all__ = [
    # High-level API
    "AnalysisResult",
    "PyGuardAPI",
    "Severity",
    "analyze_code",
    "analyze_file",
    # Rule Sets
    "BUGBEAR_RULES",
    "DEBUGGING_RULES",
    "EXCEPTION_HANDLING_RULES",
    "XSS_RULES",
    # Core Components
    "ASTAnalyzer",
    "AnalysisCache",
    "AnalysisMetrics",
    "BackupManager",
    "BatchProcessor",
    "BestPracticesFixer",
    # Bugbear - Common Mistakes
    "BugbearChecker",
    "BugbearVisitor",
    # CI/CD Integration
    "CIIntegrationGenerator",
    "CodeQualityIssue",
    "CodeSimplificationFixer",
    "ConfigCache",
    "ConsoleReporter",
    # Custom Rules Engine
    "CustomRule",
    "CustomRuleEngine",
    # Debugging Patterns
    "DebuggingPatternChecker",
    "DebuggingPatternVisitor",
    # Dependency Analyzer
    "DependencyGraphAnalyzer",
    "DiffGenerator",
    "EnhancedConsole",
    # Exception Handling
    "ExceptionHandlingChecker",
    "ExceptionHandlingVisitor",
    "FixApplicability",
    "FormattingFixer",
    "HTMLReporter",
    "ImportAnalyzer",
    # Import Management
    "ImportManager",
    "JSONReporter",
    "ModernHTMLReporter",
    "ModernPythonFixer",
    "ModernizationIssue",
    "NamingConventionFixer",
    "NamingIssue",
    # PEP 8 Comprehensive
    "PEP8Checker",
    "PEP8Rules",
    "ParallelProcessor",
    "PerformanceFixer",
    "PerformanceIssue",
    "PerformanceOptimizationSuggester",
    # Performance Profiler
    "PerformanceProfiler",
    "PreCommitHookGenerator",
    "PyGuardLogger",
    # Rule Engine
    "Rule",
    "RuleCategory",
    "RuleExecutor",
    "RuleRegistry",
    "RuleSeverity",
    "RuleViolation",
    "SARIFReporter",
    "SecurityFixer",
    "SecurityIssue",
    "SimplificationIssue",
    # String Operations
    "StringIssue",
    "StringOperationsFixer",
    "StringOperationsVisitor",
    # Type Checking
    "TypeChecker",
    "TypeInferenceEngine",
    "UnusedCodeFixer",
    "UnusedCodeIssue",
    # XSS Detection
    "XSSDetector",
    "analyze_performance",
    "analyze_project_dependencies",
    "check_xss_vulnerabilities",
    "create_rule_engine_from_config",
    "detect_xss_patterns",
    "generate_ci_config",
    "install_pre_commit_hook",
]
