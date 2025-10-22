"""PyGuard library modules - v0.8.0 with 55+ security checks and 20+ auto-fixes!"""

from pyguard.lib.advanced_injection import analyze_advanced_injection, AdvancedInjectionVisitor

__all__ = [
    "analyze_advanced_injection",
    "AdvancedInjectionVisitor",
]
from pyguard.lib.advanced_security import (
    AdvancedSecurityAnalyzer,
    IntegerSecurityAnalyzer,
    RaceConditionDetector,
    ReDoSDetector,
    TaintAnalyzer,
)
from pyguard.lib.api_security import analyze_api_security, APISecurityVisitor, API_SECURITY_RULES
from pyguard.lib.cloud_security import check_cloud_security, CloudSecurityVisitor, CLOUD_SECURITY_RULES
from pyguard.lib.dependency_confusion import (
    analyze_dependency_confusion,
    analyze_requirements_file,
    DependencyConfusionVisitor,
    DEP_CONF001_TYPOSQUATTING,
    DEP_CONF002_MALICIOUS_PATTERN,
    DEP_CONF003_NAMESPACE_HIJACK,
    DEP_CONF004_SUSPICIOUS_NAMING,
    DEP_CONF005_INSECURE_HTTP,
    DEP_CONF006_MISSING_VERSION_PIN,
    DEP_CONF007_MISSING_HASH,
)
from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.async_patterns import AsyncChecker, AsyncIssue
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.bugbear import BUGBEAR_RULES, BugbearChecker, BugbearVisitor
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.comprehensions import ComprehensionChecker, ComprehensionVisitor
from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.datetime_patterns import DatetimeChecker, DatetimeIssue
from pyguard.lib.debugging_patterns import (
    DEBUGGING_RULES,
    DebuggingPatternChecker,
    DebuggingPatternVisitor,
)
from pyguard.lib.enhanced_security_fixes import EnhancedSecurityFixer
from pyguard.lib.exception_handling import (
    EXCEPTION_HANDLING_RULES,
    ExceptionHandlingChecker,
    ExceptionHandlingVisitor,
)
from pyguard.lib.fix_safety import (
    FixClassification,
    FixSafety,
    FixSafetyClassifier,
)
from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer
from pyguard.lib.framework_django import DJANGO_RULES, DjangoRulesChecker
from pyguard.lib.framework_pandas import PANDAS_RULES, PandasRulesChecker
from pyguard.lib.framework_pytest import PYTEST_RULES, PytestRulesChecker
from pyguard.lib.framework_celery import analyze_celery_security, CelerySecurityVisitor, CELERY_RULES
from pyguard.lib.framework_tornado import analyze_tornado_security, TornadoSecurityVisitor, TORNADO_RULES
from pyguard.lib.framework_numpy import analyze_numpy_security, NumPySecurityVisitor, NUMPY_RULES
from pyguard.lib.framework_tensorflow import analyze_tensorflow_security, TensorFlowSecurityVisitor, TENSORFLOW_RULES
from pyguard.lib.git_hooks import (
    GitHooksManager,
    install_git_hooks,
    uninstall_git_hooks,
    validate_git_hooks,
)

# NEW in v0.11.0: Import rules, Pylint rules, Framework-specific rules
from pyguard.lib.import_rules import IMPORT_RULES, ImportRulesChecker
from pyguard.lib.knowledge_integration import (
    KnowledgeBase,
    KnowledgeIntegration,
    SecurityIntelligence,
)
from pyguard.lib.logging_patterns import LoggingChecker, LoggingIssue
from pyguard.lib.mcp_integration import MCPIntegration, MCPServer
from pyguard.lib.ml_detection import AnomalyDetector, MLRiskScorer

# NEW in v0.3.0: Notebook security analysis
from pyguard.lib.notebook_security import (
    NotebookCell,
    NotebookFixer,
    NotebookIssue,
    NotebookSecurityAnalyzer,
    scan_notebook,
)

# NEW in v0.3.0: AI-powered explanations
from pyguard.lib.ai_explainer import (
    AIExplainer,
    FixRationale,
    SecurityExplanation,
    explain,
)
from pyguard.lib.parallel import BatchProcessor, ParallelProcessor

# NEW in v0.9.0: Pathlib patterns, Async patterns, Logging patterns, Datetime patterns
from pyguard.lib.pathlib_patterns import PathlibChecker, PathlibIssue
from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules

# NEW in v0.10.0: PIE patterns (code smells)
from pyguard.lib.pie_patterns import PIE_RULES, PIEPatternChecker
from pyguard.lib.pylint_rules import PYLINT_RULES, PylintRulesChecker

# NEW in v0.10.0: Refurb patterns (refactoring opportunities)
from pyguard.lib.refurb_patterns import REFURB_RULES, RefurbPatternChecker
from pyguard.lib.reporting import (
    AnalysisMetrics,
    ConsoleReporter,
    HTMLReporter,
    JSONReporter,
)
from pyguard.lib.return_patterns import ReturnPatternChecker, ReturnPatternVisitor
from pyguard.lib.security import SecurityFixer
from pyguard.lib.standards_integration import (
    CERTSecureCodingMapper,
    GDPRTechnicalControls,
    HIPAASecurityRule,
    IEEE12207Mapper,
    MitreATTACKMapper,
    SANSTop25Mapper,
    StandardsMapper,
)
from pyguard.lib.string_operations import (
    StringIssue,
    StringOperationsFixer,
    StringOperationsVisitor,
)
from pyguard.lib.supply_chain import SBOM, Dependency, SupplyChainAnalyzer
from pyguard.lib.supply_chain_advanced import analyze_supply_chain_advanced, SupplyChainAdvancedVisitor, SUPPLY_CHAIN_RULES as SUPPLY_CHAIN_ADVANCED_RULES

# NEW in v0.8.0: Ultra-advanced auto-fixes
from pyguard.lib.ultra_advanced_fixes import UltraAdvancedSecurityFixer

# NEW in v0.8.0: Ultra-advanced security detectors
from pyguard.lib.ultra_advanced_security import (
    APIRateLimitDetector,
    BusinessLogicDetector,
    CachePoisoningDetector,
    ContainerEscapeDetector,
    GraphQLInjectionDetector,
    JWTSecurityDetector,
    PrototypePollutionDetector,
    SSTIDetector,
)

__all__ = [
    # Core
    "PyGuardLogger",
    "FileOperations",
    "BackupManager",
    "DiffGenerator",
    # Analysis
    "ASTAnalyzer",
    "SecurityIssue",
    "CodeQualityIssue",
    # Fixers
    "SecurityFixer",
    "BestPracticesFixer",
    "FormattingFixer",
    "WhitespaceFixer",
    "UltraAdvancedSecurityFixer",  # NEW v0.8.0
    "EnhancedSecurityFixer",  # NEW Phase 2B - Real code transformations
    # Advanced Security
    "AdvancedSecurityAnalyzer",
    "TaintAnalyzer",
    "ReDoSDetector",
    "RaceConditionDetector",
    "IntegerSecurityAnalyzer",
    # Ultra-Advanced Security (NEW v0.8.0)
    "GraphQLInjectionDetector",
    "SSTIDetector",
    "JWTSecurityDetector",
    "APIRateLimitDetector",
    "ContainerEscapeDetector",
    "PrototypePollutionDetector",
    "CachePoisoningDetector",
    "BusinessLogicDetector",
    # API Security (NEW - Security Dominance Plan Phase 1)
    "analyze_api_security",
    "APISecurityVisitor",
    "API_SECURITY_RULES",
    # Cloud Security (NEW - Security Dominance Plan Phase 1.3)
    "check_cloud_security",
    "CloudSecurityVisitor",
    "CLOUD_SECURITY_RULES",
    # Dependency Confusion & Supply Chain Attacks (NEW - Security Dominance Plan Phase 1.2)
    "analyze_dependency_confusion",
    "analyze_requirements_file",
    "DependencyConfusionVisitor",
    "DEP_CONF001_TYPOSQUATTING",
    "DEP_CONF002_MALICIOUS_PATTERN",
    "DEP_CONF003_NAMESPACE_HIJACK",
    "DEP_CONF004_SUSPICIOUS_NAMING",
    "DEP_CONF005_INSECURE_HTTP",
    "DEP_CONF006_MISSING_VERSION_PIN",
    "DEP_CONF007_MISSING_HASH",
    # Supply Chain
    "SupplyChainAnalyzer",
    "SBOM",
    "Dependency",
    # Knowledge Integration
    "KnowledgeIntegration",
    "KnowledgeBase",
    "SecurityIntelligence",
    # MCP Integration
    "MCPIntegration",
    "MCPServer",
    # ML Detection
    "MLRiskScorer",
    "AnomalyDetector",
    # Notebook Security (NEW v0.3.0)
    "NotebookSecurityAnalyzer",
    "NotebookFixer",
    "NotebookIssue",
    "NotebookCell",
    "scan_notebook",
    # AI Explainer (NEW v0.3.0)
    "AIExplainer",
    "SecurityExplanation",
    "FixRationale",
    "explain",
    # Standards Integration
    "StandardsMapper",
    "SANSTop25Mapper",
    "CERTSecureCodingMapper",
    "IEEE12207Mapper",
    "MitreATTACKMapper",
    "GDPRTechnicalControls",
    "HIPAASecurityRule",
    # Caching
    "AnalysisCache",
    "ConfigCache",
    # Parallel
    "ParallelProcessor",
    "BatchProcessor",
    # Reporting
    "AnalysisMetrics",
    "ConsoleReporter",
    "HTMLReporter",
    "JSONReporter",
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
    # Fix Safety Classification (NEW Phase 2B)
    "FixSafetyClassifier",
    "FixSafety",
    "FixClassification",
    # Return Patterns
    "ReturnPatternChecker",
    "ReturnPatternVisitor",
    # Comprehensions
    "ComprehensionChecker",
    "ComprehensionVisitor",
    # Debugging Patterns
    "DebuggingPatternChecker",
    "DebuggingPatternVisitor",
    "DEBUGGING_RULES",
    # Pathlib Patterns (NEW v0.9.0)
    "PathlibChecker",
    "PathlibIssue",
    # Async Patterns (NEW v0.9.0)
    "AsyncChecker",
    "AsyncIssue",
    # Logging Patterns (NEW v0.9.0)
    "LoggingChecker",
    "LoggingIssue",
    # Datetime Patterns (NEW v0.9.0)
    "DatetimeChecker",
    "DatetimeIssue",
    # Refurb Patterns (NEW v0.10.0)
    "RefurbPatternChecker",
    "REFURB_RULES",
    # PIE Patterns (NEW v0.10.0)
    "PIEPatternChecker",
    "PIE_RULES",
    # Import Rules (NEW v0.11.0)
    "ImportRulesChecker",
    "IMPORT_RULES",
    # Pylint Rules (NEW v0.11.0)
    "PylintRulesChecker",
    "PYLINT_RULES",
    # Framework Rules (NEW v0.11.0)
    "DjangoRulesChecker",
    "DJANGO_RULES",
    "PytestRulesChecker",
    "PYTEST_RULES",
    "PandasRulesChecker",
    "PANDAS_RULES",
    # Celery Framework (NEW - Security Dominance Plan Week 11-12)
    "analyze_celery_security",
    "CelerySecurityVisitor",
    "CELERY_RULES",
    # Tornado Framework (NEW - Security Dominance Plan Week 11-12)
    "analyze_tornado_security",
    "TornadoSecurityVisitor",
    "TORNADO_RULES",
    # Supply Chain Advanced (NEW - Security Dominance Plan Week 11-12)
    "analyze_supply_chain_advanced",
    "SupplyChainAdvancedVisitor",
    "SUPPLY_CHAIN_ADVANCED_RULES",
    # Git Hooks (NEW v0.4.0)
    "GitHooksManager",
    "install_git_hooks",
    "uninstall_git_hooks",
    "validate_git_hooks",
]
