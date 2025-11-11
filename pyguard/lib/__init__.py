"""PyGuard library modules - v0.8.0 with 55+ security checks and 20+ auto-fixes!"""

from pyguard.lib.advanced_injection import AdvancedInjectionVisitor, analyze_advanced_injection

__all__ = [
    "AdvancedInjectionVisitor",
    "analyze_advanced_injection",
]
from pyguard.lib.advanced_security import (
    AdvancedSecurityAnalyzer,
    IntegerSecurityAnalyzer,
    RaceConditionDetector,
    ReDoSDetector,
    TaintAnalyzer,
)

# NEW in v0.3.0: AI-powered explanations
from pyguard.lib.ai_explainer import (
    AIExplainer,
    FixRationale,
    SecurityExplanation,
    explain,
)
from pyguard.lib.ai_ml_security import (
    AIML_SECURITY_RULES,
    AIMLSecurityVisitor,
    analyze_ai_ml_security,
)
from pyguard.lib.api_security import API_SECURITY_RULES, APISecurityVisitor, analyze_api_security
from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.async_patterns import AsyncChecker, AsyncIssue
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.blockchain_security import (
    BLOCKCHAIN_RULES,
    BlockchainSecurityVisitor,
    analyze_blockchain_security,
)
from pyguard.lib.bugbear import BUGBEAR_RULES, BugbearChecker, BugbearVisitor
from pyguard.lib.business_logic import (
    BUSINESS_LOGIC_RULES,
    BusinessLogicVisitor,
    analyze_business_logic,
)
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.cloud_security import (
    CLOUD_SECURITY_RULES,
    CloudSecurityVisitor,
    check_cloud_security,
)
from pyguard.lib.comprehensions import ComprehensionChecker, ComprehensionVisitor
from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.datetime_patterns import DatetimeChecker, DatetimeIssue
from pyguard.lib.debugging_patterns import (
    DEBUGGING_RULES,
    DebuggingPatternChecker,
    DebuggingPatternVisitor,
)
from pyguard.lib.dependency_confusion import (
    DEP_CONF001_TYPOSQUATTING,
    DEP_CONF002_MALICIOUS_PATTERN,
    DEP_CONF003_NAMESPACE_HIJACK,
    DEP_CONF004_SUSPICIOUS_NAMING,
    DEP_CONF005_INSECURE_HTTP,
    DEP_CONF006_MISSING_VERSION_PIN,
    DEP_CONF007_MISSING_HASH,
    DependencyConfusionVisitor,
    analyze_dependency_confusion,
    analyze_requirements_file,
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
from pyguard.lib.framework_celery import (
    CELERY_RULES,
    CelerySecurityVisitor,
    analyze_celery_security,
)
from pyguard.lib.framework_django import DJANGO_RULES, DjangoRulesChecker
from pyguard.lib.framework_numpy import NUMPY_RULES, NumPySecurityVisitor, analyze_numpy_security
from pyguard.lib.framework_pandas import PANDAS_RULES, PandasRulesChecker
from pyguard.lib.framework_pyramid import (
    PYRAMID_RULES,
    PyramidSecurityVisitor,
    analyze_pyramid_security,
)
from pyguard.lib.framework_pytest import PYTEST_RULES, PytestRulesChecker
from pyguard.lib.framework_sqlalchemy import (
    SQLALCHEMY_RULES,
    SQLAlchemySecurityVisitor,
    analyze_sqlalchemy_security,
)
from pyguard.lib.framework_tensorflow import (
    TENSORFLOW_RULES,
    TensorFlowSecurityVisitor,
    analyze_tensorflow_security,
)
from pyguard.lib.framework_tornado import (
    TORNADO_RULES,
    TornadoSecurityVisitor,
    analyze_tornado_security,
)
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
from pyguard.lib.mobile_iot_security import (
    MOBILE_IOT_RULES,
    MobileIoTSecurityVisitor,
    analyze_mobile_iot_security,
)

# NEW in v0.3.0: Notebook security analysis
from pyguard.lib.notebook_security import (
    NotebookCell,
    NotebookFixer,
    NotebookIssue,
    NotebookSecurityAnalyzer,
    scan_notebook,
)
from pyguard.lib.parallel import BatchProcessor, ParallelProcessor

# NEW in v0.9.0: Pathlib patterns, Async patterns, Logging patterns, Datetime patterns
from pyguard.lib.pathlib_patterns import PathlibChecker, PathlibIssue
from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules

# NEW in v0.7.0: Performance optimization system
from pyguard.lib.performance_optimizer import (
    DependencyAnalyzer,
    DependencyGraph,
    FileMetrics,
    OptimizedAnalyzer,
    SmartAnalysisCache,
)

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
from pyguard.lib.supply_chain_advanced import SUPPLY_CHAIN_RULES as SUPPLY_CHAIN_ADVANCED_RULES
from pyguard.lib.supply_chain_advanced import (
    SupplyChainAdvancedVisitor,
    analyze_supply_chain_advanced,
)

# NEW in v0.7.0: Enhanced taint analysis with cross-function tracking
from pyguard.lib.taint_analysis import (
    EnhancedTaintAnalyzer,
    TaintPath,
    TaintSink,
    TaintSource,
    analyze_taint_flows,
    get_taint_paths,
)

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
    "AIML_SECURITY_RULES",
    "API_SECURITY_RULES",
    "BLOCKCHAIN_RULES",
    "BUGBEAR_RULES",
    "BUSINESS_LOGIC_RULES",
    "CELERY_RULES",
    "CLOUD_SECURITY_RULES",
    "DEBUGGING_RULES",
    "DEP_CONF001_TYPOSQUATTING",
    "DEP_CONF002_MALICIOUS_PATTERN",
    "DEP_CONF003_NAMESPACE_HIJACK",
    "DEP_CONF004_SUSPICIOUS_NAMING",
    "DEP_CONF005_INSECURE_HTTP",
    "DEP_CONF006_MISSING_VERSION_PIN",
    "DEP_CONF007_MISSING_HASH",
    "DJANGO_RULES",
    "EXCEPTION_HANDLING_RULES",
    "IMPORT_RULES",
    "MOBILE_IOT_RULES",
    "NUMPY_RULES",
    "PANDAS_RULES",
    "PIE_RULES",
    "PYLINT_RULES",
    "PYRAMID_RULES",
    "PYTEST_RULES",
    "REFURB_RULES",
    "SBOM",
    "SQLALCHEMY_RULES",
    "SUPPLY_CHAIN_ADVANCED_RULES",
    "TENSORFLOW_RULES",
    "TORNADO_RULES",
    # AI Explainer (NEW v0.3.0)
    "AIExplainer",
    "AIMLSecurityVisitor",
    "APIRateLimitDetector",
    "APISecurityVisitor",
    # Analysis
    "ASTAnalyzer",
    # Advanced Security
    "AdvancedSecurityAnalyzer",
    # Caching
    "AnalysisCache",
    # Reporting
    "AnalysisMetrics",
    "AnomalyDetector",
    # Async Patterns (NEW v0.9.0)
    "AsyncChecker",
    "AsyncIssue",
    "BackupManager",
    "BatchProcessor",
    "BestPracticesFixer",
    "BlockchainSecurityVisitor",
    # Bugbear - Common Mistakes
    "BugbearChecker",
    "BugbearVisitor",
    "BusinessLogicDetector",
    "BusinessLogicVisitor",
    "CERTSecureCodingMapper",
    "CachePoisoningDetector",
    "CelerySecurityVisitor",
    "CloudSecurityVisitor",
    "CodeQualityIssue",
    # Comprehensions
    "ComprehensionChecker",
    "ComprehensionVisitor",
    "ConfigCache",
    "ConsoleReporter",
    "ContainerEscapeDetector",
    # Datetime Patterns (NEW v0.9.0)
    "DatetimeChecker",
    "DatetimeIssue",
    # Debugging Patterns
    "DebuggingPatternChecker",
    "DebuggingPatternVisitor",
    "Dependency",
    # Performance Optimization (NEW v0.7.0)
    "DependencyAnalyzer",
    "DependencyConfusionVisitor",
    "DependencyGraph",
    "DiffGenerator",
    # Framework Rules (NEW v0.11.0)
    "DjangoRulesChecker",
    "EnhancedSecurityFixer",  # NEW Phase 2B - Real code transformations
    # Enhanced Taint Analysis (NEW - v0.7.0)
    "EnhancedTaintAnalyzer",
    # Exception Handling
    "ExceptionHandlingChecker",
    "ExceptionHandlingVisitor",
    "FileMetrics",
    "FileOperations",
    "FixClassification",
    "FixRationale",
    "FixSafety",
    # Fix Safety Classification (NEW Phase 2B)
    "FixSafetyClassifier",
    "FormattingFixer",
    "GDPRTechnicalControls",
    # Git Hooks (NEW v0.4.0)
    "GitHooksManager",
    # Ultra-Advanced Security (NEW v0.8.0)
    "GraphQLInjectionDetector",
    "HIPAASecurityRule",
    "HTMLReporter",
    "IEEE12207Mapper",
    # Import Rules (NEW v0.11.0)
    "ImportRulesChecker",
    "IntegerSecurityAnalyzer",
    "JSONReporter",
    "JWTSecurityDetector",
    "KnowledgeBase",
    # Knowledge Integration
    "KnowledgeIntegration",
    # Logging Patterns (NEW v0.9.0)
    "LoggingChecker",
    "LoggingIssue",
    # MCP Integration
    "MCPIntegration",
    "MCPServer",
    # ML Detection
    "MLRiskScorer",
    "MitreATTACKMapper",
    "MobileIoTSecurityVisitor",
    "NotebookCell",
    "NotebookFixer",
    "NotebookIssue",
    # Notebook Security (NEW v0.3.0)
    "NotebookSecurityAnalyzer",
    "NumPySecurityVisitor",
    "OptimizedAnalyzer",
    # PEP 8 Comprehensive
    "PEP8Checker",
    "PEP8Rules",
    # PIE Patterns (NEW v0.10.0)
    "PIEPatternChecker",
    "PandasRulesChecker",
    # Parallel
    "ParallelProcessor",
    # Pathlib Patterns (NEW v0.9.0)
    "PathlibChecker",
    "PathlibIssue",
    "PrototypePollutionDetector",
    # Core
    "PyGuardLogger",
    # Pylint Rules (NEW v0.11.0)
    "PylintRulesChecker",
    "PyramidSecurityVisitor",
    "PytestRulesChecker",
    "RaceConditionDetector",
    "ReDoSDetector",
    # Refurb Patterns (NEW v0.10.0)
    "RefurbPatternChecker",
    # Return Patterns
    "ReturnPatternChecker",
    "ReturnPatternVisitor",
    "SANSTop25Mapper",
    "SQLAlchemySecurityVisitor",
    "SSTIDetector",
    "SecurityExplanation",
    # Fixers
    "SecurityFixer",
    "SecurityIntelligence",
    "SecurityIssue",
    "SmartAnalysisCache",
    # Standards Integration
    "StandardsMapper",
    # String Operations
    "StringIssue",
    "StringOperationsFixer",
    "StringOperationsVisitor",
    "SupplyChainAdvancedVisitor",
    # Supply Chain
    "SupplyChainAnalyzer",
    "TaintAnalyzer",
    "TaintPath",
    "TaintSink",
    "TaintSource",
    "TensorFlowSecurityVisitor",
    "TornadoSecurityVisitor",
    "UltraAdvancedSecurityFixer",  # NEW v0.8.0
    "WhitespaceFixer",
    # AI/ML Security (NEW - Security Dominance Plan Month 5-6)
    "analyze_ai_ml_security",
    # API Security (NEW - Security Dominance Plan Phase 1)
    "analyze_api_security",
    # Blockchain & Web3 Security (NEW - Security Dominance Plan Month 5-6)
    "analyze_blockchain_security",
    # Business Logic Security (NEW - Security Dominance Plan Week 15-16)
    "analyze_business_logic",
    # Celery Framework (NEW - Security Dominance Plan Week 11-12)
    "analyze_celery_security",
    # Dependency Confusion & Supply Chain Attacks (NEW - Security Dominance Plan Phase 1.2)
    "analyze_dependency_confusion",
    # Mobile & IoT Security (NEW - Security Dominance Plan Month 5-6)
    "analyze_mobile_iot_security",
    # NumPy Framework (NEW - Security Dominance Plan Week 13-14)
    "analyze_numpy_security",
    # Pyramid Framework (NEW - Security Dominance Plan Week 15-16)
    "analyze_pyramid_security",
    "analyze_requirements_file",
    # SQLAlchemy Framework (NEW - P0 Priority - Security Dominance Plan Month 5-6)
    "analyze_sqlalchemy_security",
    # Supply Chain Advanced (NEW - Security Dominance Plan Week 11-12)
    "analyze_supply_chain_advanced",
    # Enhanced Taint Analysis (NEW - v0.7.0)
    "analyze_taint_flows",
    # TensorFlow Framework (NEW - Security Dominance Plan Week 13-14)
    "analyze_tensorflow_security",
    # Tornado Framework (NEW - Security Dominance Plan Week 11-12)
    "analyze_tornado_security",
    # Cloud Security (NEW - Security Dominance Plan Phase 1.3)
    "check_cloud_security",
    "explain",
    "get_taint_paths",
    "install_git_hooks",
    "scan_notebook",
    "uninstall_git_hooks",
    "validate_git_hooks",
]
