"""PyGuard library modules - v0.8.0 with 55+ security checks and 20+ auto-fixes!"""

from pyguard.lib.advanced_security import (
    AdvancedSecurityAnalyzer,
    IntegerSecurityAnalyzer,
    RaceConditionDetector,
    ReDoSDetector,
    TaintAnalyzer,
)
from pyguard.lib.ast_analyzer import ASTAnalyzer, CodeQualityIssue, SecurityIssue
from pyguard.lib.best_practices import BestPracticesFixer
from pyguard.lib.cache import AnalysisCache, ConfigCache
from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer
from pyguard.lib.knowledge_integration import KnowledgeBase, KnowledgeIntegration, SecurityIntelligence
from pyguard.lib.parallel import ParallelProcessor, BatchProcessor
from pyguard.lib.reporting import AnalysisMetrics, ConsoleReporter, HTMLReporter, JSONReporter
from pyguard.lib.security import SecurityFixer
from pyguard.lib.supply_chain import Dependency, SBOM, SupplyChainAnalyzer
from pyguard.lib.mcp_integration import MCPIntegration, MCPServer
from pyguard.lib.ml_detection import AnomalyDetector, MLRiskScorer
from pyguard.lib.standards_integration import (
    CERTSecureCodingMapper,
    GDPRTechnicalControls,
    HIPAASecurityRule,
    IEEE12207Mapper,
    MitreATTACKMapper,
    SANSTop25Mapper,
    StandardsMapper,
)
from pyguard.lib.string_operations import StringIssue, StringOperationsFixer, StringOperationsVisitor
from pyguard.lib.pep8_comprehensive import PEP8Checker, PEP8Rules
from pyguard.lib.bugbear import BugbearChecker, BugbearVisitor, BUGBEAR_RULES
from pyguard.lib.exception_handling import ExceptionHandlingChecker, ExceptionHandlingVisitor, EXCEPTION_HANDLING_RULES
from pyguard.lib.return_patterns import ReturnPatternChecker, ReturnPatternVisitor
from pyguard.lib.comprehensions import ComprehensionChecker, ComprehensionVisitor
from pyguard.lib.debugging_patterns import DebuggingPatternChecker, DebuggingPatternVisitor, DEBUGGING_RULES
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
# NEW in v0.8.0: Ultra-advanced auto-fixes
from pyguard.lib.ultra_advanced_fixes import UltraAdvancedSecurityFixer

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
]
