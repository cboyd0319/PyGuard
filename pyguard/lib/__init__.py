"""PyGuard library modules."""

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
    # Advanced Security
    "AdvancedSecurityAnalyzer",
    "TaintAnalyzer",
    "ReDoSDetector",
    "RaceConditionDetector",
    "IntegerSecurityAnalyzer",
    # Supply Chain
    "SupplyChainAnalyzer",
    "SBOM",
    "Dependency",
    # Knowledge Integration
    "KnowledgeIntegration",
    "KnowledgeBase",
    "SecurityIntelligence",
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
]
