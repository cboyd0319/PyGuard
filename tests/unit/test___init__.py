"""
Comprehensive unit tests for pyguard.__init__ module.

Tests cover:
- Package metadata (__version__, __author__, __license__)
- Import availability of all public APIs
- __all__ exports correctness
- Module imports don't raise errors

Following pytest best practices with AAA pattern and proper isolation.
"""

import pytest


class TestPackageMetadata:
    """Tests for package-level metadata."""

    def test_version_attribute_exists(self):
        """Test that __version__ attribute exists and is a string."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, "__version__")
        assert isinstance(pyguard.__version__, str)
        assert len(pyguard.__version__) > 0

    def test_version_format(self):
        """Test that __version__ follows semantic versioning."""
        # Arrange
        import pyguard

        # Act
        version = pyguard.__version__

        # Assert
        parts = version.split(".")
        assert len(parts) >= 2, f"Version should have at least major.minor: {version}"
        # Check that major and minor are numeric
        assert parts[0].isdigit(), f"Major version should be numeric: {parts[0]}"
        assert parts[1].isdigit(), f"Minor version should be numeric: {parts[1]}"

    def test_author_attribute_exists(self):
        """Test that __author__ attribute exists and is a string."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, "__author__")
        assert isinstance(pyguard.__author__, str)
        assert len(pyguard.__author__) > 0

    def test_license_attribute_exists(self):
        """Test that __license__ attribute exists and is a string."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, "__license__")
        assert isinstance(pyguard.__license__, str)
        assert pyguard.__license__ == "MIT"


class TestPublicAPIAvailability:
    """Tests for public API availability from package root."""

    @pytest.mark.parametrize(
        "class_name",
        [
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
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_core_classes_importable(self, class_name: str):
        """Test that core classes are importable from pyguard package."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, class_name), f"{class_name} should be importable from pyguard"
        cls = getattr(pyguard, class_name)
        assert cls is not None

    @pytest.mark.parametrize(
        "class_name",
        [
            "AnalysisCache",
            "ConfigCache",
            "ParallelProcessor",
            "BatchProcessor",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_utility_classes_importable(self, class_name: str):
        """Test that utility classes are importable from pyguard package."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, class_name), f"{class_name} should be importable from pyguard"

    @pytest.mark.parametrize(
        "class_name",
        [
            "ConsoleReporter",
            "JSONReporter",
            "HTMLReporter",
            "SARIFReporter",
            "AnalysisMetrics",
            "EnhancedConsole",
            "ModernHTMLReporter",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_reporter_classes_importable(self, class_name: str):
        """Test that reporter classes are importable from pyguard package."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, class_name), f"{class_name} should be importable from pyguard"

    @pytest.mark.parametrize(
        "class_name",
        [
            "Rule",
            "RuleCategory",
            "RuleSeverity",
            "RuleViolation",
            "RuleRegistry",
            "RuleExecutor",
            "FixApplicability",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_rule_engine_classes_importable(self, class_name: str):
        """Test that rule engine classes are importable from pyguard package."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, class_name), f"{class_name} should be importable from pyguard"

    @pytest.mark.parametrize(
        "class_name",
        [
            "TypeChecker",
            "TypeInferenceEngine",
            "ImportManager",
            "ImportAnalyzer",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_type_and_import_classes_importable(self, class_name: str):
        """Test that type checking and import management classes are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, class_name), f"{class_name} should be importable from pyguard"


class TestIssueClasses:
    """Tests for issue/violation classes."""

    @pytest.mark.parametrize(
        "issue_class",
        [
            "ModernizationIssue",
            "SimplificationIssue",
            "PerformanceIssue",
            "UnusedCodeIssue",
            "NamingIssue",
            "StringIssue",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_issue_classes_importable(self, issue_class: str):
        """Test that issue classes are importable from pyguard package."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, issue_class), f"{issue_class} should be importable from pyguard"


class TestSpecializedCheckers:
    """Tests for specialized checker classes."""

    @pytest.mark.parametrize(
        "checker_name",
        [
            "PEP8Checker",
            "PEP8Rules",
            "BugbearChecker",
            "BugbearVisitor",
            "BUGBEAR_RULES",
            "ExceptionHandlingChecker",
            "ExceptionHandlingVisitor",
            "EXCEPTION_HANDLING_RULES",
            "DebuggingPatternChecker",
            "DebuggingPatternVisitor",
            "DEBUGGING_RULES",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_checker_classes_importable(self, checker_name: str):
        """Test that checker classes and constants are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, checker_name), f"{checker_name} should be importable from pyguard"


class TestSecurityClasses:
    """Tests for security-related classes and functions."""

    @pytest.mark.parametrize(
        "security_item",
        [
            "XSSDetector",
            "XSS_RULES",
            "check_xss_vulnerabilities",
            "detect_xss_patterns",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_xss_detection_importable(self, security_item: str):
        """Test that XSS detection items are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, security_item), f"{security_item} should be importable from pyguard"


class TestCIIntegration:
    """Tests for CI/CD integration classes and functions."""

    @pytest.mark.parametrize(
        "ci_item",
        [
            "CIIntegrationGenerator",
            "PreCommitHookGenerator",
            "generate_ci_config",
            "install_pre_commit_hook",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_ci_integration_importable(self, ci_item: str):
        """Test that CI integration items are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, ci_item), f"{ci_item} should be importable from pyguard"


class TestPerformanceAndDependency:
    """Tests for performance and dependency analysis classes and functions."""

    @pytest.mark.parametrize(
        "item",
        [
            "PerformanceProfiler",
            "PerformanceOptimizationSuggester",
            "analyze_performance",
            "DependencyGraphAnalyzer",
            "analyze_project_dependencies",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_performance_dependency_importable(self, item: str):
        """Test that performance and dependency items are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, item), f"{item} should be importable from pyguard"


class TestCustomRules:
    """Tests for custom rules engine classes and functions."""

    @pytest.mark.parametrize(
        "rules_item",
        [
            "CustomRule",
            "CustomRuleEngine",
            "create_rule_engine_from_config",
        ],
        ids=lambda x: f"import-{x}",
    )
    def test_custom_rules_importable(self, rules_item: str):
        """Test that custom rules items are importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, rules_item), f"{rules_item} should be importable from pyguard"


class TestAllExports:
    """Tests for __all__ export list."""

    def test_all_attribute_exists(self):
        """Test that __all__ attribute exists and is a list."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, "__all__")
        assert isinstance(pyguard.__all__, list)
        assert len(pyguard.__all__) > 0

    def test_all_exports_are_strings(self):
        """Test that all items in __all__ are strings."""
        # Arrange
        import pyguard

        # Act & Assert
        for item in pyguard.__all__:
            assert isinstance(item, str), f"__all__ item should be string: {item}"

    def test_all_exports_are_available(self):
        """Test that all items in __all__ are actually available in the module."""
        # Arrange
        import pyguard

        # Act & Assert
        for item in pyguard.__all__:
            assert hasattr(pyguard, item), f"{item} in __all__ but not available in module"

    def test_no_duplicate_exports(self):
        """Test that __all__ contains no duplicates."""
        # Arrange
        import pyguard

        # Act
        all_items = pyguard.__all__

        # Assert
        assert len(all_items) == len(set(all_items)), "Duplicate items found in __all__"


class TestModuleImportIsolation:
    """Tests for module import isolation and no side effects."""

    def test_importing_pyguard_does_not_raise(self):
        """Test that importing pyguard module does not raise any exceptions."""
        # Act & Assert
        try:
            import pyguard

            assert pyguard is not None
        except Exception as e:
            pytest.fail(f"Importing pyguard raised an exception: {e}")

    def test_reimporting_pyguard_returns_same_module(self):
        """Test that re-importing pyguard returns the same module instance."""
        # Arrange
        import pyguard as pyguard1

        # Act
        import pyguard as pyguard2

        # Assert
        assert pyguard1 is pyguard2, "Re-importing should return same module instance"

    def test_string_operations_visitor_importable(self):
        """Test StringOperationsVisitor is importable."""
        # Arrange
        import pyguard

        # Act & Assert
        assert hasattr(pyguard, "StringOperationsVisitor")
        assert hasattr(pyguard, "StringOperationsFixer")
        assert hasattr(pyguard, "StringIssue")


class TestBackwardsCompatibility:
    """Tests to ensure backwards compatibility of public API."""

    def test_core_logger_importable(self):
        """Test that core PyGuardLogger is importable (critical for backwards compatibility)."""
        # Arrange
        import pyguard

        # Act
        logger_class = pyguard.PyGuardLogger

        # Assert
        assert logger_class is not None
        # Test it can be instantiated
        try:
            logger = logger_class()
            assert logger is not None
        except TypeError:
            # May require arguments
            pass

    def test_backup_manager_importable(self):
        """Test that BackupManager is importable (critical for backwards compatibility)."""
        # Arrange
        import pyguard

        # Act
        backup_class = pyguard.BackupManager

        # Assert
        assert backup_class is not None
