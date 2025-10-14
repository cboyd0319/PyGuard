"""Unit tests for fix safety classification system."""

import pytest

from pyguard.lib.fix_safety import (
    FixClassification,
    FixSafety,
    FixSafetyClassifier,
)


class TestFixSafetyClassifier:
    """Test cases for FixSafetyClassifier."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.classifier = FixSafetyClassifier()
    
    def test_initialization(self):
        """Test classifier initializes with predefined classifications."""
        stats = self.classifier.get_statistics()
        assert stats["total"] > 0
        assert stats["safe"] > 0
        assert stats["unsafe"] > 0
        assert stats["warning_only"] > 0
    
    def test_safe_fix_classification(self):
        """Test SAFE fix classification."""
        classification = self.classifier.get_classification("import_sorting")
        assert classification is not None
        assert classification.safety == FixSafety.SAFE
        assert classification.category == "style"
        assert self.classifier.is_safe("import_sorting")
        assert not self.classifier.is_unsafe("import_sorting")
        assert not self.classifier.is_warning_only("import_sorting")
    
    def test_unsafe_fix_classification(self):
        """Test UNSAFE fix classification."""
        classification = self.classifier.get_classification("sql_parameterization")
        assert classification is not None
        assert classification.safety == FixSafety.UNSAFE
        assert classification.category == "security"
        assert not self.classifier.is_safe("sql_parameterization")
        assert self.classifier.is_unsafe("sql_parameterization")
        assert not self.classifier.is_warning_only("sql_parameterization")
    
    def test_warning_only_fix_classification(self):
        """Test WARNING_ONLY fix classification."""
        classification = self.classifier.get_classification("hardcoded_secrets")
        assert classification is not None
        assert classification.safety == FixSafety.WARNING_ONLY
        assert classification.category == "security"
        assert not self.classifier.is_safe("hardcoded_secrets")
        assert not self.classifier.is_unsafe("hardcoded_secrets")
        assert self.classifier.is_warning_only("hardcoded_secrets")
    
    def test_unknown_fix(self):
        """Test handling of unknown fix IDs."""
        classification = self.classifier.get_classification("unknown_fix")
        assert classification is None
        assert not self.classifier.is_safe("unknown_fix")
        assert not self.classifier.is_unsafe("unknown_fix")
        assert not self.classifier.is_warning_only("unknown_fix")
    
    def test_should_apply_fix_safe(self):
        """Test should_apply_fix for SAFE fixes."""
        # SAFE fixes should always be applied
        assert self.classifier.should_apply_fix("import_sorting", allow_unsafe=False)
        assert self.classifier.should_apply_fix("import_sorting", allow_unsafe=True)
        assert self.classifier.should_apply_fix("yaml_safe_load", allow_unsafe=False)
    
    def test_should_apply_fix_unsafe(self):
        """Test should_apply_fix for UNSAFE fixes."""
        # UNSAFE fixes should only be applied with allow_unsafe=True
        assert not self.classifier.should_apply_fix("sql_parameterization", allow_unsafe=False)
        assert self.classifier.should_apply_fix("sql_parameterization", allow_unsafe=True)
        assert not self.classifier.should_apply_fix("command_subprocess", allow_unsafe=False)
        assert self.classifier.should_apply_fix("command_subprocess", allow_unsafe=True)
    
    def test_should_apply_fix_warning_only(self):
        """Test should_apply_fix for WARNING_ONLY fixes."""
        # WARNING_ONLY fixes should never be applied automatically
        assert not self.classifier.should_apply_fix("hardcoded_secrets", allow_unsafe=False)
        assert not self.classifier.should_apply_fix("hardcoded_secrets", allow_unsafe=True)
        assert not self.classifier.should_apply_fix("eval_exec_warning", allow_unsafe=False)
        assert not self.classifier.should_apply_fix("eval_exec_warning", allow_unsafe=True)
    
    def test_should_apply_fix_unknown(self):
        """Test should_apply_fix for unknown fixes."""
        # Unknown fixes should never be applied
        assert not self.classifier.should_apply_fix("unknown_fix", allow_unsafe=False)
        assert not self.classifier.should_apply_fix("unknown_fix", allow_unsafe=True)
    
    def test_get_all_safe_fixes(self):
        """Test getting all SAFE fixes."""
        safe_fixes = self.classifier.get_all_safe_fixes()
        assert len(safe_fixes) > 0
        assert "import_sorting" in safe_fixes
        assert "yaml_safe_load" in safe_fixes
        assert "comparison_to_none" in safe_fixes
        # Should not contain unsafe or warning_only
        assert "sql_parameterization" not in safe_fixes
        assert "hardcoded_secrets" not in safe_fixes
    
    def test_get_all_unsafe_fixes(self):
        """Test getting all UNSAFE fixes."""
        unsafe_fixes = self.classifier.get_all_unsafe_fixes()
        assert len(unsafe_fixes) > 0
        assert "sql_parameterization" in unsafe_fixes
        assert "command_subprocess" in unsafe_fixes
        assert "path_traversal_validation" in unsafe_fixes
        # Should not contain safe or warning_only
        assert "import_sorting" not in unsafe_fixes
        assert "hardcoded_secrets" not in unsafe_fixes
    
    def test_get_all_warning_only_fixes(self):
        """Test getting all WARNING_ONLY fixes."""
        warning_only_fixes = self.classifier.get_all_warning_only_fixes()
        assert len(warning_only_fixes) > 0
        assert "hardcoded_secrets" in warning_only_fixes
        assert "eval_exec_warning" in warning_only_fixes
        assert "pickle_warning" in warning_only_fixes
        # Should not contain safe or unsafe
        assert "import_sorting" not in warning_only_fixes
        assert "sql_parameterization" not in warning_only_fixes
    
    def test_get_fixes_by_category_security(self):
        """Test getting fixes by security category."""
        security_fixes = self.classifier.get_fixes_by_category("security")
        assert len(security_fixes) > 0
        assert "yaml_safe_load" in security_fixes
        assert "sql_parameterization" in security_fixes
        assert "hardcoded_secrets" in security_fixes
        # Should not contain non-security fixes
        assert "import_sorting" not in security_fixes
    
    def test_get_fixes_by_category_style(self):
        """Test getting fixes by style category."""
        style_fixes = self.classifier.get_fixes_by_category("style")
        assert len(style_fixes) > 0
        assert "import_sorting" in style_fixes
        assert "trailing_whitespace" in style_fixes
        assert "quote_normalization" in style_fixes
        # Should not contain non-style fixes
        assert "yaml_safe_load" not in style_fixes
    
    def test_get_fixes_by_category_quality(self):
        """Test getting fixes by quality category."""
        quality_fixes = self.classifier.get_fixes_by_category("quality")
        assert len(quality_fixes) > 0
        assert "comparison_to_none" in quality_fixes
        assert "type_comparison" in quality_fixes
        # Should not contain non-quality fixes
        assert "import_sorting" not in quality_fixes
    
    def test_get_statistics(self):
        """Test getting classification statistics."""
        stats = self.classifier.get_statistics()
        
        # Check all expected keys exist
        assert "total" in stats
        assert "safe" in stats
        assert "unsafe" in stats
        assert "warning_only" in stats
        assert "category_security" in stats
        assert "category_quality" in stats
        assert "category_style" in stats
        
        # Check totals match
        assert stats["total"] == stats["safe"] + stats["unsafe"] + stats["warning_only"]
        
        # Check counts are reasonable
        assert stats["safe"] >= 5  # At least 5 safe fixes
        assert stats["unsafe"] >= 3  # At least 3 unsafe fixes
        assert stats["warning_only"] >= 3  # At least 3 warning-only fixes
        assert stats["category_security"] > 0
        assert stats["category_style"] > 0
        assert stats["category_quality"] > 0
    
    def test_fix_classification_dataclass(self):
        """Test FixClassification dataclass."""
        classification = FixClassification(
            fix_id="test_fix",
            safety=FixSafety.SAFE,
            category="test",
            description="Test fix",
            reasoning="For testing"
        )
        
        assert classification.fix_id == "test_fix"
        assert classification.safety == FixSafety.SAFE
        assert classification.category == "test"
        assert classification.description == "Test fix"
        assert classification.reasoning == "For testing"
        assert classification.examples is None
    
    def test_fix_classification_with_examples(self):
        """Test FixClassification with examples."""
        classification = FixClassification(
            fix_id="test_fix",
            safety=FixSafety.SAFE,
            category="test",
            description="Test fix",
            reasoning="For testing",
            examples=["example1", "example2"]
        )
        
        assert classification.examples == ["example1", "example2"]
    
    def test_multiple_security_safe_fixes(self):
        """Test that we have multiple safe security fixes."""
        security_fixes = self.classifier.get_fixes_by_category("security")
        safe_security = [
            fix_id for fix_id in security_fixes
            if self.classifier.is_safe(fix_id)
        ]
        assert len(safe_security) >= 2  # At least 2 safe security fixes
        assert "yaml_safe_load" in safe_security
        assert "mkstemp_replacement" in safe_security
    
    def test_multiple_security_unsafe_fixes(self):
        """Test that we have multiple unsafe security fixes."""
        security_fixes = self.classifier.get_fixes_by_category("security")
        unsafe_security = [
            fix_id for fix_id in security_fixes
            if self.classifier.is_unsafe(fix_id)
        ]
        assert len(unsafe_security) >= 3  # At least 3 unsafe security fixes
        assert "sql_parameterization" in unsafe_security
        assert "command_subprocess" in unsafe_security
        assert "path_traversal_validation" in unsafe_security
    
    def test_multiple_security_warning_only_fixes(self):
        """Test that we have multiple warning-only security fixes."""
        security_fixes = self.classifier.get_fixes_by_category("security")
        warning_security = [
            fix_id for fix_id in security_fixes
            if self.classifier.is_warning_only(fix_id)
        ]
        assert len(warning_security) >= 4  # At least 4 warning-only security fixes
        assert "hardcoded_secrets" in warning_security
        assert "eval_exec_warning" in warning_security
        assert "pickle_warning" in warning_security


class TestFixSafetyEnum:
    """Test cases for FixSafety enum."""
    
    def test_enum_values(self):
        """Test enum has expected values."""
        assert FixSafety.SAFE.value == "safe"
        assert FixSafety.UNSAFE.value == "unsafe"
        assert FixSafety.WARNING_ONLY.value == "warning_only"
    
    def test_enum_comparison(self):
        """Test enum comparison."""
        assert FixSafety.SAFE == FixSafety.SAFE
        assert FixSafety.SAFE != FixSafety.UNSAFE
        assert FixSafety.UNSAFE != FixSafety.WARNING_ONLY
