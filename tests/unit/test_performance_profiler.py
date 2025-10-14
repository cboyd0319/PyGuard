"""Tests for performance profiler module."""

import pytest
from pathlib import Path
from pyguard.lib.performance_profiler import (
    PerformanceProfiler,
    PerformanceOptimizationSuggester,
    analyze_performance,
)


class TestPerformanceProfiler:
    """Test performance profiler."""

    def test_initialization(self):
        """Test profiler initialization."""
        profiler = PerformanceProfiler()
        assert profiler is not None
        assert profiler.issues == []

    def test_detect_list_concat_in_loop(self):
        """Test detection of list concatenation in loop."""
        code = """
result = []
for i in range(10):
    result += [i]  # Inefficient
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("concatenation" in issue.message.lower() for issue in issues)

    def test_detect_nested_loops(self):
        """Test detection of nested loops."""
        code = """
for i in range(10):
    for j in range(10):
        print(i, j)
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("nested" in issue.message.lower() for issue in issues)

    def test_detect_regex_in_loop(self):
        """Test detection of uncompiled regex."""
        code = """
import re
for text in texts:
    if re.match(r'pattern', text):
        pass
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("regex" in issue.message.lower() for issue in issues)

    def test_detect_dict_keys_iteration(self):
        """Test detection of redundant .keys()."""
        code = """
for key in my_dict.keys():
    print(key)
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("keys" in issue.message.lower() for issue in issues)

    def test_detect_sum_with_list(self):
        """Test detection of sum with list comprehension."""
        code = """
total = sum([x * 2 for x in range(1000)])
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("sum" in issue.message.lower() for issue in issues)

    def test_detect_complex_comprehension(self):
        """Test detection of complex list comprehension."""
        code = """
result = [x * y * z for x in range(10) for y in range(10) for z in range(10) if x + y + z > 15]
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        assert len(issues) > 0
        assert any("complex" in issue.message.lower() for issue in issues)

    def test_safe_code_no_issues(self):
        """Test that safe code produces no issues."""
        code = """
result = [x * 2 for x in range(10)]
my_dict = {k: v for k, v in items}
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        # Should have minimal or no issues
        assert len(issues) == 0

    def test_analyze_file(self, tmp_path):
        """Test analyzing a file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
for i in range(10):
    for j in range(10):
        print(i, j)
""")
        
        profiler = PerformanceProfiler()
        issues = profiler.analyze_file(test_file)
        
        assert len(issues) > 0

    def test_analyze_file_with_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def broken(")
        
        profiler = PerformanceProfiler()
        issues = profiler.analyze_file(test_file)
        
        assert len(issues) == 0  # Should handle gracefully

    def test_issue_has_all_fields(self):
        """Test that issues have all required fields."""
        code = """
for i in range(10):
    result += [i]
"""
        profiler = PerformanceProfiler()
        issues = profiler.analyze_code(code)
        
        if len(issues) > 0:
            issue = issues[0]
            assert issue.severity in ["HIGH", "MEDIUM", "LOW"]
            assert issue.category
            assert issue.message
            assert issue.line_number > 0
            assert issue.suggestion
            assert issue.estimated_impact


class TestPerformanceOptimizationSuggester:
    """Test optimization suggester."""

    def test_initialization(self):
        """Test suggester initialization."""
        suggester = PerformanceOptimizationSuggester()
        assert suggester is not None
        assert len(suggester.optimizations) > 0

    def test_list_patterns(self):
        """Test listing optimization patterns."""
        suggester = PerformanceOptimizationSuggester()
        patterns = suggester.list_patterns()
        
        assert len(patterns) > 0
        assert "list_comprehension" in patterns
        assert "dict_comprehension" in patterns
        assert "set_membership" in patterns
        assert "string_concat" in patterns

    def test_get_suggestion_list_comprehension(self):
        """Test getting list comprehension suggestion."""
        suggester = PerformanceOptimizationSuggester()
        suggestion = suggester.get_suggestion("list_comprehension")
        
        assert suggestion is not None
        assert "pattern" in suggestion
        assert "optimized" in suggestion
        assert "speedup" in suggestion

    def test_get_suggestion_dict_comprehension(self):
        """Test getting dict comprehension suggestion."""
        suggester = PerformanceOptimizationSuggester()
        suggestion = suggester.get_suggestion("dict_comprehension")
        
        assert suggestion is not None
        assert "for key, value" in suggestion["pattern"]

    def test_get_suggestion_set_membership(self):
        """Test getting set membership suggestion."""
        suggester = PerformanceOptimizationSuggester()
        suggestion = suggester.get_suggestion("set_membership")
        
        assert suggestion is not None
        assert "O(n)" in suggestion["speedup"]
        assert "O(1)" in suggestion["speedup"]

    def test_get_suggestion_string_concat(self):
        """Test getting string concatenation suggestion."""
        suggester = PerformanceOptimizationSuggester()
        suggestion = suggester.get_suggestion("string_concat")
        
        assert suggestion is not None
        assert "join" in suggestion["optimized"]

    def test_get_nonexistent_pattern(self):
        """Test getting non-existent pattern."""
        suggester = PerformanceOptimizationSuggester()
        suggestion = suggester.get_suggestion("nonexistent_pattern")
        
        assert suggestion is None


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_analyze_performance_function(self, tmp_path):
        """Test analyze_performance convenience function."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
for i in range(10):
    for j in range(10):
        pass
""")
        
        issues = analyze_performance(str(test_file))
        assert isinstance(issues, list)
