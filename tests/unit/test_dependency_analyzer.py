"""Tests for dependency analyzer module."""

import pytest
from pathlib import Path
from pyguard.lib.dependency_analyzer import (
    DependencyGraphAnalyzer,
    analyze_project_dependencies,
)


class TestDependencyGraphAnalyzer:
    """Test dependency graph analyzer."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = DependencyGraphAnalyzer()
        assert analyzer is not None
        assert len(analyzer.dependencies) == 0
        assert len(analyzer.issues) == 0

    def test_analyze_simple_file(self, tmp_path):
        """Test analyzing a simple file with imports."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import os
import sys
from pathlib import Path
""")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_file(test_file, "test")
        
        assert "test" in analyzer.dependencies
        assert "os" in analyzer.dependencies["test"]
        assert "sys" in analyzer.dependencies["test"]
        assert "pathlib" in analyzer.dependencies["test"]

    def test_analyze_file_with_from_import(self, tmp_path):
        """Test analyzing file with from imports."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from collections import defaultdict
from typing import Dict, List
""")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_file(test_file, "test")
        
        assert "collections" in analyzer.dependencies["test"]
        assert "typing" in analyzer.dependencies["test"]

    def test_analyze_file_with_syntax_error(self, tmp_path):
        """Test analyzing file with syntax error."""
        test_file = tmp_path / "test.py"
        test_file.write_text("import broken(")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_file(test_file, "test")
        
        # Should handle gracefully - no exception raised is success
        # Dependencies may or may not be added depending on error handling
        assert isinstance(analyzer.dependencies, dict)

    def test_reverse_dependencies(self, tmp_path):
        """Test reverse dependency tracking."""
        file1 = tmp_path / "module1.py"
        file1.write_text("import os")
        
        file2 = tmp_path / "module2.py"
        file2.write_text("import os")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_file(file1, "module1")
        analyzer.analyze_file(file2, "module2")
        
        assert "module1" in analyzer.reverse_dependencies["os"]
        assert "module2" in analyzer.reverse_dependencies["os"]

    def test_find_circular_dependencies(self):
        """Test finding circular dependencies."""
        analyzer = DependencyGraphAnalyzer()
        
        # Create artificial circular dependency
        analyzer.dependencies["A"].add("B")
        analyzer.dependencies["B"].add("C")
        analyzer.dependencies["C"].add("A")
        
        cycles = analyzer.find_circular_dependencies()
        
        assert len(cycles) > 0
        # Should find the A -> B -> C -> A cycle

    def test_no_circular_dependencies(self):
        """Test when there are no circular dependencies."""
        analyzer = DependencyGraphAnalyzer()
        
        # Create linear dependency chain
        analyzer.dependencies["A"].add("B")
        analyzer.dependencies["B"].add("C")
        
        cycles = analyzer.find_circular_dependencies()
        
        assert len(cycles) == 0

    def test_find_complex_dependencies(self):
        """Test finding modules with too many dependencies."""
        analyzer = DependencyGraphAnalyzer()
        
        # Create module with many dependencies
        for i in range(15):
            analyzer.dependencies["complex_module"].add(f"dep{i}")
        
        complex_mods = analyzer.find_complex_dependencies(threshold=10)
        
        assert "complex_module" in complex_mods
        assert complex_mods["complex_module"] == 15

    def test_find_god_modules(self):
        """Test finding god modules."""
        analyzer = DependencyGraphAnalyzer()
        
        # Create module that many others depend on
        for i in range(15):
            analyzer.reverse_dependencies["god_module"].add(f"user{i}")
        
        god_mods = analyzer.find_god_modules(threshold=10)
        
        assert "god_module" in god_mods
        assert god_mods["god_module"] == 15

    def test_detect_dependency_issues(self):
        """Test detecting all dependency issues."""
        analyzer = DependencyGraphAnalyzer()
        
        # Create circular dependency
        analyzer.dependencies["A"].add("B")
        analyzer.dependencies["B"].add("A")
        
        # Create complex module
        for i in range(15):
            analyzer.dependencies["complex"].add(f"dep{i}")
        
        issues = analyzer.detect_dependency_issues()
        
        assert len(issues) > 0
        assert any(issue.category == "Circular Dependency" for issue in issues)

    def test_generate_graph_data(self):
        """Test generating graph visualization data."""
        analyzer = DependencyGraphAnalyzer()
        
        analyzer.dependencies["A"].add("B")
        analyzer.dependencies["B"].add("C")
        # Also add C to dependencies so it's included in all_modules
        analyzer.dependencies["C"] = set()
        
        graph_data = analyzer.generate_graph_data()
        
        assert "nodes" in graph_data
        assert "edges" in graph_data
        assert len(graph_data["nodes"]) == 3
        assert len(graph_data["edges"]) == 2

    def test_generate_mermaid_diagram(self):
        """Test generating Mermaid diagram."""
        analyzer = DependencyGraphAnalyzer()
        
        analyzer.dependencies["module.a"].add("module.b")
        
        diagram = analyzer.generate_mermaid_diagram()
        
        assert "graph TD" in diagram
        assert "-->" in diagram

    def test_get_dependency_stats(self):
        """Test getting dependency statistics."""
        analyzer = DependencyGraphAnalyzer()
        
        analyzer.dependencies["A"].add("B")
        analyzer.dependencies["A"].add("C")
        analyzer.dependencies["B"].add("C")
        
        stats = analyzer.get_dependency_stats()
        
        assert "total_modules" in stats
        assert "total_dependencies" in stats
        assert "average_dependencies_per_module" in stats
        assert stats["total_modules"] == 2
        assert stats["total_dependencies"] == 3

    def test_get_stats_empty(self):
        """Test getting stats when empty."""
        analyzer = DependencyGraphAnalyzer()
        stats = analyzer.get_dependency_stats()
        
        assert stats["total_modules"] == 0
        assert stats["total_dependencies"] == 0
        assert stats["average_dependencies_per_module"] == 0

    def test_analyze_directory(self, tmp_path):
        """Test analyzing entire directory."""
        # Create test structure
        (tmp_path / "module1.py").write_text("import os")
        (tmp_path / "module2.py").write_text("import sys")
        
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "module3.py").write_text("import pathlib")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_directory(tmp_path)
        
        assert len(analyzer.dependencies) > 0

    def test_analyze_directory_skips_tests(self, tmp_path):
        """Test that analyze_directory skips test files."""
        (tmp_path / "module.py").write_text("import os")
        (tmp_path / "test_module.py").write_text("import pytest")
        
        analyzer = DependencyGraphAnalyzer()
        analyzer.analyze_directory(tmp_path)
        
        # Should have analyzed module.py but not test_module.py
        module_names = list(analyzer.dependencies.keys())
        assert not any("test" in name for name in module_names)


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_analyze_project_dependencies(self, tmp_path):
        """Test analyze_project_dependencies convenience function."""
        (tmp_path / "module.py").write_text("import os")
        
        analyzer = analyze_project_dependencies(str(tmp_path))
        
        assert isinstance(analyzer, DependencyGraphAnalyzer)
        assert len(analyzer.dependencies) > 0
