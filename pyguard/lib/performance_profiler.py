"""
Performance Profiler for PyGuard.

Analyzes Python code for performance bottlenecks and optimization opportunities.
Detects inefficient patterns and suggests improvements.
"""

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PerformanceIssue:
    """Represents a performance issue in code."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    line_number: int
    suggestion: str
    estimated_impact: str  # e.g., "10-100x slowdown", "High memory usage"


class PerformanceProfiler(ast.NodeVisitor):
    """AST-based performance profiler for Python code."""

    def __init__(self):
        """Initialize the performance profiler."""
        self.issues: list[PerformanceIssue] = []
        self.current_line = 0

    def visit_For(self, node: ast.For) -> None:
        """Check for inefficient loops."""
        self.current_line = node.lineno

        # Check for list concatenation in loops
        if self._has_list_append_in_loop(node):
            # This is actually fine
            pass

        # Check for list concatenation with +=
        if self._has_list_concat_in_loop(node):
            self.issues.append(
                PerformanceIssue(
                    severity="MEDIUM",
                    category="Inefficient Loop",
                    message="List concatenation with += in loop is inefficient",
                    line_number=node.lineno,
                    suggestion="Use list.append() or list comprehension instead",
                    estimated_impact="N² time complexity, use append() for O(N)",
                )
            )

        # Check for nested loops without break/early exit
        if self._has_nested_loops(node):
            self.issues.append(
                PerformanceIssue(
                    severity="LOW",
                    category="Nested Loops",
                    message="Nested loops without early exit may be slow",
                    line_number=node.lineno,
                    suggestion="Consider using break, continue, or algorithmic optimization",
                    estimated_impact="O(N²) or worse time complexity",
                )
            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for inefficient function calls."""
        self.current_line = node.lineno

        # Check for repeated list() or dict() calls
        if isinstance(node.func, ast.Name):
            if node.func.id in ["list", "dict", "set", "tuple"]:
                # Check if called multiple times with same argument
                pass

        # Check for repeated regex compilation
        if self._is_re_match_call(node) or self._is_re_search_call(node):
            self.issues.append(
                PerformanceIssue(
                    severity="MEDIUM",
                    category="Regex Performance",
                    message="Regex pattern should be compiled once, not in loop/function",
                    line_number=node.lineno,
                    suggestion="Compile regex with re.compile() at module level",
                    estimated_impact="10-100x slower than compiled regex",
                )
            )

        # Check for .keys() in dict iteration
        if self._is_dict_keys_iteration(node):
            self.issues.append(
                PerformanceIssue(
                    severity="LOW",
                    category="Redundant Dict Keys",
                    message="Calling .keys() is redundant when iterating dict",
                    line_number=node.lineno,
                    suggestion="Iterate dict directly: 'for key in dict:'",
                    estimated_impact="Minor overhead, readability issue",
                )
            )

        # Check for sum() with generator vs list
        if self._is_sum_with_list(node):
            self.issues.append(
                PerformanceIssue(
                    severity="LOW",
                    category="Memory Efficiency",
                    message="sum() with list creates unnecessary intermediate list",
                    line_number=node.lineno,
                    suggestion="Use generator expression instead: sum(x for x in ...)",
                    estimated_impact="High memory usage for large datasets",
                )
            )

        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Check list comprehension performance."""
        self.current_line = node.lineno

        # Check for complex list comprehension
        if self._is_complex_comprehension(node):
            self.issues.append(
                PerformanceIssue(
                    severity="LOW",
                    category="Code Clarity",
                    message="Complex list comprehension may be hard to optimize",
                    line_number=node.lineno,
                    suggestion="Consider breaking into multiple steps or using function",
                    estimated_impact="Readability and maintainability issue",
                )
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check for imports inside functions."""
        # This would need context tracking to detect if inside function
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check for imports inside functions."""
        # This would need context tracking
        self.generic_visit(node)

    def _has_list_concat_in_loop(self, node: ast.For) -> bool:
        """Check if loop has list concatenation with +=."""
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                return True
        return False

    def _has_nested_loops(self, node: ast.For) -> bool:
        """Check if loop has nested loops."""
        for child in ast.walk(node):
            if isinstance(child, (ast.For, ast.While)) and child != node:
                return True
        return False

    def _has_list_append_in_loop(self, node: ast.For) -> bool:
        """Check if loop uses list.append()."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute) and child.func.attr == "append":
                    return True
        return False

    def _is_re_match_call(self, node: ast.Call) -> bool:
        """Check if call is re.match()."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "re" and node.func.attr in [
                "match",
                "search",
                "findall",
            ]:
                return True
        return False

    def _is_re_search_call(self, node: ast.Call) -> bool:
        """Check if call is re.search()."""
        return self._is_re_match_call(node)

    def _is_dict_keys_iteration(self, node: ast.Call) -> bool:
        """Check if iterating dict.keys()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "keys"

    def _is_sum_with_list(self, node: ast.Call) -> bool:
        """Check if sum() is called with list comprehension."""
        if isinstance(node.func, ast.Name) and node.func.id == "sum":
            if node.args and isinstance(node.args[0], ast.ListComp):
                return True
        return False

    def _is_complex_comprehension(self, node: ast.ListComp) -> bool:
        """Check if list comprehension is complex."""
        # Count number of generators
        if len(node.generators) > 2:
            return True

        # Check for complex expressions
        return len(list(ast.walk(node.elt))) > 10

    def analyze_file(self, file_path: Path) -> list[PerformanceIssue]:
        """
        Analyze a Python file for performance issues.

        Args:
            file_path: Path to Python file

        Returns:
            List of performance issues found
        """
        try:
            code = file_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(file_path))
            self.issues = []
            self.visit(tree)
            return self.issues
        except SyntaxError:
            return []

    def analyze_code(self, code: str) -> list[PerformanceIssue]:
        """
        Analyze Python code string for performance issues.

        Args:
            code: Python code string

        Returns:
            List of performance issues found
        """
        try:
            tree = ast.parse(code)
            self.issues = []
            self.visit(tree)
            return self.issues
        except SyntaxError:
            return []


class PerformanceOptimizationSuggester:
    """Suggests performance optimizations for common patterns."""

    def __init__(self):
        """Initialize the optimization suggester."""
        self.optimizations = self._load_optimizations()

    def _load_optimizations(self) -> dict:
        """Load optimization patterns."""
        return {
            "list_comprehension": {
                "pattern": "result = []\nfor item in items:\n    result.append(f(item))",
                "optimized": "result = [f(item) for item in items]",
                "speedup": "1.5-2x faster",
            },
            "dict_comprehension": {
                "pattern": "result = {}\nfor key, value in items:\n    result[key] = f(value)",
                "optimized": "result = {key: f(value) for key, value in items}",
                "speedup": "1.5-2x faster",
            },
            "set_membership": {
                "pattern": "if item in list_of_items:",
                "optimized": "if item in set_of_items:",
                "speedup": "O(n) → O(1), 100-1000x faster for large lists",
            },
            "string_concat": {
                "pattern": "result = ''\nfor s in strings:\n    result += s",
                "optimized": "result = ''.join(strings)",
                "speedup": "O(n²) → O(n), 10-100x faster",
            },
        }

    def get_suggestion(self, pattern_name: str) -> dict | None:
        """
        Get optimization suggestion for a pattern.

        Args:
            pattern_name: Name of the pattern

        Returns:
            Optimization details or None
        """
        return self.optimizations.get(pattern_name)

    def list_patterns(self) -> list[str]:
        """
        Get list of all optimization patterns.

        Returns:
            List of pattern names
        """
        return list(self.optimizations.keys())


def analyze_performance(file_path: str) -> list[PerformanceIssue]:
    """
    Convenience function to analyze file performance.

    Args:
        file_path: Path to Python file

    Returns:
        List of performance issues
    """
    profiler = PerformanceProfiler()
    return profiler.analyze_file(Path(file_path))
