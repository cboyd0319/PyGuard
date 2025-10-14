"""
Dependency Graph Analyzer for PyGuard.

Analyzes and visualizes module dependencies in Python projects.
Detects circular dependencies and complex dependency patterns.
"""

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set


@dataclass
class DependencyIssue:
    """Represents a dependency-related issue."""

    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    modules: List[str]
    suggestion: str


class DependencyGraphAnalyzer:
    """Analyzes module dependencies and detects issues."""

    def __init__(self):
        """Initialize the dependency analyzer."""
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.issues: List[DependencyIssue] = []

    def analyze_file(self, file_path: Path, module_name: str) -> None:
        """
        Analyze a single file for imports.

        Args:
            file_path: Path to Python file
            module_name: Name of the module (e.g., 'mypackage.mymodule')
        """
        try:
            code = file_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(file_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported = alias.name
                        self.dependencies[module_name].add(imported)
                        self.reverse_dependencies[imported].add(module_name)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.dependencies[module_name].add(node.module)
                        self.reverse_dependencies[node.module].add(module_name)

        except (SyntaxError, UnicodeDecodeError):
            pass

    def analyze_directory(self, directory: Path, package_name: str = "") -> None:
        """
        Analyze all Python files in a directory.

        Args:
            directory: Directory to analyze
            package_name: Base package name for modules
        """
        for py_file in directory.rglob("*.py"):
            # Skip test files and __pycache__
            if "__pycache__" in str(py_file) or "test_" in py_file.name:
                continue

            # Calculate module name
            relative_path = py_file.relative_to(directory)
            module_parts = list(relative_path.parts[:-1]) + [py_file.stem]
            
            if module_parts[-1] == "__init__":
                module_parts = module_parts[:-1]
            
            if package_name:
                module_name = f"{package_name}.{'.'.join(module_parts)}"
            else:
                module_name = ".".join(module_parts)

            self.analyze_file(py_file, module_name)

    def find_circular_dependencies(self) -> List[List[str]]:
        """
        Find circular dependencies in the dependency graph.

        Returns:
            List of circular dependency chains
        """
        cycles = []
        visited = set()

        def dfs(node: str, path: List[str]) -> None:
            if node in path:
                # Found a cycle
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                if cycle not in cycles and list(reversed(cycle)) not in cycles:
                    cycles.append(cycle)
                return

            if node in visited:
                return

            visited.add(node)
            path.append(node)

            for dep in self.dependencies.get(node, set()):
                dfs(dep, path.copy())

        for module in self.dependencies:
            dfs(module, [])

        return cycles

    def find_complex_dependencies(self, threshold: int = 10) -> Dict[str, int]:
        """
        Find modules with too many dependencies.

        Args:
            threshold: Maximum number of dependencies

        Returns:
            Dictionary of modules with excessive dependencies
        """
        complex_modules = {}
        
        for module, deps in self.dependencies.items():
            if len(deps) > threshold:
                complex_modules[module] = len(deps)

        return complex_modules

    def find_god_modules(self, threshold: int = 10) -> Dict[str, int]:
        """
        Find modules that are dependencies of too many other modules.

        Args:
            threshold: Maximum number of reverse dependencies

        Returns:
            Dictionary of modules with excessive reverse dependencies
        """
        god_modules = {}
        
        for module, reverse_deps in self.reverse_dependencies.items():
            if len(reverse_deps) > threshold:
                god_modules[module] = len(reverse_deps)

        return god_modules

    def detect_dependency_issues(self) -> List[DependencyIssue]:
        """
        Detect all dependency-related issues.

        Returns:
            List of dependency issues
        """
        self.issues = []

        # Check for circular dependencies
        cycles = self.find_circular_dependencies()
        for cycle in cycles:
            self.issues.append(
                DependencyIssue(
                    severity="HIGH",
                    category="Circular Dependency",
                    message=f"Circular dependency detected: {' → '.join(cycle)}",
                    modules=cycle,
                    suggestion="Refactor to break the circular dependency using dependency injection or interface segregation",
                )
            )

        # Check for complex dependencies
        complex_modules = self.find_complex_dependencies()
        for module, count in complex_modules.items():
            self.issues.append(
                DependencyIssue(
                    severity="MEDIUM",
                    category="High Dependency Count",
                    message=f"Module {module} has {count} dependencies (threshold: 10)",
                    modules=[module],
                    suggestion="Consider splitting the module or using facade pattern to reduce coupling",
                )
            )

        # Check for god modules
        god_modules = self.find_god_modules()
        for module, count in god_modules.items():
            self.issues.append(
                DependencyIssue(
                    severity="MEDIUM",
                    category="God Module",
                    message=f"Module {module} is used by {count} other modules",
                    modules=[module],
                    suggestion="High coupling - consider if this module should be split into smaller, more focused modules",
                )
            )

        return self.issues

    def generate_graph_data(self) -> Dict[str, any]:
        """
        Generate data for dependency graph visualization.

        Returns:
            Dictionary with nodes and edges for visualization
        """
        nodes = []
        edges = []

        # Create nodes
        all_modules = set(self.dependencies.keys()) | set(
            self.reverse_dependencies.keys()
        )
        for i, module in enumerate(all_modules):
            nodes.append({"id": i, "label": module, "module": module})

        # Create edges
        module_to_id = {module: i for i, module in enumerate(all_modules)}
        for module, deps in self.dependencies.items():
            for dep in deps:
                if dep in module_to_id:
                    edges.append(
                        {"from": module_to_id[module], "to": module_to_id[dep]}
                    )

        return {"nodes": nodes, "edges": edges}

    def generate_mermaid_diagram(self) -> str:
        """
        Generate Mermaid diagram syntax for dependency graph.

        Returns:
            Mermaid diagram string
        """
        lines = ["graph TD"]

        # Add edges
        for module, deps in self.dependencies.items():
            for dep in deps:
                # Sanitize module names for Mermaid
                module_id = module.replace(".", "_").replace("-", "_")
                dep_id = dep.replace(".", "_").replace("-", "_")
                lines.append(f"    {module_id}[{module}] --> {dep_id}[{dep}]")

        return "\n".join(lines)

    def get_dependency_stats(self) -> Dict[str, any]:
        """
        Get statistics about dependencies.

        Returns:
            Dictionary with dependency statistics
        """
        total_modules = len(self.dependencies)
        total_dependencies = sum(len(deps) for deps in self.dependencies.values())
        avg_dependencies = total_dependencies / total_modules if total_modules > 0 else 0

        return {
            "total_modules": total_modules,
            "total_dependencies": total_dependencies,
            "average_dependencies_per_module": round(avg_dependencies, 2),
            "max_dependencies": max(
                (len(deps) for deps in self.dependencies.values()), default=0
            ),
            "modules_with_no_dependencies": len(
                [m for m, deps in self.dependencies.items() if not deps]
            ),
        }


def analyze_project_dependencies(
    project_path: str, package_name: str = ""
) -> DependencyGraphAnalyzer:
    """
    Convenience function to analyze project dependencies.

    Args:
        project_path: Path to project directory
        package_name: Base package name

    Returns:
        Analyzer with dependency data
    """
    analyzer = DependencyGraphAnalyzer()
    analyzer.analyze_directory(Path(project_path), package_name)
    analyzer.detect_dependency_issues()
    return analyzer
