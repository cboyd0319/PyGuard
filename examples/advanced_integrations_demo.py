#!/usr/bin/env python3
"""
Demo of PyGuard Advanced Integrations.

Demonstrates:
- CI/CD Integration
- Performance Profiler
- Dependency Analyzer
- Custom Rules Engine
"""


def demo_ci_integration():
    """Demonstrate CI/CD integration features."""

    from pyguard.lib.ci_integration import CIIntegrationGenerator

    generator = CIIntegrationGenerator()

    # List supported platforms
    generator.list_supported_platforms()

    # Generate GitHub Actions config
    generator.generate_config("github_actions")

    # Generate pre-commit hook
    from pyguard.lib.ci_integration import PreCommitHookGenerator

    hook_gen = PreCommitHookGenerator()
    hook_gen.generate_hook_script(security_only=True)


def demo_performance_profiler():
    """Demonstrate performance profiler features."""

    from pyguard.lib.performance_profiler import (
        PerformanceOptimizationSuggester,
        PerformanceProfiler,
    )

    profiler = PerformanceProfiler()

    # Sample code with performance issues
    code = """
import re

def process_data(items):
    result = []
    for item in items:
        # Issue 1: Uncompiled regex
        if re.match(r'pattern', item):
            # Issue 2: List concatenation
            result += [item]

    # Issue 3: Nested loops
    for i in range(len(result)):
        for j in range(len(result)):
            if i != j:
                print(i, j)

    return result
"""

    issues = profiler.analyze_code(code)

    for _i, _issue in enumerate(issues, 1):
        pass

    # Show optimization suggestions
    suggester = PerformanceOptimizationSuggester()
    patterns = suggester.list_patterns()

    for pattern in patterns[:2]:  # Show first 2
        suggester.get_suggestion(pattern)


def demo_dependency_analyzer():
    """Demonstrate dependency analyzer features."""

    from pyguard.lib.dependency_analyzer import DependencyGraphAnalyzer

    analyzer = DependencyGraphAnalyzer()

    # Create sample dependency structure
    analyzer.dependencies["myapp.views"].add("myapp.models")
    analyzer.dependencies["myapp.views"].add("myapp.utils")
    analyzer.dependencies["myapp.models"].add("myapp.database")
    analyzer.dependencies["myapp.utils"].add("myapp.config")
    analyzer.dependencies["myapp.api"].add("myapp.views")
    analyzer.dependencies["myapp.api"].add("myapp.models")
    analyzer.dependencies["myapp.tests"].add("myapp.views")
    analyzer.dependencies["myapp.tests"].add("myapp.models")

    # Get statistics
    analyzer.get_dependency_stats()

    # Find circular dependencies
    cycles = analyzer.find_circular_dependencies()
    if cycles:
        for _cycle in cycles:
            pass
    else:
        pass

    # Find complex modules
    complex_mods = analyzer.find_complex_dependencies(threshold=2)
    if complex_mods:
        for _mod, _count in complex_mods.items():
            pass

    # Generate Mermaid diagram
    diagram = analyzer.generate_mermaid_diagram()
    lines = diagram.split("\n")
    for _line in lines[:5]:
        pass


def demo_custom_rules():
    """Demonstrate custom rules engine features."""

    from pyguard.lib.custom_rules import CustomRuleEngine

    engine = CustomRuleEngine()

    # Add regex-based rules

    engine.add_regex_rule(
        rule_id="NO_PRINT",
        name="No print statements",
        pattern=r"\bprint\s*\(",
        severity="MEDIUM",
        category="Code Quality",
        description="Print statements should not be used in production",
        suggestion="Use logging instead",
    )

    engine.add_regex_rule(
        rule_id="NO_HARDCODED_PORT",
        name="No hardcoded ports",
        pattern=r"\bport\s*=\s*\d{4,5}",
        severity="HIGH",
        category="Security",
        description="Port numbers should be configurable",
        suggestion="Use environment variables",
    )

    # List rules
    rules = engine.list_rules()
    for _rule in rules:
        pass

    # Check code against rules

    code = """
def start_server():
    port = 8080  # Hardcoded port
    print(f"Starting server on port {port}")  # Print statement
    return port
"""

    violations = engine.check_code(code)
    for _v in violations:
        pass


def demo_advanced_ast_rules():
    """Demonstrate AST-based custom rules."""

    import ast

    from pyguard.lib.custom_rules import CustomRuleEngine

    def check_too_many_arguments(tree: ast.AST) -> list:
        """Find functions with too many arguments."""
        lines = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and len(node.args.args) > 5:
                lines.append(node.lineno)
        return lines

    engine = CustomRuleEngine()

    engine.add_ast_rule(
        rule_id="TOO_MANY_ARGS",
        name="Too many function arguments",
        checker=check_too_many_arguments,
        severity="MEDIUM",
        category="Code Quality",
        description="Functions should have at most 5 arguments",
        suggestion="Use a config object or dataclass instead",
    )

    # Check code
    code = """
def complex_function(arg1, arg2, arg3, arg4, arg5, arg6):
    # Too many arguments!
    return arg1 + arg2 + arg3 + arg4 + arg5 + arg6
"""

    violations = engine.check_code(code)

    if violations:
        for _v in violations:
            pass
    else:
        pass


def main():
    """Run all demos."""

    try:
        demo_ci_integration()
        demo_performance_profiler()
        demo_dependency_analyzer()
        demo_custom_rules()
        demo_advanced_ast_rules()

    except Exception:
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
