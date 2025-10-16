#!/usr/bin/env python3
"""
Demo of PyGuard Advanced Integrations.

Demonstrates:
- CI/CD Integration
- Performance Profiler
- Dependency Analyzer
- Custom Rules Engine
"""

from pathlib import Path


def demo_ci_integration():
    """Demonstrate CI/CD integration features."""
    print("\n" + "=" * 60)
    print("CI/CD INTEGRATION DEMO")
    print("=" * 60)

    from pyguard.lib.ci_integration import CIIntegrationGenerator

    generator = CIIntegrationGenerator()

    # List supported platforms
    platforms = generator.list_supported_platforms()
    print(f"\n✓ Supported CI/CD platforms: {', '.join(platforms)}")

    # Generate GitHub Actions config
    print("\n📝 Generating GitHub Actions workflow...")
    gh_config = generator.generate_config("github_actions")
    print(f"   Generated {len(gh_config)} bytes of YAML config")
    print("\n   Preview (first 200 chars):")
    print(f"   {gh_config[:200]}...")

    # Generate pre-commit hook
    print("\n📝 Generating pre-commit hook...")
    from pyguard.lib.ci_integration import PreCommitHookGenerator

    hook_gen = PreCommitHookGenerator()
    hook_script = hook_gen.generate_hook_script(security_only=True)
    print(f"   Generated {len(hook_script)} bytes of bash script")


def demo_performance_profiler():
    """Demonstrate performance profiler features."""
    print("\n" + "=" * 60)
    print("PERFORMANCE PROFILER DEMO")
    print("=" * 60)

    from pyguard.lib.performance_profiler import (
        PerformanceProfiler,
        PerformanceOptimizationSuggester,
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

    print("\n🔍 Analyzing code for performance issues...")
    issues = profiler.analyze_code(code)

    print(f"\n✓ Found {len(issues)} performance issues:")
    for i, issue in enumerate(issues, 1):
        print(f"\n   {i}. {issue.severity}: {issue.category}")
        print(f"      Line {issue.line_number}: {issue.message}")
        print(f"      💡 {issue.suggestion}")
        print(f"      📊 {issue.estimated_impact}")

    # Show optimization suggestions
    print("\n📚 Optimization suggestions:")
    suggester = PerformanceOptimizationSuggester()
    patterns = suggester.list_patterns()

    for pattern in patterns[:2]:  # Show first 2
        suggestion = suggester.get_suggestion(pattern)
        print(f"\n   Pattern: {pattern}")
        print(f"   Speedup: {suggestion['speedup']}")


def demo_dependency_analyzer():
    """Demonstrate dependency analyzer features."""
    print("\n" + "=" * 60)
    print("DEPENDENCY ANALYZER DEMO")
    print("=" * 60)

    from pyguard.lib.dependency_analyzer import DependencyGraphAnalyzer

    analyzer = DependencyGraphAnalyzer()

    # Create sample dependency structure
    print("\n🔍 Analyzing dependencies...")
    analyzer.dependencies["myapp.views"].add("myapp.models")
    analyzer.dependencies["myapp.views"].add("myapp.utils")
    analyzer.dependencies["myapp.models"].add("myapp.database")
    analyzer.dependencies["myapp.utils"].add("myapp.config")
    analyzer.dependencies["myapp.api"].add("myapp.views")
    analyzer.dependencies["myapp.api"].add("myapp.models")
    analyzer.dependencies["myapp.tests"].add("myapp.views")
    analyzer.dependencies["myapp.tests"].add("myapp.models")

    # Get statistics
    stats = analyzer.get_dependency_stats()
    print(f"\n✓ Dependency statistics:")
    print(f"   Total modules: {stats['total_modules']}")
    print(f"   Total dependencies: {stats['total_dependencies']}")
    print(f"   Average dependencies per module: {stats['average_dependencies_per_module']}")
    print(f"   Max dependencies: {stats['max_dependencies']}")

    # Find circular dependencies
    print("\n🔍 Checking for circular dependencies...")
    cycles = analyzer.find_circular_dependencies()
    if cycles:
        print(f"   ⚠️ Found {len(cycles)} circular dependencies!")
        for cycle in cycles:
            print(f"      {' → '.join(cycle)}")
    else:
        print("   ✓ No circular dependencies found")

    # Find complex modules
    print("\n🔍 Finding complex modules (>2 dependencies)...")
    complex_mods = analyzer.find_complex_dependencies(threshold=2)
    if complex_mods:
        print(f"   Found {len(complex_mods)} complex modules:")
        for mod, count in complex_mods.items():
            print(f"      {mod}: {count} dependencies")

    # Generate Mermaid diagram
    print("\n📊 Generating Mermaid diagram...")
    diagram = analyzer.generate_mermaid_diagram()
    lines = diagram.split("\n")
    print(f"   Generated diagram with {len(lines)} nodes/edges")
    print(f"\n   Preview (first 5 lines):")
    for line in lines[:5]:
        print(f"      {line}")


def demo_custom_rules():
    """Demonstrate custom rules engine features."""
    print("\n" + "=" * 60)
    print("CUSTOM RULES ENGINE DEMO")
    print("=" * 60)

    from pyguard.lib.custom_rules import CustomRuleEngine

    engine = CustomRuleEngine()

    # Add regex-based rules
    print("\n📝 Adding custom rules...")

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
    print(f"\n✓ Added {len(rules)} custom rules:")
    for rule in rules:
        print(f"   {rule.rule_id}: {rule.name} ({rule.severity})")

    # Check code against rules
    print("\n🔍 Checking code against custom rules...")

    code = """
def start_server():
    port = 8080  # Hardcoded port
    print(f"Starting server on port {port}")  # Print statement
    return port
"""

    violations = engine.check_code(code)
    print(f"\n✓ Found {len(violations)} violations:")
    for v in violations:
        print(f"\n   {v.severity}: {v.rule_name}")
        print(f"   Line {v.line_number}: {v.message}")
        print(f"   💡 {v.suggestion}")


def demo_advanced_ast_rules():
    """Demonstrate AST-based custom rules."""
    print("\n" + "=" * 60)
    print("AST-BASED CUSTOM RULES DEMO")
    print("=" * 60)

    import ast

    from pyguard.lib.custom_rules import CustomRuleEngine

    def check_too_many_arguments(tree: ast.AST) -> list:
        """Find functions with too many arguments."""
        lines = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if len(node.args.args) > 5:
                    lines.append(node.lineno)
        return lines

    engine = CustomRuleEngine()

    print("\n📝 Adding AST-based rule...")
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

    print("\n🔍 Checking code with AST rule...")
    violations = engine.check_code(code)

    if violations:
        print(f"\n✓ Found {len(violations)} violations:")
        for v in violations:
            print(f"\n   {v.severity}: {v.rule_name}")
            print(f"   Line {v.line_number}: {v.message}")
            print(f"   💡 {v.suggestion}")
    else:
        print("\n✓ No violations found")


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("PYGUARD ADVANCED INTEGRATIONS DEMO")
    print("=" * 60)
    print("\nThis demo showcases PyGuard's advanced features:")
    print("  • CI/CD Integration")
    print("  • Performance Profiler")
    print("  • Dependency Analyzer")
    print("  • Custom Rules Engine")

    try:
        demo_ci_integration()
        demo_performance_profiler()
        demo_dependency_analyzer()
        demo_custom_rules()
        demo_advanced_ast_rules()

        print("\n" + "=" * 60)
        print("DEMO COMPLETE!")
        print("=" * 60)
        print("\n✨ All features demonstrated successfully!")
        print("\n📚 Learn more:")
        print("   docs/guides/advanced-integrations.md")
        print("   docs/reference/capabilities-reference.md")

    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
