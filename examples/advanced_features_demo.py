#!/usr/bin/env python3
"""
PyGuard Advanced Features Demo

Demonstrates the cutting-edge capabilities that differentiate PyGuard
from other Python security tools:

1. Jupyter Notebook Security Analysis
2. AI-Powered Vulnerability Explanations
3. Educational Fix Recommendations

Run this script to see PyGuard's advanced features in action.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyguard.lib.ai_explainer import AIExplainer, explain
from pyguard.lib.notebook_security import scan_notebook


def print_section(title: str):
    """Print a section header."""


def demo_notebook_analysis():
    """Demonstrate Jupyter notebook security analysis."""
    print_section("🔍 Jupyter Notebook Security Analysis")

    notebook_path = Path(__file__).parent / "notebook_security_demo.ipynb"

    if not notebook_path.exists():
        return

    # Scan the notebook
    issues = scan_notebook(str(notebook_path))

    if not issues:
        return

    # Group by severity
    by_severity = {}
    for issue in issues:
        if issue.severity not in by_severity:
            by_severity[issue.severity] = []
        by_severity[issue.severity].append(issue)

    # Display summary
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(by_severity.get(severity, []))
        if count > 0:
            {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]

    # Show first 5 issues in detail
    for _i, issue in enumerate(issues[:5], 1):
        if issue.cwe_id:
            pass
        if issue.fix_suggestion:
            pass


def demo_ai_explanations():
    """Demonstrate AI-powered vulnerability explanations."""
    print_section(" AI-Powered Vulnerability Explanations")

    explainer = AIExplainer()

    # Demonstrate SQL Injection explanation

    explanation = explainer.explain_vulnerability("SQL_INJECTION")

    if explanation:
        for _line in explanation.how_to_fix.split("\n")[:3]:
            pass

        for _line in explanation.example_vulnerable.split("\n")[:3]:
            pass

        for _line in explanation.example_secure.split("\n")[:3]:
            pass

        for _ref in explanation.references[:2]:
            pass

    # Demonstrate fix explanation

    original = "query = f'SELECT * FROM users WHERE id = {user_id}'"
    fixed = "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))"

    rationale = explainer.explain_fix(original, fixed, "SQL_INJECTION")

    for _line in fixed.split("\n"):
        pass

    for _alt in rationale.alternatives[:2]:
        pass


def demo_educational_mode():
    """Demonstrate educational learning content."""
    print_section("📖 Educational Mode (Learn While You Scan)")

    explainer = AIExplainer()

    # Generate learning content
    content = explainer.generate_learning_content("COMMAND_INJECTION")

    for _obj in content["learning_objectives"]:
        pass

    for _line in content["vulnerable_pattern"].split("\n")[:4]:
        pass

    for _line in content["secure_pattern"].split("\n")[:4]:
        pass

    quiz = content["quiz_question"]

    for i, _option in enumerate(quiz["options"], 1):
        "[OK]" if i - 1 == quiz["correct"] else " "


def demo_beginner_vs_advanced():
    """Demonstrate educational level adjustment."""
    print_section("🎓 Educational Levels (Beginner vs Advanced)")

    # Beginner explanation
    beginner_exp = explain("CODE_INJECTION", "beginner")

    if beginner_exp:
        for _line in beginner_exp.how_to_fix.split("\n")[:2]:
            pass

    # Advanced explanation
    advanced_exp = explain("CODE_INJECTION", "advanced")

    if advanced_exp:
        pass


def main():
    """Run all demonstrations."""

    # Run demonstrations
    demo_notebook_analysis()
    demo_ai_explanations()
    demo_educational_mode()
    demo_beginner_vs_advanced()

    # Summary
    print_section(" Summary: What Makes PyGuard Different")

    features = [
        ("Native Jupyter Notebook Support", "Few tools offer this"),
        ("Cell execution order analysis", "Unique to PyGuard"),
        ("Magic command security checks", "Unique to PyGuard"),
        ("AI-powered explanations", "Educational and actionable"),
        ("Fix rationale generation", "Understand why fixes work"),
        ("Multi-level educational content", "Learn as you secure"),
        ("Interactive learning modules", "Quiz questions included"),
    ]

    for _feature, _note in features:
        pass


if __name__ == "__main__":
    main()
