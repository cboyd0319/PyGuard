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
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def demo_notebook_analysis():
    """Demonstrate Jupyter notebook security analysis."""
    print_section("🔍 Jupyter Notebook Security Analysis")

    notebook_path = Path(__file__).parent / "notebook_security_demo.ipynb"

    if not notebook_path.exists():
        print(f"[WARN]  Demo notebook not found: {notebook_path}")
        return

    print(f"Analyzing: {notebook_path.name}\n")

    # Scan the notebook
    issues = scan_notebook(str(notebook_path))

    if not issues:
        print("[OK] No security issues found!")
        return

    print(f"Found {len(issues)} security issues:\n")

    # Group by severity
    by_severity = {}
    for issue in issues:
        if issue.severity not in by_severity:
            by_severity[issue.severity] = []
        by_severity[issue.severity].append(issue)

    # Display summary
    print("Summary by Severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(by_severity.get(severity, []))
        if count > 0:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
            print(f"  {emoji} {severity}: {count}")

    # Show first 5 issues in detail
    print("\nDetailed View (First 5 Issues):")
    for i, issue in enumerate(issues[:5], 1):
        print(f"\n{i}. {issue.severity}: {issue.category}")
        print(f"   📍 Cell {issue.cell_index}, Line {issue.line_number}")
        print(f"   📝 {issue.message}")
        if issue.cwe_id:
            print(f"   🏷️  {issue.cwe_id}")
        if issue.fix_suggestion:
            print(f"   💡 Fix: {issue.fix_suggestion[:80]}...")

    print("\n✨ PyGuard is one of the few tools with native Jupyter notebook support!")


def demo_ai_explanations():
    """Demonstrate AI-powered vulnerability explanations."""
    print_section(" AI-Powered Vulnerability Explanations")

    explainer = AIExplainer()

    # Demonstrate SQL Injection explanation
    print("Example 1: SQL Injection (Comprehensive Explanation)\n")

    explanation = explainer.explain_vulnerability("SQL_INJECTION")

    if explanation:
        print(f" {explanation.vulnerability_name} ({explanation.severity})")
        print(f"\n🔍 What is it?")
        print(f"   {explanation.description[:150]}...")

        print(f"\n[WARN]  Why is it dangerous?")
        print(f"   {explanation.why_dangerous[:150]}...")

        print(f"\n🛠️  How to fix:")
        for line in explanation.how_to_fix.split("\n")[:3]:
            print(f"   {line}")

        print(f"\n💻 Vulnerable Code:")
        for line in explanation.example_vulnerable.split("\n")[:3]:
            print(f"   {line}")

        print(f"\n[OK] Secure Code:")
        for line in explanation.example_secure.split("\n")[:3]:
            print(f"   {line}")

        print(f"\n📖 Learn more:")
        for ref in explanation.references[:2]:
            print(f"   • {ref}")

    # Demonstrate fix explanation
    print("\n" + "-" * 80 + "\n")
    print("Example 2: Fix Rationale (Why this specific fix?)\n")

    original = "query = f'SELECT * FROM users WHERE id = {user_id}'"
    fixed = "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))"

    rationale = explainer.explain_fix(original, fixed, "SQL_INJECTION")

    print(f"🔴 Original Code:")
    print(f"   {original}")

    print(f"\n[OK] Fixed Code:")
    for line in fixed.split("\n"):
        print(f"   {line}")

    print(f"\n💡 Why this fix?")
    print(f"   {rationale.why_this_fix}")

    print(f"\n🔄 Alternatives:")
    for alt in rationale.alternatives[:2]:
        print(f"   • {alt}")

    print(f"\n🛡️  Security Impact:")
    print(f"   {rationale.security_impact}")

    print(f"\n⚡ Performance Impact:")
    print(f"   {rationale.performance_impact}")


def demo_educational_mode():
    """Demonstrate educational learning content."""
    print_section("📖 Educational Mode (Learn While You Scan)")

    explainer = AIExplainer()

    # Generate learning content
    content = explainer.generate_learning_content("COMMAND_INJECTION")

    print(f" Learning Module: {content['title']}\n")

    print(f" Risk Level: {content['risk_level']}\n")

    print(f" Learning Objectives:")
    for obj in content["learning_objectives"]:
        print(f"   • {obj}")

    print(f"\n💻 Vulnerable Pattern:")
    for line in content["vulnerable_pattern"].split("\n")[:4]:
        print(f"   {line}")

    print(f"\n[OK] Secure Pattern:")
    for line in content["secure_pattern"].split("\n")[:4]:
        print(f"   {line}")

    print(f"\n❓ Quiz Question:")
    quiz = content["quiz_question"]
    print(f"   {quiz['question']}\n")

    for i, option in enumerate(quiz["options"], 1):
        marker = "[OK]" if i - 1 == quiz["correct"] else " "
        print(f"   {marker} {i}. {option}")

    print(f"\n💡 Explanation: {quiz['explanation']}")


def demo_beginner_vs_advanced():
    """Demonstrate educational level adjustment."""
    print_section("🎓 Educational Levels (Beginner vs Advanced)")

    # Beginner explanation
    print("Beginner Level (Simplified):\n")
    beginner_exp = explain("CODE_INJECTION", "beginner")

    if beginner_exp:
        print(f" {beginner_exp.vulnerability_name}")
        print(f"\n🔍 Description (Simplified):")
        print(f"   {beginner_exp.description[:150]}...")

        print(f"\n🛠️  How to fix:")
        for line in beginner_exp.how_to_fix.split("\n")[:2]:
            print(f"   {line}")

    # Advanced explanation
    print("\n" + "-" * 80 + "\n")
    print("Advanced Level (Technical):\n")
    advanced_exp = explain("CODE_INJECTION", "advanced")

    if advanced_exp:
        print(f" {advanced_exp.vulnerability_name}")
        print(f"\n🔍 How to exploit:")
        print(f"   {advanced_exp.how_to_exploit[:150]}...")

        print(f"\n🏷️  Technical IDs:")
        print(f"   • CWE: {advanced_exp.cwe_id}")
        print(f"   • OWASP: {advanced_exp.owasp_id}")


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 80)
    print(" PyGuard Advanced Features Demo")
    print(" Cutting-edge capabilities that differentiate PyGuard")
    print("=" * 80)

    # Run demonstrations
    demo_notebook_analysis()
    demo_ai_explanations()
    demo_educational_mode()
    demo_beginner_vs_advanced()

    # Summary
    print_section(" Summary: What Makes PyGuard Different")

    print("✨ Unique Features:\n")

    features = [
        ("Native Jupyter Notebook Support", "Few tools offer this"),
        ("Cell execution order analysis", "Unique to PyGuard"),
        ("Magic command security checks", "Unique to PyGuard"),
        ("AI-powered explanations", "Educational and actionable"),
        ("Fix rationale generation", "Understand why fixes work"),
        ("Multi-level educational content", "Learn as you secure"),
        ("Interactive learning modules", "Quiz questions included"),
    ]

    for feature, note in features:
        print(f"   [OK] {feature}")
        print(f"     → {note}\n")

    print(" These features make PyGuard ideal for:")
    print("   • Data Scientists using Jupyter notebooks")
    print("   • Development teams wanting educational security tools")
    print("   • Security teams teaching secure coding practices")
    print("   • Organizations with notebook-heavy workflows\n")

    print(" Learn more: https://github.com/cboyd0319/PyGuard")
    print()


if __name__ == "__main__":
    main()
