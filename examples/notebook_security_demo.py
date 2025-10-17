#!/usr/bin/env python3
"""
PyGuard Jupyter Notebook Security Analysis Demo

This script demonstrates how to use PyGuard to scan Jupyter notebooks
for security vulnerabilities, generate SARIF reports, and apply auto-fixes.

Usage:
    python notebook_security_demo.py path/to/notebook.ipynb
    python notebook_security_demo.py --scan-only path/to/notebook.ipynb
    python notebook_security_demo.py --fix path/to/notebook.ipynb
"""

import json
import sys
from pathlib import Path

from pyguard.lib.notebook_security import (
    scan_notebook,
    generate_notebook_sarif,
    NotebookFixer,
)


def print_issues(issues):
    """Print security issues in a readable format."""
    if not issues:
        print("✓ No security issues found!")
        return
    
    print(f"\n{'='*80}")
    print(f"Found {len(issues)} security issues:")
    print(f"{'='*80}\n")
    
    # Group by severity
    by_severity = {}
    for issue in issues:
        if issue.severity not in by_severity:
            by_severity[issue.severity] = []
        by_severity[issue.severity].append(issue)
    
    # Print by severity (CRITICAL first)
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity not in by_severity:
            continue
        
        severity_issues = by_severity[severity]
        print(f"\n{severity} Issues ({len(severity_issues)}):")
        print("-" * 80)
        
        for issue in severity_issues:
            print(f"\n  • {issue.message}")
            print(f"    Location: Cell {issue.cell_index}, Line {issue.line_number or 'N/A'}")
            print(f"    Category: {issue.category}")
            print(f"    Confidence: {issue.confidence:.0%}")
            
            if issue.cwe_id:
                print(f"    {issue.cwe_id}")
            
            if issue.auto_fixable:
                print("    ✓ Auto-fix available")
            
            if issue.fix_suggestion:
                print(f"    Fix: {issue.fix_suggestion[:100]}...")
            
            if issue.code_snippet:
                print(f"    Code: {issue.code_snippet[:60]}...")


def main():
    """Main demo function."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    notebook_path = sys.argv[-1]
    scan_only = "--scan-only" in sys.argv
    apply_fix = "--fix" in sys.argv
    
    if not Path(notebook_path).exists():
        print(f"Error: Notebook not found: {notebook_path}")
        sys.exit(1)
    
    print(f"Analyzing notebook: {notebook_path}")
    print("=" * 80)
    
    # Step 1: Scan the notebook
    issues = scan_notebook(notebook_path)
    
    # Print findings
    print_issues(issues)
    
    if scan_only:
        return
    
    # Step 2: Generate SARIF report
    print(f"\n{'='*80}")
    print("Generating SARIF 2.1.0 report...")
    print(f"{'='*80}")
    
    sarif = generate_notebook_sarif(notebook_path, issues)
    sarif_path = Path(notebook_path).with_suffix('.sarif')
    
    with open(sarif_path, 'w') as f:
        json.dump(sarif, f, indent=2)
    
    print(f"\n✓ SARIF report saved to: {sarif_path}")
    print(f"  - Total rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}")
    print(f"  - Total findings: {len(sarif['runs'][0]['results'])}")
    print(f"  - CRITICAL: {sarif['runs'][0]['properties']['critical_issues']}")
    print(f"  - HIGH: {sarif['runs'][0]['properties']['high_issues']}")
    print(f"  - MEDIUM: {sarif['runs'][0]['properties']['medium_issues']}")
    
    # Step 3: Apply auto-fixes if requested
    if apply_fix:
        print(f"\n{'='*80}")
        print("Applying auto-fixes...")
        print(f"{'='*80}")
        
        fixable_issues = [i for i in issues if i.auto_fixable]
        
        if not fixable_issues:
            print("\nNo auto-fixable issues found.")
            return
        
        print(f"\nFound {len(fixable_issues)} auto-fixable issues:")
        for issue in fixable_issues:
            print(f"  - {issue.message}")
        
        fixer = NotebookFixer()
        success, fixes = fixer.fix_notebook(Path(notebook_path), fixable_issues)
        
        if success:
            print(f"\n✓ Applied {len(fixes)} fixes:")
            for fix in fixes:
                print(f"  - {fix}")
            print(f"\nNotebook updated: {notebook_path}")
        else:
            print("\nNo fixes were applied.")
    else:
        auto_fixable_count = sum(1 for i in issues if i.auto_fixable)
        if auto_fixable_count > 0:
            print(f"\n💡 Tip: Run with --fix to automatically fix {auto_fixable_count} issues")


if __name__ == "__main__":
    main()
