#!/usr/bin/env python3
"""
Helper script to add suppression comments to PyGuard false positives.

This script identifies common false positive patterns and adds appropriate
suppression comments. It focuses on:
1. String literal checks (pattern detection code)
2. Method/attribute name comparisons  
3. AST inspection code

Usage:
    python scripts/add_suppressions.py [--dry-run] [--file FILE]
    
Options:
    --dry-run    Show what would be changed without modifying files
    --file FILE  Only process specific file
"""

import argparse
import json
import re
from pathlib import Path
from typing import List, Dict, Set

# Patterns that indicate code is doing pattern detection, not actual operations
SAFE_PATTERNS = [
    r'in code\b',
    r'in func_name\b', 
    r'in method_name\b',
    r'== ["\']__\w+__["\']',  # Dunder method checks
    r'kw\.arg ==',
    r'item\.name ==',
    r'node\.name ==',
    r'\.attr ==',
    r'if ["\'].*["\'] in \w+:',  # String literal in variable check
]

def is_pattern_detection_code(line: str) -> bool:
    """Check if line is pattern detection code vs actual vulnerable code."""
    return any(re.search(pattern, line) for pattern in SAFE_PATTERNS)

def load_sarif_issues(sarif_path: Path) -> Dict[str, List[Dict]]:
    """Load issues from SARIF file grouped by file."""
    with open(sarif_path) as f:
        data = json.load(f)
    
    results = data['runs'][0]['results']
    
    # Group by file
    file_issues = {}
    for result in results:
        if not result['ruleId'].startswith('PY/CWE-'):
            continue  # Only process security false positives
            
        location = result['locations'][0]['physicalLocation']
        file_path = location['artifactLocation']['uri']
        line_num = location['region']['startLine']
        rule_id = result['ruleId'].split('/')[-1]
        
        if file_path not in file_issues:
            file_issues[file_path] = []
        file_issues[file_path].append({
            'line': line_num,
            'rule': rule_id,
        })
    
    return file_issues

def add_suppressions(
    file_path: Path,
    issues: List[Dict],
    dry_run: bool = False
) -> int:
    """
    Add suppression comments to a file.
    
    Returns number of suppressions added.
    """
    if not file_path.exists():
        return 0
        
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    modifications = 0
    # Process in reverse order to maintain line numbers
    for issue in sorted(issues, key=lambda x: x['line'], reverse=True):
        line_num = issue['line']
        rule_id = issue['rule']
        
        if line_num > len(lines):
            continue
            
        line = lines[line_num - 1]
        
        # Skip if already has suppression
        if '# pyguard: disable' in line or '# noqa' in line:
            continue
            
        # Check if this is pattern detection code
        if not is_pattern_detection_code(line):
            continue  # Only suppress obvious false positives
            
        # Add suppression
        stripped = line.rstrip('\n')
        comment = f"  # pyguard: disable={rule_id}  # Pattern detection, not vulnerable code"
        new_line = f"{stripped}{comment}\n"
        lines[line_num - 1] = new_line
        modifications += 1
        
        if dry_run:
            print(f"  Line {line_num}: Would add suppression for {rule_id}")
            print(f"    {stripped}")
    
    if modifications > 0 and not dry_run:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    
    return modifications

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true',
                       help='Show changes without modifying files')
    parser.add_argument('--file', type=Path,
                       help='Only process specific file')
    args = parser.parse_args()
    
    # Find SARIF file
    sarif_path = Path('pyguard-report.sarif')
    if not sarif_path.exists():
        print("Error: pyguard-report.sarif not found")
        print("Run: pyguard pyguard/ --scan-only --no-backup --sarif --no-html")
        return 1
    
    # Load issues
    file_issues = load_sarif_issues(sarif_path)
    
    # Filter to specific file if requested
    if args.file:
        file_issues = {str(args.file): file_issues.get(str(args.file), [])}
    
    # Process files
    total_modifications = 0
    for file_path_str, issues in file_issues.items():
        file_path = Path(file_path_str)
        
        if not file_path.exists():
            continue
            
        if args.dry_run:
            print(f"\nProcessing {file_path}...")
        
        modifications = add_suppressions(file_path, issues, args.dry_run)
        total_modifications += modifications
        
        if modifications > 0 and not args.dry_run:
            print(f"  {file_path}: Added {modifications} suppressions")
    
    # Summary
    print(f"\n{'Would add' if args.dry_run else 'Added'} {total_modifications} suppressions")
    
    if total_modifications > 0:
        print("\nNext steps:")
        print("1. Review the changes: git diff")
        print("2. Re-run PyGuard: pyguard pyguard/ --scan-only")
        print("3. Commit if satisfied: git add . && git commit -m 'Add suppressions for false positives'")
    
    return 0

if __name__ == '__main__':
    exit(main())
