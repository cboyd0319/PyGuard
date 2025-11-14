#!/usr/bin/env python3
"""
False Positive Rate Benchmarking Tool

This script benchmarks PyGuard against popular open-source Python projects
to establish a baseline false positive rate and identify common FP patterns.

Target: <1.5% false positive rate (v0.7.0 goal)
Stretch: <1% false positive rate (v1.0.0 goal)

Usage:
    python tools/benchmark_false_positives.py --clone
    python tools/benchmark_false_positives.py --scan
    python tools/benchmark_false_positives.py --review
    python tools/benchmark_false_positives.py --report
    python tools/benchmark_false_positives.py --all  # Run all steps
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# Add parent directory to path to import pyguard
sys.path.insert(0, str(Path(__file__).parent.parent))

# Benchmark projects - popular, well-maintained Python projects
BENCHMARK_PROJECTS = [
    {
        "name": "django",
        "repo": "https://github.com/django/django.git",
        "description": "Web framework",
        "stars": "75K+",
        "files": "~2,500 .py files"
    },
    {
        "name": "flask",
        "repo": "https://github.com/pallets/flask.git",
        "description": "Micro web framework",
        "stars": "65K+",
        "files": "~100 .py files"
    },
    {
        "name": "fastapi",
        "repo": "https://github.com/tiangolo/fastapi.git",
        "description": "Modern API framework",
        "stars": "70K+",
        "files": "~200 .py files"
    },
    {
        "name": "requests",
        "repo": "https://github.com/psf/requests.git",
        "description": "HTTP library",
        "stars": "50K+",
        "files": "~30 .py files"
    },
    {
        "name": "numpy",
        "repo": "https://github.com/numpy/numpy.git",
        "description": "Scientific computing",
        "stars": "25K+",
        "files": "~1,000 .py files"
    },
    {
        "name": "pandas",
        "repo": "https://github.com/pandas-dev/pandas.git",
        "description": "Data analysis",
        "stars": "40K+",
        "files": "~1,500 .py files"
    },
    {
        "name": "scikit-learn",
        "repo": "https://github.com/scikit-learn/scikit-learn.git",
        "description": "Machine learning",
        "stars": "55K+",
        "files": "~1,000 .py files"
    },
    {
        "name": "pytest",
        "repo": "https://github.com/pytest-dev/pytest.git",
        "description": "Testing framework",
        "stars": "10K+",
        "files": "~300 .py files"
    },
    {
        "name": "black",
        "repo": "https://github.com/psf/black.git",
        "description": "Code formatter",
        "stars": "35K+",
        "files": "~100 .py files"
    },
    {
        "name": "httpx",
        "repo": "https://github.com/encode/httpx.git",
        "description": "Async HTTP client",
        "stars": "12K+",
        "files": "~100 .py files"
    },
]


class FPBenchmark:
    """False Positive Benchmarking Tool"""

    def __init__(self, workspace_dir: str = "benchmark_workspace"):
        self.workspace = Path(workspace_dir)
        self.workspace.mkdir(exist_ok=True)
        self.results_dir = self.workspace / "results"
        self.results_dir.mkdir(exist_ok=True)
        self.repos_dir = self.workspace / "repos"
        self.repos_dir.mkdir(exist_ok=True)
        self.review_dir = self.workspace / "review"
        self.review_dir.mkdir(exist_ok=True)

    def clone_projects(self, shallow: bool = True) -> None:
        """Clone benchmark projects"""
        print("=" * 80)
        print("CLONING BENCHMARK PROJECTS")
        print("=" * 80)
        print()

        for project in BENCHMARK_PROJECTS:
            name = project["name"]
            repo = project["repo"]
            target = self.repos_dir / name

            if target.exists():
                print(f"[SKIP] {name} - already cloned")
                continue

            print(f"[CLONE] {name} - {project['description']}")
            print(f"  Repo: {repo}")
            print(f"  Stars: {project['stars']}")
            print(f"  Files: {project['files']}")

            cmd = ["git", "clone"]
            if shallow:
                cmd.extend(["--depth", "1"])
            cmd.extend([repo, str(target)])

            try:
                subprocess.run(cmd, check=True, capture_output=True)
                print(f"  [OK] Cloned to {target}")
            except subprocess.CalledProcessError as e:
                print(f"  [ERROR] Failed to clone: {e}")
                continue

            print()

        print(f"✅ All projects cloned to {self.repos_dir}")
        print()

    def scan_projects(self, severity: str = "MEDIUM") -> Dict[str, Dict]:
        """Scan all projects with PyGuard"""
        print("=" * 80)
        print("SCANNING PROJECTS WITH PYGUARD")
        print("=" * 80)
        print()
        print(f"Severity threshold: {severity}")
        print()

        results = {}

        for project in BENCHMARK_PROJECTS:
            name = project["name"]
            repo_path = self.repos_dir / name

            if not repo_path.exists():
                print(f"[SKIP] {name} - not cloned")
                continue

            print(f"[SCAN] {name}")
            print(f"  Path: {repo_path}")

            # Run PyGuard scan
            result_file = self.results_dir / f"{name}_scan.json"
            cmd = [
                sys.executable,
                "-m", "pyguard.cli",
                str(repo_path),
                "--scan-only",
                "--severity", severity,
                "--output-json", str(result_file),
                "--no-color"
            ]

            try:
                start_time = datetime.now()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                elapsed = (datetime.now() - start_time).total_seconds()

                # Load scan results
                if result_file.exists():
                    with open(result_file, 'r') as f:
                        scan_data = json.load(f)

                    findings_count = len(scan_data.get('findings', []))
                    results[name] = {
                        "project": project,
                        "scan_file": str(result_file),
                        "findings_count": findings_count,
                        "elapsed_seconds": elapsed,
                        "exit_code": result.returncode,
                        "success": result.returncode in [0, 1]  # 0=no issues, 1=issues found
                    }

                    print(f"  [OK] Found {findings_count} potential issues ({elapsed:.1f}s)")
                else:
                    print(f"  [ERROR] No results file generated")
                    results[name] = {
                        "project": project,
                        "error": "No results file",
                        "exit_code": result.returncode
                    }

            except subprocess.TimeoutExpired:
                print(f"  [TIMEOUT] Scan exceeded 10 minutes")
                results[name] = {
                    "project": project,
                    "error": "Timeout"
                }
            except Exception as e:
                print(f"  [ERROR] {e}")
                results[name] = {
                    "project": project,
                    "error": str(e)
                }

            print()

        # Save summary
        summary_file = self.results_dir / "scan_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"✅ Scan complete. Summary: {summary_file}")
        print()

        return results

    def create_review_templates(self) -> None:
        """Create review templates for manual FP classification"""
        print("=" * 80)
        print("CREATING REVIEW TEMPLATES")
        print("=" * 80)
        print()

        for project in BENCHMARK_PROJECTS:
            name = project["name"]
            scan_file = self.results_dir / f"{name}_scan.json"

            if not scan_file.exists():
                continue

            print(f"[TEMPLATE] {name}")

            with open(scan_file, 'r') as f:
                scan_data = json.load(f)

            findings = scan_data.get('findings', [])

            # Create review file
            review_file = self.review_dir / f"{name}_review.jsonl"
            with open(review_file, 'w') as f:
                for i, finding in enumerate(findings):
                    review_entry = {
                        "project": name,
                        "finding_id": i,
                        "rule_id": finding.get('rule_id'),
                        "severity": finding.get('severity'),
                        "file": finding.get('file'),
                        "line": finding.get('line'),
                        "message": finding.get('message'),
                        "code_snippet": finding.get('code', ''),
                        # Manual review fields (to be filled by reviewer)
                        "is_false_positive": None,  # true/false/unsure
                        "reason": "",  # Why is it FP?
                        "pattern": "",  # Common FP pattern?
                        "suggestion": "",  # How to fix the rule?
                        "reviewed_by": "",  # Reviewer name
                        "reviewed_at": ""  # Review timestamp
                    }
                    f.write(json.dumps(review_entry) + '\n')

            print(f"  [OK] Created {review_file} ({len(findings)} findings)")

        print()
        print(f"✅ Review templates created in {self.review_dir}")
        print()
        print("NEXT STEPS:")
        print("1. Open each *_review.jsonl file")
        print("2. For each finding, set:")
        print("   - is_false_positive: true/false")
        print("   - reason: Why it's FP (if applicable)")
        print("   - pattern: Common FP pattern name (if applicable)")
        print("3. Save the file")
        print("4. Run: python tools/benchmark_false_positives.py --report")
        print()

    def generate_report(self) -> Tuple[float, Dict]:
        """Generate false positive rate report from reviewed findings"""
        print("=" * 80)
        print("FALSE POSITIVE RATE REPORT")
        print("=" * 80)
        print()

        total_findings = 0
        total_false_positives = 0
        total_true_positives = 0
        total_unsure = 0
        total_unreviewed = 0

        fp_by_rule = {}
        fp_by_severity = {}
        fp_by_project = {}
        fp_patterns = {}

        for project in BENCHMARK_PROJECTS:
            name = project["name"]
            review_file = self.review_dir / f"{name}_review.jsonl"

            if not review_file.exists():
                continue

            project_findings = 0
            project_fps = 0

            with open(review_file, 'r') as f:
                for line in f:
                    entry = json.loads(line)
                    total_findings += 1
                    project_findings += 1

                    is_fp = entry.get('is_false_positive')
                    rule_id = entry.get('rule_id', 'unknown')
                    severity = entry.get('severity', 'unknown')
                    pattern = entry.get('pattern', '')

                    if is_fp is True:
                        total_false_positives += 1
                        project_fps += 1

                        # Track by rule
                        fp_by_rule[rule_id] = fp_by_rule.get(rule_id, 0) + 1

                        # Track by severity
                        fp_by_severity[severity] = fp_by_severity.get(severity, 0) + 1

                        # Track patterns
                        if pattern:
                            fp_patterns[pattern] = fp_patterns.get(pattern, 0) + 1

                    elif is_fp is False:
                        total_true_positives += 1
                    elif is_fp == "unsure":
                        total_unsure += 1
                    else:
                        total_unreviewed += 1

            if project_findings > 0:
                project_fp_rate = (project_fps / project_findings) * 100
                fp_by_project[name] = {
                    "findings": project_findings,
                    "false_positives": project_fps,
                    "fp_rate": project_fp_rate
                }

        # Calculate overall FP rate
        reviewed = total_findings - total_unreviewed
        if reviewed > 0:
            fp_rate = (total_false_positives / reviewed) * 100
        else:
            fp_rate = 0.0

        # Print report
        print(f"Total Findings: {total_findings}")
        print(f"Reviewed: {reviewed} ({(reviewed/total_findings)*100:.1f}%)")
        print(f"Unreviewed: {total_unreviewed}")
        print()

        print("CLASSIFICATION:")
        print(f"  True Positives:  {total_true_positives:4d} ({(total_true_positives/reviewed)*100:.1f}%)")
        print(f"  False Positives: {total_false_positives:4d} ({fp_rate:.2f}%)")
        print(f"  Unsure:          {total_unsure:4d} ({(total_unsure/reviewed)*100:.1f}%)")
        print()

        print("=" * 80)
        print(f"FALSE POSITIVE RATE: {fp_rate:.2f}%")
        print("=" * 80)

        # Goal assessment
        if fp_rate < 1.0:
            status = "✅ EXCELLENT - Below v1.0.0 stretch goal (<1%)"
        elif fp_rate < 1.5:
            status = "✅ GOOD - Below v0.7.0 target (<1.5%)"
        elif fp_rate < 2.0:
            status = "⚠️ ACCEPTABLE - Near target (1.5-2%)"
        else:
            status = "❌ NEEDS IMPROVEMENT - Above target (>2%)"

        print(status)
        print()

        # Top FP rules
        if fp_by_rule:
            print("TOP FALSE POSITIVE RULES:")
            sorted_rules = sorted(fp_by_rule.items(), key=lambda x: x[1], reverse=True)
            for rule, count in sorted_rules[:10]:
                percentage = (count / total_false_positives) * 100
                print(f"  {rule:40s} {count:4d} ({percentage:5.1f}%)")
            print()

        # FP by severity
        if fp_by_severity:
            print("FALSE POSITIVES BY SEVERITY:")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = fp_by_severity.get(severity, 0)
                if count > 0:
                    percentage = (count / total_false_positives) * 100
                    print(f"  {severity:10s} {count:4d} ({percentage:5.1f}%)")
            print()

        # FP by project
        if fp_by_project:
            print("FALSE POSITIVE RATE BY PROJECT:")
            sorted_projects = sorted(fp_by_project.items(), key=lambda x: x[1]['fp_rate'], reverse=True)
            for name, stats in sorted_projects:
                print(f"  {name:20s} {stats['fp_rate']:5.2f}% ({stats['false_positives']}/{stats['findings']})")
            print()

        # Common patterns
        if fp_patterns:
            print("COMMON FALSE POSITIVE PATTERNS:")
            sorted_patterns = sorted(fp_patterns.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns:
                percentage = (count / total_false_positives) * 100
                print(f"  {pattern:40s} {count:4d} ({percentage:5.1f}%)")
            print()

        # Save full report
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_findings": total_findings,
                "reviewed": reviewed,
                "true_positives": total_true_positives,
                "false_positives": total_false_positives,
                "unsure": total_unsure,
                "unreviewed": total_unreviewed,
                "fp_rate": fp_rate,
                "status": status
            },
            "fp_by_rule": fp_by_rule,
            "fp_by_severity": fp_by_severity,
            "fp_by_project": fp_by_project,
            "fp_patterns": fp_patterns
        }

        report_file = self.results_dir / f"fp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"📊 Full report saved to: {report_file}")
        print()

        return fp_rate, report_data


def main():
    parser = argparse.ArgumentParser(description="PyGuard False Positive Benchmarking")
    parser.add_argument("--clone", action="store_true", help="Clone benchmark projects")
    parser.add_argument("--scan", action="store_true", help="Scan projects with PyGuard")
    parser.add_argument("--review", action="store_true", help="Create review templates")
    parser.add_argument("--report", action="store_true", help="Generate FP rate report")
    parser.add_argument("--all", action="store_true", help="Run all steps (clone, scan, review)")
    parser.add_argument("--workspace", default="benchmark_workspace", help="Workspace directory")
    parser.add_argument("--severity", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum severity to scan")
    parser.add_argument("--shallow", action="store_true", default=True, help="Shallow clone (default: True)")

    args = parser.parse_args()

    if not any([args.clone, args.scan, args.review, args.report, args.all]):
        parser.print_help()
        return 1

    benchmark = FPBenchmark(workspace_dir=args.workspace)

    if args.all or args.clone:
        benchmark.clone_projects(shallow=args.shallow)

    if args.all or args.scan:
        benchmark.scan_projects(severity=args.severity)

    if args.all or args.review:
        benchmark.create_review_templates()

    if args.report:
        fp_rate, report = benchmark.generate_report()

    return 0


if __name__ == "__main__":
    sys.exit(main())
