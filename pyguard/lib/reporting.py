"""
Advanced reporting for PyGuard analysis results.

Provides formatted console output, JSON/HTML reports, and metrics tracking.
Aligned with observability best practices from Google SRE.

References:
- Google SRE | https://sre.google | Medium | Observability and monitoring patterns
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyguard.lib.core import PyGuardLogger


@dataclass
class AnalysisMetrics:
    """Metrics from a PyGuard analysis run."""

    total_files: int
    files_analyzed: int
    files_with_issues: int
    files_fixed: int
    total_issues: int
    security_issues: int
    quality_issues: int
    fixes_applied: int
    analysis_time_seconds: float
    avg_time_per_file_ms: float


class ConsoleReporter:
    """
    Console reporter with formatted output.

    Provides beautiful, human-readable console output with colors and formatting.
    """

    def __init__(self, use_color: bool = True):
        """
        Initialize console reporter.

        Args:
            use_color: Whether to use ANSI color codes
        """
        self.logger = PyGuardLogger()
        self.use_color = use_color

        # ANSI color codes
        self.COLORS = {
            "RED": "\033[91m" if use_color else "",
            "GREEN": "\033[92m" if use_color else "",
            "YELLOW": "\033[93m" if use_color else "",
            "BLUE": "\033[94m" if use_color else "",
            "MAGENTA": "\033[95m" if use_color else "",
            "CYAN": "\033[96m" if use_color else "",
            "BOLD": "\033[1m" if use_color else "",
            "RESET": "\033[0m" if use_color else "",
        }

    def print_header(self, title: str):
        """Print a formatted header."""
        border = "=" * 70
        print(f"\n{self.COLORS['BOLD']}{self.COLORS['CYAN']}{border}{self.COLORS['RESET']}")
        print(f"{self.COLORS['BOLD']}{self.COLORS['CYAN']}{title:^70}{self.COLORS['RESET']}")
        print(f"{self.COLORS['BOLD']}{self.COLORS['CYAN']}{border}{self.COLORS['RESET']}\n")

    def print_section(self, title: str):
        """Print a section header."""
        print(f"\n{self.COLORS['BOLD']}{self.COLORS['BLUE']}▶ {title}{self.COLORS['RESET']}")
        print(f"{self.COLORS['BLUE']}{'-' * 70}{self.COLORS['RESET']}")

    def print_metric(self, label: str, value: Any, color: str = "GREEN"):
        """Print a metric with label and value."""
        color_code = self.COLORS.get(color, "")
        reset = self.COLORS["RESET"]
        print(f"  {label:.<50} {color_code}{value}{reset}")

    def print_summary(self, metrics: AnalysisMetrics):
        """Print analysis summary."""
        self.print_header("PyGuard Analysis Summary")

        # Files section
        self.print_section("Files Processed")
        self.print_metric("Total files", metrics.total_files, "BLUE")
        self.print_metric("Files analyzed", metrics.files_analyzed, "CYAN")
        self.print_metric("Files with issues", metrics.files_with_issues, "YELLOW")
        self.print_metric("Files fixed", metrics.files_fixed, "GREEN")

        # Issues section
        self.print_section("Issues Detected")
        self.print_metric("Total issues", metrics.total_issues, "BLUE")
        self.print_metric("Security issues", metrics.security_issues, "RED")
        self.print_metric("Quality issues", metrics.quality_issues, "YELLOW")
        self.print_metric("Fixes applied", metrics.fixes_applied, "GREEN")

        # Performance section
        self.print_section("Performance")
        self.print_metric("Total analysis time", f"{metrics.analysis_time_seconds:.2f}s", "CYAN")
        self.print_metric("Average time per file", f"{metrics.avg_time_per_file_ms:.2f}ms", "CYAN")

        # Status
        print()
        if metrics.total_issues == 0:
            print(
                f"{self.COLORS['GREEN']}{self.COLORS['BOLD']}✅ No issues found! Code is clean.{self.COLORS['RESET']}"
            )
        elif metrics.fixes_applied > 0:
            print(
                f"{self.COLORS['YELLOW']}{self.COLORS['BOLD']}⚠️  Issues found and {metrics.fixes_applied} fixes applied.{self.COLORS['RESET']}"
            )
        else:
            print(
                f"{self.COLORS['RED']}{self.COLORS['BOLD']}❌ Issues found but not fixed. Run with --fix to apply fixes.{self.COLORS['RESET']}"
            )

        print()

    def print_issue_details(
        self,
        severity: str,
        category: str,
        message: str,
        file_path: str,
        line_number: int,
        fix_suggestion: Optional[str] = None,
    ):
        """Print details of a single issue."""
        severity_colors = {"HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "CYAN"}
        color = severity_colors.get(severity, "RESET")
        color_code = self.COLORS[color]
        reset = self.COLORS["RESET"]

        print(f"\n{color_code}[{severity}] {category}{reset}")
        print(f"  File: {file_path}:{line_number}")
        print(f"  Issue: {message}")
        if fix_suggestion:
            print(f"  {self.COLORS['GREEN']}Fix: {fix_suggestion}{reset}")


class JSONReporter:
    """
    JSON reporter for machine-readable output.

    Generates structured JSON reports suitable for CI/CD integration.
    """

    def __init__(self):
        """Initialize JSON reporter."""
        self.logger = PyGuardLogger()

    def generate_report(
        self, metrics: AnalysisMetrics, issues: List[Dict[str, Any]], fixes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate JSON report.

        Args:
            metrics: Analysis metrics
            issues: List of issues found
            fixes: List of fixes applied

        Returns:
            Report as dictionary
        """
        return {
            "pyguard_version": "0.2.0",
            "generated_at": datetime.now().isoformat(),
            "summary": asdict(metrics),
            "issues": issues,
            "fixes": fixes,
            "status": self._get_status(metrics),
        }

    def save_report(self, report: Dict[str, Any], output_path: Path):
        """
        Save report to JSON file.

        Args:
            report: Report dictionary
            output_path: Path to output file
        """
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            self.logger.success(f"JSON report saved to {output_path}", category="Reporting")
        except Exception as e:
            self.logger.error(f"Failed to save JSON report: {str(e)}", category="Reporting")

    def _get_status(self, metrics: AnalysisMetrics) -> str:
        """Get overall status based on metrics."""
        if metrics.total_issues == 0:
            return "passed"
        elif metrics.security_issues > 0:
            return "failed_security"
        elif metrics.quality_issues > 0:
            return "warning"
        else:
            return "unknown"


class HTMLReporter:
    """
    HTML reporter for visual reports.

    Generates beautiful HTML reports with charts and interactive elements.
    """

    def __init__(self):
        """Initialize HTML reporter."""
        self.logger = PyGuardLogger()

    def generate_report(
        self, metrics: AnalysisMetrics, issues: List[Dict[str, Any]], fixes: List[Dict[str, Any]]
    ) -> str:
        """
        Generate HTML report.

        Args:
            metrics: Analysis metrics
            issues: List of issues found
            fixes: List of fixes applied

        Returns:
            HTML as string
        """
        # Generate issue rows
        issue_rows = ""
        for issue in issues:
            severity_class = f"severity-{issue.get('severity', 'LOW').lower()}"
            issue_rows += f"""
            <tr class="{severity_class}">
                <td>{issue.get('severity', 'UNKNOWN')}</td>
                <td>{issue.get('category', 'Unknown')}</td>
                <td>{issue.get('file', 'N/A')}</td>
                <td>{issue.get('line', 0)}</td>
                <td>{issue.get('message', '')}</td>
            </tr>
            """

        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyGuard Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .metric-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .issues-table {{
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        .severity-high {{ background: #fee; }}
        .severity-medium {{ background: #ffeaa7; }}
        .severity-low {{ background: #e8f4f8; }}
        .status {{
            text-align: center;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            font-size: 1.2em;
            font-weight: bold;
        }}
        .status.passed {{
            background: #d4edda;
            color: #155724;
        }}
        .status.failed {{
            background: #f8d7da;
            color: #721c24;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🐍 PyGuard Analysis Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="metrics">
        <div class="metric-card">
            <h3>Total Files</h3>
            <div class="value">{metrics.total_files}</div>
        </div>
        <div class="metric-card">
            <h3>Issues Found</h3>
            <div class="value">{metrics.total_issues}</div>
        </div>
        <div class="metric-card">
            <h3>Security Issues</h3>
            <div class="value">{metrics.security_issues}</div>
        </div>
        <div class="metric-card">
            <h3>Fixes Applied</h3>
            <div class="value">{metrics.fixes_applied}</div>
        </div>
    </div>
    
    <div class="status {'passed' if metrics.total_issues == 0 else 'failed'}">
        {'✅ No issues found!' if metrics.total_issues == 0 else f'⚠️ {metrics.total_issues} issues detected'}
    </div>
    
    <div class="issues-table">
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {issue_rows if issue_rows else '<tr><td colspan="5" style="text-align:center;">No issues found</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
        """
        return html.strip()

    def save_report(self, html: str, output_path: Path):
        """
        Save report to HTML file.

        Args:
            html: HTML string
            output_path: Path to output file
        """
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

            self.logger.success(f"HTML report saved to {output_path}", category="Reporting")
        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {str(e)}", category="Reporting")
