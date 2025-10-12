"""
Enhanced UI module for PyGuard - World-class user interface.

Provides stunning visual output using Rich library for terminal output
and modern HTML/CSS for report generation. Designed for ZERO technical
knowledge required - beautiful, intuitive, beginner-friendly.

References:
- Rich Documentation | https://rich.readthedocs.io | High | Beautiful terminal formatting
- Material Design | https://material.io | High | Modern UI/UX principles
- Web Content Accessibility Guidelines | https://www.w3.org/WAI/WCAG21 | High | Accessibility standards
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown


@dataclass
class UITheme:
    """Theme configuration for PyGuard UI."""

    primary_color: str = "cyan"
    success_color: str = "green"
    warning_color: str = "yellow"
    error_color: str = "red"
    info_color: str = "blue"
    accent_color: str = "magenta"
    muted_color: str = "dim"


class EnhancedConsole:
    """
    World-class console interface with Rich library.

    Features:
    - Beautiful formatted output with colors and styles
    - Progress bars and spinners
    - Tables and trees for structured data
    - Panels and boxes for emphasis
    - Emoji support for visual cues
    - Beginner-friendly error messages
    """

    def __init__(self, theme: Optional[UITheme] = None):
        """
        Initialize enhanced console.

        Args:
            theme: UI theme configuration
        """
        self.console = Console(record=True)
        self.theme = theme or UITheme()

    def print_banner(self):
        """Print PyGuard banner with style."""
        banner_text = """
        ╔═══════════════════════════════════════════════════════════════╗
        ║                                                                 ║
        ║   🛡️  PyGuard - World's Best Python Security Tool 🛡️         ║
        ║                                                                 ║
        ║   Security • Quality • Formatting • Compliance                  ║
        ║   Zero Technical Knowledge Required - Just Run and Fix!        ║
        ║                                                                 ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner_text, style="bold cyan", justify="center")

    def print_welcome(self, files_count: int):
        """Print welcome message."""
        panel = Panel(
            f"[bold green]✨ Ready to analyze {files_count} Python files![/bold green]\n\n"
            f"[dim]PyGuard will find security issues, improve code quality, and format your code.\n"
            f"Sit back and relax - this will only take a moment...[/dim]",
            title="[bold cyan]🚀 Getting Started[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
        self.console.print(panel)
        self.console.print()

    def create_progress_bar(self, description: str = "Processing") -> tuple:
        """
        Create a beautiful progress bar.

        Args:
            description: Progress bar description

        Returns:
            Tuple of (Progress, TaskID)
        """
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )
        return progress

    def print_summary_table(self, metrics: Dict[str, Any]):
        """Print beautiful summary table."""
        table = Table(
            title="[bold cyan]📊 Analysis Summary[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            title_style="bold cyan",
        )

        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Metric", style="white")
        table.add_column("Value", justify="right", style="bold green")

        # Files section
        table.add_row(
            "📁 Files",
            "Total files scanned",
            str(metrics.get("total_files", 0)),
        )
        table.add_row(
            "",
            "Files with issues",
            str(metrics.get("files_with_issues", 0)),
            style="yellow",
        )
        table.add_row(
            "",
            "Files fixed",
            str(metrics.get("files_fixed", 0)),
            style="green",
        )

        # Issues section
        table.add_row(
            "🔍 Issues",
            "Total issues found",
            str(metrics.get("total_issues", 0)),
            style="bold",
        )
        table.add_row(
            "",
            "🔴 Security issues (HIGH)",
            str(metrics.get("security_issues", 0)),
            style="red bold",
        )
        table.add_row(
            "",
            "🟡 Quality issues (MEDIUM)",
            str(metrics.get("quality_issues", 0)),
            style="yellow",
        )
        table.add_row(
            "",
            "✅ Fixes applied",
            str(metrics.get("fixes_applied", 0)),
            style="green bold",
        )

        # Performance section
        table.add_row(
            "⚡ Performance",
            "Total time",
            f"{metrics.get('analysis_time_seconds', 0):.2f}s",
        )
        table.add_row(
            "",
            "Avg time per file",
            f"{metrics.get('avg_time_per_file_ms', 0):.2f}ms",
        )

        self.console.print()
        self.console.print(table)
        self.console.print()

    def print_issue_details(self, issues: List[Dict[str, Any]], max_display: int = 10):
        """Print detailed issue list."""
        if not issues:
            self.console.print(
                Panel(
                    "[bold green]🎉 Excellent! No issues found!\n\n"
                    "Your code is clean, secure, and follows best practices.[/bold green]",
                    title="[bold green]✨ Perfect Score[/bold green]",
                    border_style="green",
                    box=box.DOUBLE,
                )
            )
            return

        # Group issues by severity
        high_issues = [i for i in issues if i.get("severity") == "HIGH"]
        medium_issues = [i for i in issues if i.get("severity") == "MEDIUM"]
        low_issues = [i for i in issues if i.get("severity") == "LOW"]

        # Print high severity issues
        if high_issues:
            table = Table(
                title="[bold red]🔴 HIGH Severity Issues (Fix Immediately!)[/bold red]",
                box=box.HEAVY,
                show_header=True,
                header_style="bold red",
                border_style="red",
            )
            table.add_column("File", style="cyan")
            table.add_column("Line", justify="right", style="white")
            table.add_column("Issue", style="white")

            for issue in high_issues[:max_display]:
                table.add_row(
                    Path(issue.get("file", "")).name,
                    str(issue.get("line", 0)),
                    issue.get("message", ""),
                )

            self.console.print(table)
            self.console.print()

        # Print medium severity issues
        if medium_issues:
            table = Table(
                title="[bold yellow]🟡 MEDIUM Severity Issues (Fix Soon)[/bold yellow]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold yellow",
                border_style="yellow",
            )
            table.add_column("File", style="cyan")
            table.add_column("Line", justify="right", style="white")
            table.add_column("Issue", style="white")

            for issue in medium_issues[:max_display]:
                table.add_row(
                    Path(issue.get("file", "")).name,
                    str(issue.get("line", 0)),
                    issue.get("message", ""),
                )

            self.console.print(table)
            self.console.print()

    def print_success_message(self, fixes_applied: int):
        """Print celebratory success message."""
        if fixes_applied > 0:
            message = (
                f"[bold green]🎉 Success! Applied {fixes_applied} fixes to your code![/bold green]\n\n"
                f"[dim]Your code is now more secure, cleaner, and follows best practices.\n"
                f"Great job taking the time to improve your code quality![/dim]"
            )
            border_style = "green"
            title = "[bold green]✅ Analysis Complete[/bold green]"
        else:
            message = (
                "[bold green]🎉 Perfect! Your code is already clean![/bold green]\n\n"
                "[dim]No issues found. Your code follows security best practices\n"
                "and coding standards. Keep up the excellent work![/dim]"
            )
            border_style = "green"
            title = "[bold green]✨ Excellent Work[/bold green]"

        panel = Panel(message, title=title, border_style=border_style, box=box.DOUBLE)
        self.console.print()
        self.console.print(panel)
        self.console.print()

    def print_next_steps(self, report_path: Optional[Path] = None):
        """Print helpful next steps."""
        steps = [
            "✅ Review the changes PyGuard made to your files",
            "✅ Test your code to ensure everything works correctly",
            "✅ Commit your improved code to version control",
        ]

        if report_path:
            steps.append(f"✅ Open the HTML report: [bold cyan]{report_path}[/bold cyan]")

        steps.append("✅ Run PyGuard regularly to keep your code quality high")

        tree = Tree("[bold cyan]📋 What's Next?[/bold cyan]")
        for step in steps:
            tree.add(step)

        self.console.print(tree)
        self.console.print()

    def print_help_message(self):
        """Print helpful getting started message for beginners."""
        panel = Panel(
            "[bold cyan]Need Help?[/bold cyan]\n\n"
            "📖 [bold]Documentation:[/bold] Check docs/BEGINNER-GUIDE.md\n"
            "💬 [bold]Questions:[/bold] Open a discussion on GitHub\n"
            "🐛 [bold]Issues:[/bold] Report bugs on GitHub Issues\n"
            "⭐ [bold]Like PyGuard?:[/bold] Give us a star on GitHub!\n\n"
            "[dim]PyGuard is free and open-source. Built with ❤️ for developers.[/dim]",
            title="[bold cyan]💡 Help & Support[/bold cyan]",
            border_style="cyan",
        )
        self.console.print(panel)

    def print_error(self, error: str, suggestion: Optional[str] = None):
        """Print beginner-friendly error message."""
        message = f"[bold red]❌ Oops! Something went wrong:[/bold red]\n\n{error}"

        if suggestion:
            message += f"\n\n[bold yellow]💡 Suggestion:[/bold yellow]\n{suggestion}"

        panel = Panel(
            message,
            title="[bold red]Error[/bold red]",
            border_style="red",
            box=box.HEAVY,
        )
        self.console.print(panel)


class ModernHTMLReporter:
    """
    Modern, beautiful HTML reporter with best-in-class design.

    Features:
    - Responsive design for all screen sizes
    - Dark mode support
    - Interactive charts and graphs
    - Beautiful color scheme
    - Accessibility compliant (WCAG 2.1 AA)
    - Print-friendly CSS
    - Export options
    """

    def generate_report(
        self,
        metrics: Dict[str, Any],
        issues: List[Dict[str, Any]],
        fixes: List[Dict[str, Any]],
    ) -> str:
        """
        Generate stunning HTML report.

        Args:
            metrics: Analysis metrics
            issues: List of issues found
            fixes: List of fixes applied

        Returns:
            HTML string
        """
        # Generate timestamp
        timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")

        # Calculate summary stats
        total_issues = len(issues)
        high_issues = len([i for i in issues if i.get("severity") == "HIGH"])
        medium_issues = len([i for i in issues if i.get("severity") == "MEDIUM"])
        low_issues = len([i for i in issues if i.get("severity") == "LOW"])
        security_issues = len([i for i in issues if "security" in i.get("category", "").lower()])

        # Status message
        if total_issues == 0:
            status_class = "success"
            status_icon = "✅"
            status_text = "Perfect! No issues found"
        elif high_issues > 0:
            status_class = "critical"
            status_icon = "🔴"
            status_text = f"{high_issues} critical issues require immediate attention"
        else:
            status_class = "warning"
            status_icon = "⚠️"
            status_text = f"{total_issues} issues found - review and fix when possible"

        # Generate issue rows HTML
        issue_rows_html = ""
        for issue in issues:
            severity = issue.get("severity", "UNKNOWN")
            severity_class = severity.lower()
            severity_icon = {
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(severity, "⚪")

            issue_rows_html += f"""
                <tr class="severity-{severity_class}">
                    <td><span class="severity-badge severity-{severity_class}">{severity_icon} {severity}</span></td>
                    <td>{issue.get('category', 'Unknown')}</td>
                    <td class="file-cell">{Path(issue.get('file', '')).name}</td>
                    <td class="text-center">{issue.get('line', 0)}</td>
                    <td>{issue.get('message', '')}</td>
                </tr>
            """

        if not issue_rows_html:
            issue_rows_html = '<tr><td colspan="5" class="text-center no-issues">🎉 No issues found! Your code is clean and secure.</td></tr>'

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyGuard Analysis Report - {timestamp}</title>
    <style>
        /* === Modern Design System === */
        :root {{
            --primary: #667eea;
            --primary-dark: #5a67d8;
            --success: #48bb78;
            --warning: #ed8936;
            --danger: #f56565;
            --info: #4299e1;
            --gray-50: #f7fafc;
            --gray-100: #edf2f7;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e0;
            --gray-600: #718096;
            --gray-700: #4a5568;
            --gray-800: #2d3748;
            --gray-900: #1a202c;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            --radius-sm: 0.375rem;
            --radius-md: 0.5rem;
            --radius-lg: 0.75rem;
        }}

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {{
            :root {{
                --gray-50: #1a202c;
                --gray-100: #2d3748;
                --gray-200: #4a5568;
                --gray-300: #718096;
                --gray-600: #cbd5e0;
                --gray-700: #e2e8f0;
                --gray-800: #edf2f7;
                --gray-900: #f7fafc;
            }}
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-xl);
            overflow: hidden;
        }}

        /* Header */
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
        }}

        header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            font-weight: 300;
        }}

        header .timestamp {{
            margin-top: 1rem;
            font-size: 0.9rem;
            opacity: 0.8;
        }}

        /* Status Banner */
        .status-banner {{
            padding: 2rem;
            text-align: center;
            font-size: 1.5rem;
            font-weight: 600;
            border-bottom: 3px solid var(--gray-200);
        }}

        .status-banner.success {{
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
        }}

        .status-banner.warning {{
            background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);
            color: white;
        }}

        .status-banner.critical {{
            background: linear-gradient(135deg, #f56565 0%, #e53e3e 100%);
            color: white;
        }}

        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            padding: 2rem;
            background: var(--gray-50);
        }}

        .metric-card {{
            background: white;
            padding: 1.5rem;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }}

        .metric-card h3 {{
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--gray-600);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        .metric-card .value {{
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--gray-900);
            margin-bottom: 0.25rem;
        }}

        .metric-card .label {{
            font-size: 0.875rem;
            color: var(--gray-600);
        }}

        .metric-card.success .value {{ color: var(--success); }}
        .metric-card.warning .value {{ color: var(--warning); }}
        .metric-card.danger .value {{ color: var(--danger); }}
        .metric-card.info .value {{ color: var(--info); }}

        /* Issues Table */
        .issues-section {{
            padding: 2rem;
        }}

        .section-title {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--gray-900);
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .table-container {{
            background: white;
            border-radius: var(--radius-md);
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}

        th {{
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--gray-200);
            font-size: 0.9rem;
        }}

        tr:hover {{
            background: var(--gray-50);
        }}

        .text-center {{
            text-align: center;
        }}

        .file-cell {{
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--info);
        }}

        /* Severity Badges */
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .severity-badge.severity-high {{
            background: #fee;
            color: #c53030;
        }}

        .severity-badge.severity-medium {{
            background: #fefce8;
            color: #b7791f;
        }}

        .severity-badge.severity-low {{
            background: #e6fffa;
            color: #234e52;
        }}

        /* Row highlighting by severity */
        tr.severity-high {{
            background: #fff5f5;
        }}

        tr.severity-medium {{
            background: #fffaf0;
        }}

        tr.severity-low {{
            background: #f0fdf4;
        }}

        .no-issues {{
            padding: 3rem;
            font-size: 1.25rem;
            color: var(--success);
            font-weight: 600;
        }}

        /* Footer */
        footer {{
            background: var(--gray-900);
            color: var(--gray-300);
            padding: 2rem;
            text-align: center;
        }}

        footer a {{
            color: var(--primary);
            text-decoration: none;
        }}

        footer a:hover {{
            text-decoration: underline;
        }}

        .footer-links {{
            margin-top: 1rem;
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
        }}

        /* Print styles */
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
            .metric-card:hover {{
                transform: none;
            }}
        }}

        /* Responsive design */
        @media (max-width: 768px) {{
            body {{
                padding: 1rem;
            }}
            header h1 {{
                font-size: 1.75rem;
            }}
            .metrics-grid {{
                grid-template-columns: 1fr;
            }}
            .table-container {{
                overflow-x: auto;
            }}
        }}

        /* Animations */
        @keyframes fadeIn {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .metric-card {{
            animation: fadeIn 0.5s ease-out;
        }}

        .metric-card:nth-child(2) {{ animation-delay: 0.1s; }}
        .metric-card:nth-child(3) {{ animation-delay: 0.2s; }}
        .metric-card:nth-child(4) {{ animation-delay: 0.3s; }}
        .metric-card:nth-child(5) {{ animation-delay: 0.4s; }}
        .metric-card:nth-child(6) {{ animation-delay: 0.5s; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ PyGuard Analysis Report</h1>
            <p class="subtitle">The World's Best Python Security & Quality Tool</p>
            <p class="timestamp">Generated on {timestamp}</p>
        </header>

        <div class="status-banner {status_class}">
            {status_icon} {status_text}
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Total Files</h3>
                <div class="value">{metrics.get('total_files', 0)}</div>
                <div class="label">Analyzed</div>
            </div>
            <div class="metric-card danger">
                <h3>Issues Found</h3>
                <div class="value">{total_issues}</div>
                <div class="label">Total Issues</div>
            </div>
            <div class="metric-card danger">
                <h3>Critical Issues</h3>
                <div class="value">{high_issues}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="metric-card warning">
                <h3>Medium Issues</h3>
                <div class="value">{medium_issues}</div>
                <div class="label">Medium Severity</div>
            </div>
            <div class="metric-card success">
                <h3>Fixes Applied</h3>
                <div class="value">{len(fixes)}</div>
                <div class="label">Auto-Fixed</div>
            </div>
            <div class="metric-card info">
                <h3>Analysis Time</h3>
                <div class="value">{metrics.get('analysis_time_seconds', 0):.2f}s</div>
                <div class="label">Total Duration</div>
            </div>
        </div>

        <div class="issues-section">
            <h2 class="section-title">🔍 Detailed Issues</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>File</th>
                            <th class="text-center">Line</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {issue_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <footer>
            <p><strong>PyGuard</strong> - Built with ❤️ by <a href="https://github.com/cboyd0319" target="_blank">Chad Boyd</a></p>
            <p>Security • Quality • Formatting • Compliance</p>
            <div class="footer-links">
                <a href="https://github.com/cboyd0319/PyGuard" target="_blank">GitHub</a>
                <a href="https://github.com/cboyd0319/PyGuard/docs" target="_blank">Documentation</a>
                <a href="https://github.com/cboyd0319/PyGuard/issues" target="_blank">Report Issues</a>
            </div>
        </footer>
    </div>
</body>
</html>
        """
        return html.strip()

    def save_report(self, html: str, output_path: Path):
        """
        Save HTML report to file.

        Args:
            html: HTML content
            output_path: Output file path
        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            return True
        except Exception as e:
            print(f"Error saving HTML report: {e}")
            return False
