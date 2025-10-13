"""
PyGuard CLI - Main entry point for PyGuard QA and Auto-Fix Tool.

Enhanced with world-class UI using Rich library for beautiful, beginner-friendly output.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import List

from pyguard.lib.best_practices import BestPracticesFixer, NamingConventionFixer
from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer
from pyguard.lib.security import SecurityFixer
from pyguard.lib.ui import EnhancedConsole, ModernHTMLReporter
from pyguard.lib.sarif_reporter import SARIFReporter


class PyGuardCLI:
    """Main PyGuard CLI application."""

    def __init__(self):
        """Initialize PyGuard CLI."""
        self.logger = PyGuardLogger()
        self.backup_manager = BackupManager()
        self.file_ops = FileOperations()
        self.diff_generator = DiffGenerator()
        self.ui = EnhancedConsole()
        self.html_reporter = ModernHTMLReporter()
        self.sarif_reporter = SARIFReporter()

        # Initialize fixers
        self.security_fixer = SecurityFixer()
        self.best_practices_fixer = BestPracticesFixer()
        self.formatting_fixer = FormattingFixer()
        self.whitespace_fixer = WhitespaceFixer()
        self.naming_fixer = NamingConventionFixer()

    def run_security_fixes(self, files: List[Path], create_backup: bool = True) -> dict:
        """
        Run security fixes on files.

        Args:
            files: List of Python files to fix
            create_backup: Whether to create backups

        Returns:
            Dictionary with results
        """
        results = {"total": len(files), "fixed": 0, "failed": 0, "fixes": []}

        for file_path in files:
            # Create backup if requested
            if create_backup:
                self.backup_manager.create_backup(file_path)

            # Apply fixes
            success, fixes = self.security_fixer.fix_file(file_path)

            if success and fixes:
                results["fixed"] += 1
                results["fixes"].extend(fixes)
            elif not success:
                results["failed"] += 1

        return results

    def run_best_practices_fixes(self, files: List[Path], create_backup: bool = True) -> dict:
        """
        Run best practices fixes on files.

        Args:
            files: List of Python files to fix
            create_backup: Whether to create backups

        Returns:
            Dictionary with results
        """
        results = {"total": len(files), "fixed": 0, "failed": 0, "fixes": []}

        for file_path in files:
            # Create backup if requested
            if create_backup:
                self.backup_manager.create_backup(file_path)

            # Apply fixes
            success, fixes = self.best_practices_fixer.fix_file(file_path)

            if success and fixes:
                results["fixed"] += 1
                results["fixes"].extend(fixes)
            elif not success:
                results["failed"] += 1

        return results

    def run_formatting(
        self,
        files: List[Path],
        create_backup: bool = True,
        use_black: bool = True,
        use_isort: bool = True,
    ) -> dict:
        """
        Run formatting on files.

        Args:
            files: List of Python files to format
            create_backup: Whether to create backups
            use_black: Whether to use Black
            use_isort: Whether to use isort

        Returns:
            Dictionary with results
        """
        results = {"total": len(files), "formatted": 0, "failed": 0}

        for file_path in files:
            # Create backup if requested
            if create_backup:
                self.backup_manager.create_backup(file_path)

            # Apply formatting
            result = self.formatting_fixer.format_file(
                file_path,
                use_black=use_black,
                use_isort=use_isort,
            )

            if result["success"]:
                results["formatted"] += 1
            else:
                results["failed"] += 1

        return results

    def run_full_analysis(
        self, files: List[Path], create_backup: bool = True, fix: bool = True
    ) -> dict:
        """
        Run full analysis and fixes on files with beautiful progress display.

        Args:
            files: List of Python files to analyze
            create_backup: Whether to create backups
            fix: Whether to apply fixes

        Returns:
            Dictionary with comprehensive results
        """
        start_time = time.time()
        
        results = {
            "total_files": len(files),
            "files_with_issues": 0,
            "files_fixed": 0,
            "total_issues": 0,
            "security_issues": 0,
            "quality_issues": 0,
            "fixes_applied": 0,
            "security": {},
            "best_practices": {},
            "formatting": {},
            "all_issues": [],
        }

        if fix:
            # Create progress bar
            progress = self.ui.create_progress_bar()
            with progress:
                # Security fixes
                task = progress.add_task("🔒 Security Analysis...", total=len(files))
                results["security"] = self.run_security_fixes(files, create_backup)
                progress.update(task, completed=len(files))

                # Best practices
                task = progress.add_task("✨ Best Practices...", total=len(files))
                results["best_practices"] = self.run_best_practices_fixes(files, create_backup)
                progress.update(task, completed=len(files))

                # Formatting
                task = progress.add_task("🎨 Formatting...", total=len(files))
                results["formatting"] = self.run_formatting(files, create_backup)
                progress.update(task, completed=len(files))

            # Aggregate results
            if "fixes" in results["security"]:
                results["fixes_applied"] += len(results["security"]["fixes"])
                results["security_issues"] += len(results["security"]["fixes"])
            if "fixes" in results["best_practices"]:
                results["fixes_applied"] += len(results["best_practices"]["fixes"])
                results["quality_issues"] += len(results["best_practices"]["fixes"])

        else:
            # Just scan for issues
            from dataclasses import asdict

            security_issues = []
            progress = self.ui.create_progress_bar()
            with progress:
                task = progress.add_task("🔍 Scanning for issues...", total=len(files))
                for i, file_path in enumerate(files):
                    issues = self.security_fixer.scan_file_for_issues(file_path)
                    for issue in issues:
                        issue_dict = asdict(issue)
                        issue_dict["file"] = str(file_path)
                        # Rename line_number to line for consistency
                        if "line_number" in issue_dict:
                            issue_dict["line"] = issue_dict.pop("line_number")
                        security_issues.append(issue_dict)
                    progress.update(task, advance=1)

            results["security"] = {"issues_found": len(security_issues), "issues": security_issues}
            results["all_issues"] = security_issues
            results["total_issues"] = len(security_issues)
            results["security_issues"] = len(security_issues)

        # Calculate timing
        end_time = time.time()
        results["analysis_time_seconds"] = end_time - start_time
        results["avg_time_per_file_ms"] = (results["analysis_time_seconds"] / len(files)) * 1000 if files else 0

        return results

    def print_results(
        self, results: dict, generate_html: bool = True, generate_sarif: bool = False
    ) -> None:
        """
        Print beautiful formatted results using Rich UI.

        Args:
            results: Results dictionary
            generate_html: Whether to generate HTML report
            generate_sarif: Whether to generate SARIF report
        """
        # Print summary table
        self.ui.print_summary_table(results)

        # Print issue details if available
        if "all_issues" in results and results["all_issues"]:
            self.ui.print_issue_details(results["all_issues"])

        # Print success message
        self.ui.print_success_message(results.get("fixes_applied", 0))

        # Generate HTML report
        html_path = None
        if generate_html:
            html_path = Path("pyguard-report.html")
            html_content = self.html_reporter.generate_report(
                metrics=results,
                issues=results.get("all_issues", []),
                fixes=results.get("security", {}).get("fixes", [])
                + results.get("best_practices", {}).get("fixes", []),
            )
            if self.html_reporter.save_report(html_content, html_path):
                self.ui.console.print(
                    f"[bold green]✅ HTML report saved:[/bold green] [cyan]{html_path}[/cyan]"
                )
                self.ui.console.print()

        # Generate SARIF report
        if generate_sarif:
            sarif_path = Path("pyguard-report.sarif")
            from pyguard import __version__

            sarif_report = self.sarif_reporter.generate_report(
                issues=results.get("all_issues", []),
                tool_name="PyGuard",
                tool_version=__version__,
            )
            if self.sarif_reporter.save_report(sarif_report, sarif_path):
                self.ui.console.print(
                    f"[bold green]✅ SARIF report saved:[/bold green] [cyan]{sarif_path}[/cyan]"
                )
                self.ui.console.print(
                    "   Use this report for GitHub Code Scanning integration"
                )
                self.ui.console.print()

        # Print next steps
        self.ui.print_next_steps(html_path)

        # Print help message
        self.ui.print_help_message()


def main():
    """Main CLI entry point."""
    from pyguard import __version__

    parser = argparse.ArgumentParser(
        description="PyGuard - Python QA and Auto-Fix Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"PyGuard {__version__}",
    )

    parser.add_argument(
        "paths",
        nargs="+",
        help="File or directory paths to analyze",
    )

    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backups before fixing",
    )

    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan for issues, don't apply fixes",
    )

    parser.add_argument(
        "--security-only",
        action="store_true",
        help="Only run security fixes",
    )

    parser.add_argument(
        "--formatting-only",
        action="store_true",
        help="Only run formatting",
    )

    parser.add_argument(
        "--best-practices-only",
        action="store_true",
        help="Only run best practices fixes",
    )

    parser.add_argument(
        "--no-black",
        action="store_true",
        help="Don't use Black formatter",
    )

    parser.add_argument(
        "--no-isort",
        action="store_true",
        help="Don't use isort for import sorting",
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="Patterns to exclude (e.g., 'venv/*' 'tests/*')",
    )

    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Generate SARIF report for GitHub Code Scanning integration",
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Don't generate HTML report",
    )

    args = parser.parse_args()

    # Initialize CLI
    cli = PyGuardCLI()

    # Collect files
    all_files = []
    for path_str in args.paths:
        path = Path(path_str)

        if path.is_file() and path.suffix == ".py":
            all_files.append(path)
        elif path.is_dir():
            files = cli.file_ops.find_python_files(path, args.exclude)
            all_files.extend(files)
        else:
            print(f"Warning: {path} is not a Python file or directory, skipping...")

    if not all_files:
        cli.ui.print_error(
            "No Python files found to analyze.",
            "Make sure you specified the correct path and that Python files exist in that location."
        )
        sys.exit(1)

    # Print banner and welcome
    cli.ui.print_banner()
    cli.ui.print_welcome(len(all_files))

    # Run analysis based on flags
    create_backup = not args.no_backup
    fix = not args.scan_only

    if args.security_only:
        results = {"security": cli.run_security_fixes(all_files, create_backup)}
    elif args.formatting_only:
        results = {
            "formatting": cli.run_formatting(
                all_files,
                create_backup,
                use_black=not args.no_black,
                use_isort=not args.no_isort,
            )
        }
    elif args.best_practices_only:
        results = {"best_practices": cli.run_best_practices_fixes(all_files, create_backup)}
    else:
        # Run full analysis
        results = cli.run_full_analysis(all_files, create_backup, fix)

    # Print results
    cli.print_results(results, generate_html=not args.no_html, generate_sarif=args.sarif)


if __name__ == "__main__":
    main()
