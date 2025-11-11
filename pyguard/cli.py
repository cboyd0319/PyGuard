"""
PyGuard CLI - Main entry point for PyGuard QA and Auto-Fix Tool.

Enhanced with world-class UI using Rich library for beautiful, beginner-friendly output.
"""

import argparse
from collections import Counter
from dataclasses import asdict
from pathlib import Path
import sys
import time
from typing import TYPE_CHECKING, Any, Optional

from pyguard import __version__
from pyguard.lib.best_practices import BestPracticesFixer, NamingConventionFixer
from pyguard.lib.compliance_tracker import ComplianceTracker
from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.enhanced_security_fixes import EnhancedSecurityFixer
from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer
from pyguard.lib.import_analyzer import ImportAnalyzer
from pyguard.lib.ripgrep_filter import RipGrepFilter
from pyguard.lib.sarif_reporter import SARIFReporter
from pyguard.lib.secret_scanner import SecretScanner
from pyguard.lib.security import SecurityFixer
from pyguard.lib.test_coverage import TestCoverageAnalyzer
from pyguard.lib.ui import EnhancedConsole, ModernHTMLReporter

if TYPE_CHECKING:
    from pyguard.lib.notebook_analyzer import NotebookSecurityAnalyzer

# Display constants
MAX_ITEMS_TO_DISPLAY = 10
MAX_UNTESTED_MODULES_TO_DISPLAY = 20


class PyGuardCLI:
    """Main PyGuard CLI application."""

    def __init__(self, allow_unsafe_fixes: bool = False):
        """
        Initialize PyGuard CLI.

        Args:
            allow_unsafe_fixes: Whether to allow unsafe auto-fixes
        """
        self.logger = PyGuardLogger()
        self.backup_manager = BackupManager()
        self.file_ops = FileOperations()
        self.diff_generator = DiffGenerator()
        self.ui = EnhancedConsole()
        self.html_reporter = ModernHTMLReporter()
        self.sarif_reporter = SARIFReporter()

        # Initialize fixers
        self.security_fixer = SecurityFixer()
        self.enhanced_security_fixer = EnhancedSecurityFixer(allow_unsafe=allow_unsafe_fixes)
        self.best_practices_fixer = BestPracticesFixer()
        self.formatting_fixer = FormattingFixer()
        self.whitespace_fixer = WhitespaceFixer()
        self.naming_fixer = NamingConventionFixer()

        # Initialize notebook analyzer (lazy load)
        self._notebook_analyzer: NotebookSecurityAnalyzer | None = None

    @property
    def notebook_analyzer(self) -> Optional["NotebookSecurityAnalyzer"]:
        """Lazy load notebook analyzer."""
        if self._notebook_analyzer is None:
            try:
                from pyguard.lib.notebook_analyzer import (  # noqa: PLC0415 - Lazy import for optional dependency
                    NotebookSecurityAnalyzer,
                )

                self._notebook_analyzer = NotebookSecurityAnalyzer()
            except ImportError:
                self.ui.console.print(
                    "[yellow]Warning: nbformat not installed. "
                    "Notebook analysis unavailable.[/yellow]"
                )
                self._notebook_analyzer = None
        return self._notebook_analyzer

    def run_security_fixes(self, files: list[Path], create_backup: bool = True) -> dict[str, Any]:
        """
        Run security fixes on files.

        Args:
            files: List of Python files to fix
            create_backup: Whether to create backups

        Returns:
            Dictionary with results
        """
        total: int = len(files)
        fixed: int = 0
        failed: int = 0
        fixes_list: list[str] = []

        for file_path in files:
            # Create backup if requested
            if create_backup:
                self.backup_manager.create_backup(file_path)

            # Apply fixes from both fixers
            # Original security fixer
            success1, fixes1 = self.security_fixer.fix_file(file_path)

            # Enhanced security fixer with safety classifications
            success2, fixes2 = self.enhanced_security_fixer.fix_file(file_path)

            if (success1 and fixes1) or (success2 and fixes2):
                fixed += 1
                fixes_list.extend(fixes1)
                fixes_list.extend(fixes2)
            elif not success1 or not success2:
                failed += 1

        return {"total": total, "fixed": fixed, "failed": failed, "fixes": fixes_list}

    def run_best_practices_fixes(
        self, files: list[Path], create_backup: bool = True
    ) -> dict[str, Any]:
        """
        Run best practices fixes on files.

        Args:
            files: List[Path] of Python files to fix
            create_backup: Whether to create backups

        Returns:
            Dictionary with results
        """
        total: int = len(files)
        fixed: int = 0
        failed: int = 0
        fixes_list: list[str] = []

        for file_path in files:
            # Create backup if requested
            if create_backup:
                self.backup_manager.create_backup(file_path)

            # Apply fixes
            success, fixes = self.best_practices_fixer.fix_file(file_path)

            if success and fixes:
                fixed += 1
                fixes_list.extend(fixes)
            elif not success:
                failed += 1

        return {"total": total, "fixed": fixed, "failed": failed, "fixes": fixes_list}

    def analyze_notebooks(self, notebooks: list[Path]) -> dict[str, Any]:
        """
        Analyze Jupyter notebooks for security issues.

        Args:
            notebooks: List of .ipynb files to analyze

        Returns:
            Dictionary with results
        """
        if not self.notebook_analyzer:
            return {
                "total": len(notebooks),
                "analyzed": 0,
                "findings": [],
                "error": "Notebook analyzer not available (nbformat not installed)",
            }

        all_results = []
        total_findings = 0
        critical_count = 0
        high_count = 0

        for nb_path in notebooks:
            try:
                result = self.notebook_analyzer.analyze_notebook(nb_path)
                all_results.append(result)
                total_findings += result.total_count()
                critical_count += result.critical_count()
                high_count += result.high_count()
            except Exception as e:
                self.logger.error(f"Failed to analyze {nb_path}: {e}")

        return {
            "total": len(notebooks),
            "analyzed": len(all_results),
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "results": all_results,
        }

    def run_formatting(
        self,
        files: list[Path],
        create_backup: bool = True,
        use_black: bool = True,
        use_isort: bool = True,
    ) -> dict[str, Any]:
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
        self, files: list[Path], create_backup: bool = True, fix: bool = True
    ) -> dict[str, Any]:
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
                task = progress.add_task(" Security Analysis...", total=len(files))
                results["security"] = self.run_security_fixes(files, create_backup)
                progress.update(task, completed=len(files))

                # Best practices
                task = progress.add_task(
                    self.ui._safe_text("✨ Best Practices..."), total=len(files)
                )
                results["best_practices"] = self.run_best_practices_fixes(files, create_backup)
                progress.update(task, completed=len(files))

                # Formatting
                task = progress.add_task(self.ui._safe_text("🎨 Formatting..."), total=len(files))
                results["formatting"] = self.run_formatting(files, create_backup)
                progress.update(task, completed=len(files))

            # Aggregate results
            security_result = results["security"]
            if isinstance(security_result, dict) and "fixes" in security_result:
                fixes_count = len(security_result["fixes"])
                results["fixes_applied"] = results["fixes_applied"] + fixes_count  # type: ignore
                results["security_issues"] = results["security_issues"] + fixes_count  # type: ignore

            bp_result = results["best_practices"]
            if isinstance(bp_result, dict) and "fixes" in bp_result:
                fixes_count = len(bp_result["fixes"])
                results["fixes_applied"] = results["fixes_applied"] + fixes_count  # type: ignore
                results["quality_issues"] = results["quality_issues"] + fixes_count  # type: ignore

        else:
            # Just scan for issues (ALL types: security, quality, patterns)

            all_issues = []
            security_issues = []
            quality_issues = []

            progress = self.ui.create_progress_bar()
            with progress:
                task = progress.add_task(
                    self.ui._safe_text("🔍 Scanning for issues..."), total=len(files)
                )
                for _i, file_path in enumerate(files):
                    # Security issues
                    sec_issues = self.security_fixer.scan_file_for_issues(file_path)
                    for sec_issue in sec_issues:
                        issue_dict = asdict(sec_issue)
                        issue_dict["file"] = str(file_path)
                        # Rename line_number to line for consistency
                        if "line_number" in issue_dict:
                            issue_dict["line"] = issue_dict.pop("line_number")
                        security_issues.append(issue_dict)
                        all_issues.append(issue_dict)

                    # Quality issues (best practices, naming, etc.)
                    qual_issues = self.best_practices_fixer.scan_file_for_issues(file_path)
                    for qual_issue in qual_issues:
                        issue_dict = asdict(qual_issue)
                        issue_dict["file"] = str(file_path)
                        if "line_number" in issue_dict:
                            issue_dict["line"] = issue_dict.pop("line_number")
                        quality_issues.append(issue_dict)
                        all_issues.append(issue_dict)

                    progress.update(task, advance=1)

            results["security"] = {"issues_found": len(security_issues), "issues": security_issues}
            results["best_practices"] = {
                "issues_found": len(quality_issues),
                "issues": quality_issues,
            }
            results["all_issues"] = all_issues
            results["total_issues"] = len(all_issues)
            results["security_issues"] = len(security_issues)
            results["quality_issues"] = len(quality_issues)

        # Calculate timing
        end_time = time.time()
        analysis_time = end_time - start_time
        results["analysis_time_seconds"] = analysis_time
        results["avg_time_per_file_ms"] = (analysis_time / len(files)) * 1000 if files else 0

        return results

    def print_results(
        self, results: dict[str, Any], generate_html: bool = True, generate_sarif: bool = False
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
        if results.get("all_issues"):
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
                    f"[bold green][OK] HTML report saved:[/bold green] [cyan]{html_path}[/cyan]"
                )
                self.ui.console.print()

        # Generate SARIF report
        if generate_sarif:
            sarif_path = Path("pyguard-report.sarif")

            sarif_report = self.sarif_reporter.generate_report(
                issues=results.get("all_issues", []),
                tool_name="PyGuard",
                tool_version=__version__,
            )
            if self.sarif_reporter.save_report(sarif_report, sarif_path):
                self.ui.console.print(
                    f"[bold green][OK] SARIF report saved:[/bold green] [cyan]{sarif_path}[/cyan]"
                )
                self.ui.console.print("   Use this report for GitHub Code Scanning integration")
                self.ui.console.print()

        # Print next steps
        self.ui.print_next_steps(html_path)

        # Print help message
        self.ui.print_help_message()


def main():
    """Main CLI entry point."""

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

    parser.add_argument(
        "--unsafe-fixes",
        action="store_true",
        help="Enable unsafe auto-fixes that may change code behavior. "
        "WARNING: These fixes include SQL parameterization, command injection "
        "refactoring, and path traversal validation. Review changes carefully!",
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch mode: monitor files for changes and re-analyze automatically. "
        "Press Ctrl+C to stop.",
    )

    parser.add_argument(
        "--fast",
        action="store_true",
        help="Enable fast mode with ripgrep pre-filtering (requires ripgrep installed). "
        "Dramatically improves performance for large codebases by pre-filtering files.",
    )

    parser.add_argument(
        "--scan-secrets",
        action="store_true",
        help="Fast secret scanning using ripgrep to detect hardcoded credentials, "
        "API keys, tokens, and other sensitive data.",
    )

    parser.add_argument(
        "--analyze-imports",
        action="store_true",
        help="Analyze import structure to detect circular imports and god modules.",
    )

    parser.add_argument(
        "--check-test-coverage",
        action="store_true",
        help="Check for modules without corresponding test files.",
    )

    parser.add_argument(
        "--compliance-report",
        action="store_true",
        help="Generate compliance report from OWASP/CWE annotations in code.",
    )

    parser.add_argument(
        "--compliance-html",
        type=str,
        metavar="FILE",
        help="Generate HTML compliance report with issues mapped to frameworks "
        "(OWASP, PCI-DSS, HIPAA, SOC2, ISO27001, etc.). Example: --compliance-html report.html",
    )

    parser.add_argument(
        "--compliance-json",
        type=str,
        metavar="FILE",
        help="Generate JSON compliance report for programmatic processing. "
        "Example: --compliance-json report.json",
    )

    parser.add_argument(
        "--diff",
        type=str,
        metavar="SPEC",
        help="Analyze only changed files in git diff. "
        "SPEC can be branch comparison (main..feature), commit range (HEAD~1), "
        "or 'staged' for staged changes. Example: --diff main..feature-branch",
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel processing for faster analysis of multiple files. "
        "Uses multiple CPU cores to process files concurrently.",
    )

    args = parser.parse_args()

    # Initialize CLI with unsafe fixes flag
    cli = PyGuardCLI(allow_unsafe_fixes=args.unsafe_fixes)

    # Handle git diff mode
    if args.diff:
        from pyguard.lib.git_diff_analyzer import GitDiffAnalyzer  # noqa: PLC0415 - Lazy import

        try:
            diff_analyzer = GitDiffAnalyzer()

            # Handle special cases
            if args.diff == "staged":
                all_files = diff_analyzer.get_changed_files(include_staged=True)
            else:
                all_files = diff_analyzer.get_changed_files(diff_spec=args.diff)

            if not all_files:
                cli.ui.console.print(
                    f"[yellow]No changed Python files found for diff: {args.diff}[/yellow]"
                )
                sys.exit(0)

            # Show what we're analyzing
            stats = diff_analyzer.get_diff_stats(args.diff if args.diff != "staged" else "HEAD")
            cli.ui.console.print("[bold cyan]Git Diff Analysis[/bold cyan]")
            cli.ui.console.print(f"  Diff specification: {args.diff}")
            cli.ui.console.print(f"  Changed files: {stats.total_changed_files}")
            cli.ui.console.print(f"  Python files: {len(all_files)}")
            cli.ui.console.print(f"  Lines added: +{stats.added_lines}")
            cli.ui.console.print(f"  Lines deleted: -{stats.deleted_lines}")
            cli.ui.console.print()

            notebook_files: list[Path] = []  # Don't analyze notebooks in diff mode for now

        except ValueError as e:
            cli.ui.print_error("Git Diff Error", str(e))
            sys.exit(1)
    else:
        # Collect files normally
        all_files = []
        notebook_files = []
        for path_str in args.paths:
            path = Path(path_str)

            if path.is_file():
                if path.suffix == ".py":
                    all_files.append(path)
                elif path.suffix == ".ipynb":
                    notebook_files.append(path)
            elif path.is_dir():
                # Find Python files
                files = cli.file_ops.find_python_files(path, args.exclude)
                all_files.extend(files)

                # Find Jupyter notebooks
                for nb_file in path.rglob("*.ipynb"):
                    # Skip files in exclude patterns
                    skip = False
                    for pattern in args.exclude:
                        if nb_file.match(pattern):
                            skip = True
                            break
                    if not skip and ".ipynb_checkpoints" not in str(nb_file):
                        notebook_files.append(nb_file)
            else:
                # Path doesn't exist or is not a regular file/directory
                cli.ui.console.print(
                    f"[yellow]Warning: {path_str} is not a Python file, notebook, or directory.[/yellow]"
                )

    if not all_files and not notebook_files:
        cli.ui.print_error(
            "No Python files or Jupyter notebooks found to analyze.",
            "Make sure you specified the correct path and that files exist in that location.",
        )
        sys.exit(1)

    # Handle special analysis modes first
    # Secret scanning
    if args.scan_secrets:
        cli.ui.console.print("[bold cyan]Running Secret Scan...[/bold cyan]")
        cli.ui.console.print()

        if not RipGrepFilter.is_ripgrep_available():
            cli.ui.console.print(
                "[yellow]Warning: ripgrep not found. Secret scanning requires ripgrep.[/yellow]"
            )
            cli.ui.console.print(
                "[yellow]Install with: brew install ripgrep (macOS) or apt install ripgrep (Linux)[/yellow]"
            )
            sys.exit(1)

        for path_str in args.paths:
            findings = SecretScanner.scan_secrets(path_str, export_sarif=args.sarif)

            if findings:
                cli.ui.console.print(f"[red]Found {len(findings)} hardcoded secrets:[/red]")

                # Group by secret type

                types = Counter(f.secret_type for f in findings)
                for secret_type, count in types.items():
                    cli.ui.console.print(f"  - {count} x {secret_type}")

                cli.ui.console.print()
                cli.ui.console.print("[bold]Secret Details:[/bold]")
                for finding in findings[:10]:  # Show first 10
                    cli.ui.console.print(
                        f"  {finding.file_path}:{finding.line_number} - {finding.secret_type}"
                    )
                    cli.ui.console.print(f"    {finding.match}")

                if len(findings) > MAX_ITEMS_TO_DISPLAY:
                    cli.ui.console.print(f"  ... and {len(findings) - MAX_ITEMS_TO_DISPLAY} more")

                if args.sarif:
                    cli.ui.console.print("[green]SARIF report: pyguard-secrets.sarif[/green]")
            else:
                cli.ui.console.print("[green]No hardcoded secrets found.[/green]")

        sys.exit(0)

    # Import analysis
    if args.analyze_imports:
        cli.ui.console.print("[bold cyan]Analyzing Import Structure...[/bold cyan]")
        cli.ui.console.print()

        if not RipGrepFilter.is_ripgrep_available():
            cli.ui.console.print(
                "[yellow]Warning: ripgrep not found. Import analysis requires ripgrep.[/yellow]"
            )
            cli.ui.console.print(
                "[yellow]Install with: brew install ripgrep (macOS) or apt install ripgrep (Linux)[/yellow]"
            )
            sys.exit(1)

        for path_str in args.paths:
            # Find circular imports
            circular = ImportAnalyzer.find_circular_imports(path_str)
            if circular:
                cli.ui.console.print("[red]Circular imports detected:[/red]")
                for file_a, file_b in circular[:MAX_ITEMS_TO_DISPLAY]:
                    cli.ui.console.print(f"  - {file_a} ↔ {file_b}")
                if len(circular) > MAX_ITEMS_TO_DISPLAY:
                    cli.ui.console.print(f"  ... and {len(circular) - MAX_ITEMS_TO_DISPLAY} more")
            else:
                cli.ui.console.print("[green]No circular imports detected.[/green]")

            cli.ui.console.print()

            # Find god modules
            god_modules = ImportAnalyzer.find_god_modules(path_str)
            if god_modules:
                cli.ui.console.print("[yellow]God modules (>20 imports):[/yellow]")
                for module, count in god_modules[:MAX_ITEMS_TO_DISPLAY]:
                    cli.ui.console.print(f"  - {module}: imported {count} times")
                if len(god_modules) > MAX_ITEMS_TO_DISPLAY:
                    cli.ui.console.print(
                        f"  ... and {len(god_modules) - MAX_ITEMS_TO_DISPLAY} more"
                    )
            else:
                cli.ui.console.print("[green]No god modules detected.[/green]")

        sys.exit(0)

    # Test coverage check
    if args.check_test_coverage:
        cli.ui.console.print("[bold cyan]Checking Test Coverage...[/bold cyan]")
        cli.ui.console.print()

        if not RipGrepFilter.is_ripgrep_available():
            cli.ui.console.print(
                "[yellow]Warning: ripgrep not found. Test coverage check requires ripgrep.[/yellow]"
            )
            cli.ui.console.print(
                "[yellow]Install with: brew install ripgrep (macOS) or apt install ripgrep (Linux)[/yellow]"
            )
            sys.exit(1)

        for path_str in args.paths:
            # Try common test directory names
            test_dirs = ["tests", "test", "testing"]
            test_dir = None
            for td in test_dirs:
                if Path(td).exists():
                    test_dir = td
                    break

            if not test_dir:
                cli.ui.console.print(
                    "[yellow]No test directory found. Looking for 'tests', 'test', or 'testing'.[/yellow]"
                )
                sys.exit(1)

            coverage_ratio = TestCoverageAnalyzer.calculate_test_coverage_ratio(path_str, test_dir)
            cli.ui.console.print(f"[bold]Test coverage: {coverage_ratio:.1f}%[/bold]")
            cli.ui.console.print()

            untested = TestCoverageAnalyzer.find_untested_modules(path_str, test_dir)
            if untested:
                cli.ui.console.print(f"[yellow]Untested modules ({len(untested)}):[/yellow]")
                for module in untested[:MAX_UNTESTED_MODULES_TO_DISPLAY]:
                    cli.ui.console.print(f"  - {module}")
                if len(untested) > MAX_UNTESTED_MODULES_TO_DISPLAY:
                    cli.ui.console.print(
                        f"  ... and {len(untested) - MAX_UNTESTED_MODULES_TO_DISPLAY} more"
                    )
            else:
                cli.ui.console.print("[green]All modules have test coverage![/green]")

        sys.exit(0)

    # Compliance report
    if args.compliance_report:
        cli.ui.console.print("[bold cyan]Generating Compliance Report...[/bold cyan]")
        cli.ui.console.print()

        if not RipGrepFilter.is_ripgrep_available():
            cli.ui.console.print(
                "[yellow]Warning: ripgrep not found. Compliance tracking requires ripgrep.[/yellow]"
            )
            cli.ui.console.print(
                "[yellow]Install with: brew install ripgrep (macOS) or apt install ripgrep (Linux)[/yellow]"
            )
            sys.exit(1)

        for path_str in args.paths:
            ComplianceTracker.generate_compliance_report(path_str)

            # Also print summary
            annotations = ComplianceTracker.find_compliance_annotations(path_str)
            cli.ui.console.print(
                f"[green]Found {len(annotations['OWASP'])} OWASP references[/green]"
            )
            cli.ui.console.print(f"[green]Found {len(annotations['CWE'])} CWE references[/green]")

        sys.exit(0)

    # Print banner and welcome
    cli.ui.print_banner()
    total_files = len(all_files) + len(notebook_files)
    cli.ui.print_welcome(total_files)

    # Apply fast mode filtering if enabled
    if args.fast and all_files:
        if RipGrepFilter.is_ripgrep_available():
            cli.ui.console.print("[cyan]Fast mode enabled: Using ripgrep pre-filtering...[/cyan]")

            # Get suspicious files for each directory
            all_candidate_files = set()
            for path_str in args.paths:
                path = Path(path_str)
                if path.is_dir():
                    candidates = RipGrepFilter.find_suspicious_files(str(path))
                    all_candidate_files.update(candidates)

            # Convert to Path objects
            candidate_paths = {Path(f) for f in all_candidate_files}

            # Filter the all_files list
            original_count = len(all_files)
            all_files = [
                f for f in all_files if f in candidate_paths or str(f) in all_candidate_files
            ]

            filtered_count = original_count - len(all_files)
            cli.ui.console.print(
                f"[cyan]RipGrep filter: {len(all_files)} candidates "
                f"(skipping {filtered_count} clean files)[/cyan]"
            )
            cli.ui.console.print()

            if len(all_files) == 0:
                cli.ui.console.print(
                    "[green]No suspicious files found! Your codebase looks clean.[/green]"
                )
                sys.exit(0)
        else:
            cli.ui.console.print("[yellow]Warning: ripgrep not found. Fast mode disabled.[/yellow]")
            cli.ui.console.print(
                "[yellow]Install with: brew install ripgrep (macOS) or apt install ripgrep (Linux)[/yellow]"
            )

    if notebook_files:
        cli.ui.console.print(
            f"[cyan]Found {len(all_files)} Python files and {len(notebook_files)} Jupyter notebooks[/cyan]"
        )
        cli.ui.console.print()

    # Run analysis based on flags
    create_backup = not args.no_backup
    fix = not args.scan_only

    # Watch mode
    if args.watch:
        from pyguard.lib.watch import run_watch_mode  # noqa: PLC0415 - Lazy import for watch mode

        def analyze_file(file_path: Path):
            """Analyze a single file in watch mode."""
            from rich.console import Console  # noqa: PLC0415 - Lazy import for watch mode

            console = Console()
            console.print(f"[cyan]Analyzing {file_path}...[/cyan]")

            if args.security_only:
                cli.run_security_fixes([file_path], create_backup)
            elif args.formatting_only:
                cli.run_formatting(
                    [file_path],
                    create_backup,
                    use_black=not args.no_black,
                    use_isort=not args.no_isort,
                )
            elif args.best_practices_only:
                cli.run_best_practices_fixes([file_path], create_backup)
            else:
                cli.run_full_analysis([file_path], create_backup, fix)

            console.print("[green][OK] Analysis complete[/green]")

        # Convert paths back to Path objects for watch mode
        watch_paths = [Path(p) for p in args.paths]
        run_watch_mode(watch_paths, analyze_file)
        return

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

        # Analyze notebooks if any
        if notebook_files:
            cli.ui.console.print()
            cli.ui.console.print("[bold cyan]Analyzing Jupyter Notebooks...[/bold cyan]")
            cli.ui.console.print()

            notebook_results = cli.analyze_notebooks(notebook_files)
            results["notebooks"] = notebook_results

            # Add notebook findings to all_issues for reporting
            if "results" in notebook_results:
                for nb_result in notebook_results["results"]:
                    for finding in nb_result.findings:
                        # Convert finding to issue format
                        issue = {
                            "file": str(nb_result.notebook_path),
                            "line": finding.line_number or 0,
                            "severity": finding.severity,
                            "rule_id": finding.rule_id,
                            "message": finding.message,
                            "description": finding.description,
                            "cell_index": finding.cell_index,
                            "cell_type": finding.cell_type,
                        }
                        if "all_issues" not in results:
                            results["all_issues"] = []  # type: ignore[assignment]
                        results["all_issues"].append(issue)  # type: ignore[attr-defined]

                        # Update counters
                        if finding.severity in {"CRITICAL", "HIGH"}:
                            security_count = results.get("security_issues", 0)
                            if isinstance(security_count, int):
                                results["security_issues"] = security_count + 1  # type: ignore[assignment]

            # Print notebook summary
            cli.ui.console.print()
            cli.ui.console.print("[bold]Notebook Analysis Summary:[/bold]")
            cli.ui.console.print(f"  Total notebooks: {notebook_results['total']}")
            cli.ui.console.print(f"  Analyzed: {notebook_results['analyzed']}")
            cli.ui.console.print(f"  Total findings: {notebook_results.get('total_findings', 0)}")
            cli.ui.console.print(f"    CRITICAL: {notebook_results.get('critical_count', 0)}")
            cli.ui.console.print(f"    HIGH: {notebook_results.get('high_count', 0)}")
            cli.ui.console.print()

    # Generate enhanced compliance reports if requested
    if args.compliance_html or args.compliance_json:
        from pyguard.lib.compliance_reporter import (
            ComplianceReporter,
        )

        reporter = ComplianceReporter()

        # Collect all issues from results
        all_issues_raw: dict[str, Any] | list[Any] = results.get("all_issues", [])
        all_issues: list[dict[str, Any]] = all_issues_raw if isinstance(all_issues_raw, list) else []

        if args.compliance_html:
            cli.ui.console.print(f"[cyan]Generating HTML compliance report: {args.compliance_html}[/cyan]")
            reporter.generate_html_report(all_issues, args.compliance_html)

        if args.compliance_json:
            cli.ui.console.print(f"[cyan]Generating JSON compliance report: {args.compliance_json}[/cyan]")
            reporter.generate_json_report(all_issues, args.compliance_json)

    # Print results
    cli.print_results(results, generate_html=not args.no_html, generate_sarif=args.sarif)


if __name__ == "__main__":
    main()
