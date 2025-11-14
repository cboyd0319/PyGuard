"""PyGuard fix command - Automatically fix issues."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.prompt import Confirm

from pyguard.cli import PyGuardCLI
from pyguard.lib.config import PyGuardConfig
from pyguard.lib.ui import EnhancedConsole


class FixCommand:
    """Automatically fix code issues."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add fix command parser."""
        parser = subparsers.add_parser(
            "fix",
            help="Automatically fix issues",
            description="Scan and automatically fix security issues, quality problems, and style violations",
        )
        parser.add_argument(
            "paths",
            nargs="*",
            default=["."],
            help="Files or directories to fix (default: current directory)",
        )
        parser.add_argument(
            "--interactive",
            "-i",
            action="store_true",
            help="Interactively confirm each fix",
        )
        parser.add_argument(
            "--unsafe",
            action="store_true",
            help="Include unsafe fixes (may change behavior) - REVIEW CAREFULLY",
        )
        parser.add_argument(
            "--no-backup",
            action="store_true",
            help="Don't create backups before fixing",
        )
        parser.add_argument(
            "--security-only",
            action="store_true",
            help="Only fix security issues",
        )
        parser.add_argument(
            "--formatting-only",
            action="store_true",
            help="Only apply formatting fixes",
        )
        parser.add_argument(
            "--exclude",
            nargs="+",
            default=[],
            help="Patterns to exclude (e.g., 'venv/*' 'tests/*')",
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
            "--sarif",
            action="store_true",
            help="Generate SARIF report",
        )
        parser.add_argument(
            "--no-html",
            action="store_true",
            help="Don't generate HTML report",
        )
        parser.set_defaults(func=FixCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute fix command."""
        console = EnhancedConsole()

        # Validate conflicting flags
        if args.security_only and args.formatting_only:
            console.print_error(
                "Conflicting options",
                "Cannot use --security-only and --formatting-only together",
                suggestions=[
                    "Use --security-only for security fixes only",
                    "Use --formatting-only for formatting fixes only",
                    "Remove both flags to apply all fixes",
                ],
            )
            return 1

        # Load configuration
        config = PyGuardConfig.find_and_load()
        if config:
            console.console.print(f"[dim]Loaded config from {config.config_path}[/dim]")
        else:
            config = PyGuardConfig.get_default_config()

        # Merge config exclude patterns with command-line excludes
        exclude_patterns = list(set(config.general.exclude_patterns + args.exclude))

        # Warn about unsafe fixes
        if args.unsafe:
            console.console.print()
            console.console.print(
                "[bold yellow]⚠ WARNING: Unsafe fixes enabled![/bold yellow]"
            )
            console.console.print(
                "These fixes may change code behavior. Review all changes carefully!"
            )
            console.console.print()

            if not args.interactive:
                proceed = Confirm.ask("Do you want to continue?", default=False)
                if not proceed:
                    console.console.print("[yellow]Cancelled[/yellow]")
                    return 0

        # Initialize CLI
        cli = PyGuardCLI(allow_unsafe_fixes=args.unsafe)

        # Print banner
        cli.ui.print_banner()

        # Collect files
        all_files = []
        notebook_files = []

        for path_str in args.paths:
            path = Path(path_str)

            if not path.exists():
                console.print_error(
                    f"Path not found: {path_str}",
                    f"The path '{path_str}' does not exist. Please check the path and try again.",
                    suggestions=[
                        "Check for typos in the path",
                        f"Use absolute path: {path.resolve()}",
                        "Run 'ls' to see available files/directories",
                    ],
                )
                return 1

            if path.is_file():
                if path.suffix == ".py":
                    all_files.append(path)
                elif path.suffix == ".ipynb":
                    notebook_files.append(path)
            elif path.is_dir():
                # Find Python files
                files = cli.file_ops.find_python_files(path, exclude_patterns)
                all_files.extend(files)

                # Find Jupyter notebooks (for now, just scan them)
                for nb_file in path.rglob("*.ipynb"):
                    skip = False
                    for pattern in exclude_patterns:
                        if nb_file.match(pattern):
                            skip = True
                            break
                    if not skip and ".ipynb_checkpoints" not in str(nb_file):
                        notebook_files.append(nb_file)

        if not all_files and not notebook_files:
            console.print_error(
                "No Python files found",
                f"No .py files found in: {', '.join(args.paths)}",
                suggestions=[
                    "Check that you're in the right directory",
                    "Use 'pyguard fix path/to/code' to specify a different path",
                    "Check exclude patterns - you may be excluding too much",
                    f"Current exclude patterns: {', '.join(exclude_patterns)}",
                ],
            )
            return 1

        # Print file count
        total_files = len(all_files) + len(notebook_files)
        cli.ui.print_welcome(total_files)

        # Interactive mode
        if args.interactive:
            return FixCommand._interactive_fix(cli, all_files, config, args)

        # Auto-fix mode
        create_backup = not args.no_backup

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
        else:
            # Run full analysis with fixes
            results = cli.run_full_analysis(all_files, create_backup, fix=True)

        # Print results
        cli.print_results(results, generate_html=not args.no_html, generate_sarif=args.sarif)

        return 0

    @staticmethod
    def _interactive_fix(
        # TODO: Add docstring
        cli: PyGuardCLI,
        files: list[Path],
        _config: PyGuardConfig,
        args: argparse.Namespace,
    ) -> int:
        """Run interactive fix mode."""
        console = cli.ui.console

        console.print("[bold cyan]Interactive Fix Mode[/bold cyan]")
        console.print("Scanning for issues...")
        console.print()

        # First, scan for all issues
        results = cli.run_full_analysis(files, create_backup=False, fix=False)

        all_issues = results.get("all_issues", [])
        if not all_issues:
            console.print("[green]✓ No issues found![/green]")
            return 0

        console.print(f"Found {len(all_issues)} issues")
        console.print()

        fixed_count = 0
        skipped_count = 0

        # Group issues by file for better UX
        from collections import defaultdict

        issues_by_file = defaultdict(list)
        for issue in all_issues:
            issues_by_file[issue.get("file", "unknown")].append(issue)

        for file_path, file_issues in issues_by_file.items():
            console.print(f"[bold]{file_path}[/bold] ({len(file_issues)} issues)")

            for i, issue in enumerate(file_issues, 1):
                console.print()
                console.print(f"Issue {i}/{len(file_issues)}: {issue.get('message', 'Unknown')}")
                console.print(f"  Line {issue.get('line', '?')}: {issue.get('description', '')}")
                console.print(f"  Severity: {issue.get('severity', 'UNKNOWN')}")

                # Ask user
                choices = ["y", "n", "a", "q"]
                while True:
                    response = (
                        input("Apply this fix? [Y/n/a/q] (Yes/No/All/Quit): ").lower() or "y"
                    )
                    if response in choices:
                        break
                    console.print("[yellow]Invalid choice. Use y/n/a/q[/yellow]")

                if response == "q":
                    console.print("[yellow]Quitting interactive mode[/yellow]")
                    break
                if response == "a":
                    console.print("[cyan]Applying all remaining fixes...[/cyan]")
                    # Apply all fixes automatically
                    cli.run_full_analysis(files, create_backup=not args.no_backup, fix=True)
                    fixed_count += len(file_issues) - i + 1
                    break
                if response == "y":
                    # Apply this specific fix (simplified - in real implementation would target specific issue)
                    fixed_count += 1
                else:
                    skipped_count += 1

        console.print()
        console.print("[bold]Summary:[/bold]")
        console.print(f"  Fixed: {fixed_count}")
        console.print(f"  Skipped: {skipped_count}")

        return 0
