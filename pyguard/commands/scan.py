"""PyGuard scan command - Analyze code without making changes."""

from __future__ import annotations

import argparse
from pathlib import Path

from pyguard.cli import PyGuardCLI
from pyguard.lib.config import PyGuardConfig
from pyguard.lib.ui import EnhancedConsole


class ScanCommand:
    """Scan code for issues without making changes."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add scan command parser."""
        parser = subparsers.add_parser(
            "scan",
            help="Scan code for issues (no fixes)",
            description="Analyze Python code for security issues, quality problems, and style violations",
        )
        parser.add_argument(
            "paths",
            nargs="*",
            default=["."],
            help="Files or directories to scan (default: current directory)",
        )
        parser.add_argument(
            "--security-only",
            action="store_true",
            help="Only scan for security issues",
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
            help="Generate SARIF report for GitHub Code Scanning",
        )
        parser.add_argument(
            "--no-html",
            action="store_true",
            help="Don't generate HTML report",
        )
        parser.add_argument(
            "--fast",
            action="store_true",
            help="Fast mode with ripgrep pre-filtering (requires ripgrep)",
        )
        parser.add_argument(
            "--json",
            type=str,
            metavar="FILE",
            help="Export results as JSON",
        )
        parser.set_defaults(func=ScanCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute scan command."""
        console = EnhancedConsole()

        # Load configuration
        config = PyGuardConfig.find_and_load()
        if config:
            console.console.print(f"[dim]Loaded config from {config.config_path}[/dim]")
        else:
            config = PyGuardConfig.get_default_config()

        # Merge config exclude patterns with command-line excludes
        exclude_patterns = list(set(config.general.exclude_patterns + args.exclude))

        # Initialize CLI
        cli = PyGuardCLI(allow_unsafe_fixes=False)

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
                else:
                    console.console.print(
                        f"[yellow]Warning: {path_str} is not a Python file (.py) or notebook (.ipynb)[/yellow]"
                    )
            elif path.is_dir():
                # Find Python files
                files = cli.file_ops.find_python_files(path, exclude_patterns)
                all_files.extend(files)

                # Find Jupyter notebooks
                for nb_file in path.rglob("*.ipynb"):
                    # Skip files in exclude patterns
                    skip = False
                    for pattern in exclude_patterns:
                        if nb_file.match(pattern):
                            skip = True
                            break
                    if not skip and ".ipynb_checkpoints" not in str(nb_file):
                        notebook_files.append(nb_file)

        if not all_files and not notebook_files:
            console.print_error(
                "No Python files or Jupyter notebooks found",
                f"No .py or .ipynb files found in: {', '.join(args.paths)}",
                suggestions=[
                    "Check that you're in the right directory",
                    "Use 'pyguard scan path/to/code' to specify a different path",
                    "Check exclude patterns - you may be excluding too much",
                    f"Current exclude patterns: {', '.join(exclude_patterns)}",
                ],
            )
            return 1

        # Print file count
        total_files = len(all_files) + len(notebook_files)
        cli.ui.print_welcome(total_files)

        # Run analysis (scan only, no fixes)
        results = cli.run_full_analysis(all_files, create_backup=False, fix=False)

        # Analyze notebooks if any
        if notebook_files:
            notebook_results = cli.analyze_notebooks(notebook_files)
            results["notebooks"] = notebook_results

        # Print results
        cli.print_results(results, generate_html=not args.no_html, generate_sarif=args.sarif)

        # Export JSON if requested
        if args.json:
            import json

            json_path = Path(args.json)
            with json_path.open("w") as f:
                json.dump(results, f, indent=2, default=str)
            console.console.print(f"[green]✓ JSON report saved:[/green] {json_path}")

        # Return exit code based on findings
        if config.security.enabled and results.get("security_issues", 0) > 0:
            return 1

        return 0
