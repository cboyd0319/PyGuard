"""PyGuard watch command - Watch files for changes and auto-fix."""

from __future__ import annotations

import argparse
from pathlib import Path

from pyguard.cli import PyGuardCLI
from pyguard.lib.config import PyGuardConfig
from pyguard.lib.ui import EnhancedConsole


class WatchCommand:
    """Watch files for changes and automatically fix issues."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add watch command parser."""
        parser = subparsers.add_parser(
            "watch",
            help="Watch files and auto-fix on changes",
            description="Monitor files for changes and automatically fix issues when files are saved",
        )
        parser.add_argument(
            "paths",
            nargs="*",
            default=["."],
            help="Files or directories to watch (default: current directory)",
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
        parser.set_defaults(func=WatchCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute watch command."""
        console = EnhancedConsole()

        # Load configuration
        config = PyGuardConfig.find_and_load()
        if config:
            console.console.print(f"[dim]Loaded config from {config.config_path}[/dim]")
        else:
            config = PyGuardConfig.get_default_config()

        # Merge config exclude patterns with command-line excludes
        exclude_patterns = list(set(config.general.exclude_patterns + args.exclude))

        console.console.print("[bold cyan]PyGuard Watch Mode[/bold cyan]")
        console.console.print()
        console.console.print(f"Watching: {', '.join(args.paths)}")
        console.console.print(f"Exclude: {', '.join(exclude_patterns)}")
        console.console.print()
        console.console.print("[dim]Press Ctrl+C to stop[/dim]")
        console.console.print()

        # Initialize CLI
        cli = PyGuardCLI(allow_unsafe_fixes=False)

        # Define analyze function for watch mode
        def analyze_file(file_path: Path) -> None:
            """Analyze a single file."""
            console.console.print(f"[cyan]Changed:[/cyan] {file_path}")

            try:
                if args.security_only:
                    cli.run_security_fixes([file_path], create_backup=not args.no_backup)
                elif args.formatting_only:
                    cli.run_formatting([file_path], create_backup=not args.no_backup)
                else:
                    cli.run_full_analysis(
                        [file_path], create_backup=not args.no_backup, fix=True
                    )

                console.console.print("[green]✓ Fixed[/green]")
            except Exception as e:
                console.console.print(f"[red]✗ Error: {e}[/red]")

        # Use existing watch mode implementation
        from pyguard.lib.watch import run_watch_mode

        watch_paths = [Path(p) for p in args.paths]

        try:
            run_watch_mode(watch_paths, analyze_file)
        except KeyboardInterrupt:
            console.console.print()
            console.console.print("[yellow]Watch mode stopped[/yellow]")

        return 0
