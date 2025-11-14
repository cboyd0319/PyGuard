"""PyGuard validate-config command - Validate configuration file."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from pyguard.lib.config import PyGuardConfig


class ValidateConfigCommand:
    """Validate .pyguard.toml configuration file."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add validate-config command parser."""
        parser = subparsers.add_parser(
            "validate-config",
            help="Validate configuration file",
            description="Check that .pyguard.toml is valid and show current settings",
        )
        parser.add_argument(
            "--config",
            "-c",
            type=str,
            help="Path to config file (default: .pyguard.toml)",
        )
        parser.set_defaults(func=ValidateConfigCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute validate-config command."""
        console = Console()

        # Determine config path
        config_path = Path(args.config) if args.config else Path.cwd() / ".pyguard.toml"

        if not config_path.exists():
            console.print(f"[yellow]Config file not found: {config_path}[/yellow]")
            console.print()
            console.print("Create one with: [cyan]pyguard init[/cyan]")
            return 1

        console.print(f"[bold]Validating:[/bold] {config_path}")
        console.print()

        # Try to load config
        try:
            config = PyGuardConfig.from_file(config_path)
        except FileNotFoundError:
            console.print("[red]✗ File not found[/red]")
            return 1
        except ValueError as e:
            console.print("[red]✗ Invalid TOML syntax:[/red]")
            console.print(f"  {e}")
            return 1

        # Validate config
        errors = config.validate()

        if errors:
            console.print("[red]✗ Configuration has errors:[/red]")
            console.print()
            for error in errors:
                console.print(f"  • {error}")
            console.print()
            console.print("Fix these errors in your .pyguard.toml file")
            return 1

        # No errors - show current config
        console.print("[green]✓ Configuration is valid![/green]")
        console.print()

        # Display config summary
        console.print("[bold]Current Settings:[/bold]")
        console.print()

        console.print("[cyan]General:[/cyan]")
        console.print(f"  Log level: {config.general.log_level}")
        console.print(f"  Backup directory: {config.general.backup_dir}")
        console.print(f"  Exclude patterns: {', '.join(config.general.exclude_patterns)}")
        console.print()

        console.print("[cyan]Security:[/cyan]")
        console.print(f"  Enabled: {config.security.enabled}")
        console.print(f"  Severity levels: {', '.join(config.security.severity_levels)}")
        if config.security.checks:
            console.print("  Checks:")
            for check, enabled in config.security.checks.items():
                status = "✓" if enabled else "✗"
                console.print(f"    {status} {check}")
        console.print()

        console.print("[cyan]Best Practices:[/cyan]")
        console.print(f"  Check docstrings: {config.best_practices.check_docstrings}")
        console.print(f"  Check naming: {config.best_practices.check_naming_conventions}")
        console.print(f"  Max complexity: {config.best_practices.max_complexity}")
        console.print()

        console.print("[cyan]Formatting:[/cyan]")
        console.print(f"  Line length: {config.formatting.line_length}")
        console.print(f"  Use Black: {config.formatting.use_black}")
        console.print(f"  Use isort: {config.formatting.use_isort}")

        return 0
