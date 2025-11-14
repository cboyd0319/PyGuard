"""PyGuard init command - Initialize configuration."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt

from pyguard.lib.config import PyGuardConfig


class InitCommand:
    """Initialize PyGuard configuration."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add init command parser."""
        parser = subparsers.add_parser(
            "init",
            help="Initialize PyGuard configuration",
            description="Create a .pyguard.toml configuration file with smart defaults",
        )
        parser.add_argument(
            "--interactive",
            "-i",
            action="store_true",
            help="Interactive mode with prompts",
        )
        parser.add_argument(
            "--profile",
            choices=["strict", "balanced", "lenient", "security", "formatting"],
            default="balanced",
            help="Configuration profile (default: balanced)",
        )
        parser.add_argument(
            "--force",
            "-f",
            action="store_true",
            help="Overwrite existing .pyguard.toml",
        )
        parser.set_defaults(func=InitCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute init command."""
        console = Console()
        config_path = Path.cwd() / ".pyguard.toml"

        # Check if config already exists
        if config_path.exists() and not args.force:
            console.print("[yellow].pyguard.toml already exists![/yellow]")
            console.print("Use --force to overwrite or edit it manually.")
            return 1

        if args.interactive:
            config = InitCommand._interactive_setup(console)
        else:
            config = InitCommand._get_profile_config(args.profile)

        # Write config
        config_path.write_text(config.to_toml())

        console.print(f"[green]✓ Created {config_path}[/green]")
        console.print()
        console.print("[bold]Next steps:[/bold]")
        console.print("  1. Review and customize .pyguard.toml if needed")
        console.print("  2. Run [cyan]pyguard scan[/cyan] to analyze your code")
        console.print("  3. Run [cyan]pyguard fix[/cyan] to automatically fix issues")

        return 0

    @staticmethod
    def _interactive_setup(console: Console) -> PyGuardConfig:
        """Interactive configuration setup."""
        console.print("[bold cyan]Welcome to PyGuard! Let's set up your project.[/bold cyan]")
        console.print()

        # Project type
        console.print("[bold]What type of project is this?[/bold]")
        console.print("  1. Web application (Django, Flask, FastAPI)")
        console.print("  2. Data science / Machine learning")
        console.print("  3. Python library / Package")
        console.print("  4. Scripts / Automation")
        console.print("  5. Other")

        project_type = IntPrompt.ask("Choose option", default=1, choices=["1", "2", "3", "4", "5"])

        # Security level
        console.print()
        console.print("[bold]Security level:[/bold]")
        console.print("  1. Strict   - Maximum security, may have false positives")
        console.print("  2. Balanced - Recommended for most projects")
        console.print("  3. Lenient  - Fewer checks, faster analysis")

        security_level = IntPrompt.ask("Choose option", default=2, choices=["1", "2", "3"])

        # Auto-fix preferences
        console.print()
        auto_fix = Confirm.ask("Automatically fix safe issues?", default=True)

        # Formatting
        use_black = Confirm.ask("Use Black formatter?", default=True)
        use_isort = Confirm.ask("Use isort for import sorting?", default=True)

        # Build config based on responses
        config = PyGuardConfig()

        # Adjust security based on level
        if security_level == 1:  # Strict
            config.security.severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            config.best_practices.max_complexity = 8
        elif security_level == 2:  # Balanced
            config.security.severity_levels = ["HIGH", "MEDIUM", "LOW"]
            config.best_practices.max_complexity = 10
        else:  # Lenient
            config.security.severity_levels = ["HIGH", "MEDIUM"]
            config.best_practices.max_complexity = 15

        # Adjust for project type
        if project_type == 1:  # Web app
            config.security.checks = {
                "sql_injection": True,
                "command_injection": True,
                "xss": True,
                "csrf": True,
                "hardcoded_passwords": True,
            }
        elif project_type == 2:  # Data science
            config.best_practices.check_docstrings = True
            config.formatting.line_length = 120  # Data science often needs longer lines
        elif project_type == 3:  # Library
            config.best_practices.check_docstrings = True
            config.best_practices.check_naming_conventions = True

        config.formatting.use_black = use_black
        config.formatting.use_isort = use_isort

        console.print()
        console.print("[green]✓ Configuration created![/green]")
        console.print()

        return config

    @staticmethod
    def _get_profile_config(profile: str) -> PyGuardConfig:
        """Get configuration for a specific profile."""
        config = PyGuardConfig()

        if profile == "strict":
            config.security.severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            config.best_practices.max_complexity = 8
            config.best_practices.check_docstrings = True
            config.best_practices.check_naming_conventions = True

        elif profile == "balanced":
            config.security.severity_levels = ["HIGH", "MEDIUM", "LOW"]
            config.best_practices.max_complexity = 10

        elif profile == "lenient":
            config.security.severity_levels = ["HIGH", "MEDIUM"]
            config.best_practices.max_complexity = 15
            config.best_practices.check_docstrings = False

        elif profile == "security":
            config.security.severity_levels = ["CRITICAL", "HIGH", "MEDIUM"]
            config.security.checks = {
                "hardcoded_passwords": True,
                "sql_injection": True,
                "command_injection": True,
                "eval_exec_usage": True,
                "weak_crypto": True,
                "path_traversal": True,
                "xxe": True,
                "deserialization": True,
            }
            config.formatting.use_black = False
            config.formatting.use_isort = False

        elif profile == "formatting":
            config.security.enabled = False
            config.best_practices.check_docstrings = False
            config.formatting.use_black = True
            config.formatting.use_isort = True

        return config
