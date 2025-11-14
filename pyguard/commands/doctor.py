"""PyGuard doctor command - Verify installation and dependencies."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from pyguard import __version__


class DoctorCommand:
    """Verify PyGuard installation and dependencies."""

    @staticmethod
    def add_parser(subparsers: argparse._SubParsersAction) -> None:
        """Add doctor command parser."""
        parser = subparsers.add_parser(
            "doctor",
            help="Verify installation and dependencies",
            description="Check that PyGuard and all optional dependencies are properly installed",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Show detailed version information",
        )
        parser.set_defaults(func=DoctorCommand.run)

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        """Execute doctor command."""
        console = Console()

        console.print(f"[bold cyan]PyGuard Doctor v{__version__}[/bold cyan]")
        console.print()

        # Check Python version
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        console.print(f"[bold]Python:[/bold] {py_version}")

        if sys.version_info < (3, 11):
            console.print("[red]✗ Python 3.11+ required[/red]")
            return 1
        else:
            console.print("[green]✓ Python version OK[/green]")

        console.print()

        # Create status table
        table = Table(title="Dependency Status", show_header=True)
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Version", style="white")
        table.add_column("Notes", style="yellow")

        # Core dependencies
        core_deps = [
            ("rich", "rich", True),
            ("watchdog", "watchdog", False),
        ]

        # Tool dependencies (optional)
        tool_deps = [
            ("pylint", "pylint", False),
            ("flake8", "flake8", False),
            ("black", "black", False),
            ("isort", "isort", False),
            ("mypy", "mypy", False),
            ("bandit", "bandit", False),
            ("autopep8", "autopep8", False),
            ("pydocstyle", "pydocstyle", False),
            ("safety", "safety", False),
            ("radon", "radon", False),
            ("vulture", "vulture", False),
            ("ruff", "ruff", False),
            ("nbformat", "nbformat", False),
            ("nbclient", "nbclient", False),
        ]

        # System tools
        system_tools = [("ripgrep", "rg", False)]

        all_ok = True

        # Check core dependencies
        for name, import_name, required in core_deps:
            status, version = DoctorCommand._check_python_package(import_name)
            if status:
                table.add_row(name, "[green]✓[/green]", version, "Core dependency")
            else:
                table.add_row(name, "[red]✗[/red]", "Not found", "REQUIRED")
                if required:
                    all_ok = False

        # Check tool dependencies
        for name, import_name, required in tool_deps:
            status, version = DoctorCommand._check_python_package(import_name)
            if status:
                table.add_row(name, "[green]✓[/green]", version, "Optional")
            else:
                table.add_row(
                    name,
                    "[yellow]○[/yellow]",
                    "Not installed",
                    f"pip install {import_name}",
                )

        # Check system tools
        for name, command, required in system_tools:
            status, version = DoctorCommand._check_system_tool(command)
            if status:
                table.add_row(name, "[green]✓[/green]", version, "System tool")
            else:
                table.add_row(
                    name,
                    "[yellow]○[/yellow]",
                    "Not found",
                    "Optional (improves performance)",
                )

        console.print(table)
        console.print()

        # Configuration check
        config_path = Path.cwd() / ".pyguard.toml"
        if config_path.exists():
            console.print(f"[green]✓ Found config:[/green] {config_path}")
        else:
            console.print("[yellow]○ No .pyguard.toml found[/yellow]")
            console.print(f"  Run [cyan]pyguard init[/cyan] to create one")

        console.print()

        # Summary
        if all_ok:
            console.print("[bold green]✓ PyGuard is properly installed![/bold green]")
            console.print()
            console.print("[bold]Next steps:[/bold]")
            console.print("  • Run [cyan]pyguard init[/cyan] to create configuration")
            console.print("  • Run [cyan]pyguard scan .[/cyan] to analyze your code")
            console.print("  • Run [cyan]pyguard fix .[/cyan] to automatically fix issues")
            return 0
        else:
            console.print("[bold red]✗ Some required dependencies are missing[/bold red]")
            console.print("Install missing dependencies and run [cyan]pyguard doctor[/cyan] again")
            return 1

    @staticmethod
    def _check_python_package(package_name: str) -> tuple[bool, str]:
        """Check if a Python package is installed."""
        try:
            if package_name == "rich":
                import rich

                return True, rich.__version__
            elif package_name == "watchdog":
                import watchdog

                return True, watchdog.__version__
            elif package_name == "pylint":
                import pylint

                return True, pylint.__version__
            elif package_name == "flake8":
                import flake8

                return True, flake8.__version__
            elif package_name == "black":
                import black

                return True, black.__version__
            elif package_name == "isort":
                import isort

                return True, isort.__version__
            elif package_name == "mypy":
                import mypy

                return True, mypy.__version__
            elif package_name == "bandit":
                import bandit

                return True, bandit.__version__
            elif package_name == "autopep8":
                import autopep8

                return True, autopep8.__version__
            elif package_name == "pydocstyle":
                import pydocstyle

                return True, pydocstyle.__version__
            elif package_name == "safety":
                import safety

                return True, safety.VERSION
            elif package_name == "radon":
                import radon

                return True, radon.__version__
            elif package_name == "vulture":
                import vulture

                return True, vulture.__version__
            elif package_name == "ruff":
                import ruff

                return True, ruff.__version__
            elif package_name == "nbformat":
                import nbformat

                return True, nbformat.__version__
            elif package_name == "nbclient":
                import nbclient

                return True, nbclient.__version__
            else:
                return False, "Unknown"
        except (ImportError, AttributeError):
            return False, "Not found"

    @staticmethod
    def _check_system_tool(command: str) -> tuple[bool, str]:
        """Check if a system tool is available."""
        tool_path = shutil.which(command)
        if not tool_path:
            return False, "Not found"

        try:
            result = subprocess.run(
                [command, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            version_output = result.stdout.strip() or result.stderr.strip()
            # Extract version number (first line, first word after removing command name)
            version = version_output.split("\n")[0].split()[-1] if version_output else "installed"
            return True, version
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return True, "installed"
