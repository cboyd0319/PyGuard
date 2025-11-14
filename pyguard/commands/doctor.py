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

        # Notebook support (ONLY optional dependency)
        notebook_deps = [
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

        # Check notebook dependencies
        for name, import_name, required in notebook_deps:
            status, version = DoctorCommand._check_python_package(import_name)
            if status:
                table.add_row(name, "[green]✓[/green]", version, "Notebook support")
            else:
                table.add_row(
                    name,
                    "[dim]○[/dim]",
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
            console.print("[bold green]✓ PyGuard is ready to use![/bold green]")
            console.print()
            console.print("[bold]PyGuard is 100% standalone:[/bold]")
            console.print("  ✓ Core dependencies installed")
            console.print("  ✓ Built-in AST-based security scanning (1,230+ checks)")
            console.print("  ✓ Built-in auto-fix capabilities (199+ fixes)")
            console.print("  ✓ Built-in code formatting")
            console.print("  ✓ No external tools required!")
            console.print()
            console.print("[bold]Optional (Jupyter notebooks only):[/bold]")
            console.print("  • [cyan]pip install nbformat nbclient[/cyan] - for .ipynb analysis")
            console.print()
            console.print("[bold]Next steps:[/bold]")
            console.print("  1. Run [cyan]pyguard init[/cyan] to create configuration")
            console.print("  2. Run [cyan]pyguard scan .[/cyan] to analyze your code")
            console.print("  3. Run [cyan]pyguard fix .[/cyan] to automatically fix issues")
            return 0
        else:
            console.print("[bold red]✗ Some required dependencies are missing[/bold red]")
            console.print("Install missing dependencies and run [cyan]pyguard doctor[/cyan] again")
            return 1

    @staticmethod
    def _check_python_package(package_name: str) -> tuple[bool, str]:
        """Check if a Python package is installed."""
        try:
            # Use importlib.metadata for version checking (standard library)
            from importlib.metadata import version as get_version

            version_str = get_version(package_name)
            return True, version_str
        except Exception:
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
