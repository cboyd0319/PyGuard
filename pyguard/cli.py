"""
PyGuard CLI - Main entry point for PyGuard QA and Auto-Fix Tool.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from pyguard.lib.core import BackupManager, DiffGenerator, FileOperations, PyGuardLogger
from pyguard.lib.security import SecurityFixer
from pyguard.lib.best_practices import BestPracticesFixer, NamingConventionFixer
from pyguard.lib.formatting import FormattingFixer, WhitespaceFixer


class PyGuardCLI:
    """Main PyGuard CLI application."""

    def __init__(self):
        """Initialize PyGuard CLI."""
        self.logger = PyGuardLogger()
        self.backup_manager = BackupManager()
        self.file_ops = FileOperations()
        self.diff_generator = DiffGenerator()

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

    def run_full_analysis(self, files: List[Path], create_backup: bool = True, fix: bool = True) -> dict:
        """
        Run full analysis and fixes on files.

        Args:
            files: List of Python files to analyze
            create_backup: Whether to create backups
            fix: Whether to apply fixes

        Returns:
            Dictionary with comprehensive results
        """
        results = {
            "total_files": len(files),
            "security": {},
            "best_practices": {},
            "formatting": {},
        }

        self.logger.info(f"Starting full analysis of {len(files)} files...")

        if fix:
            # Run security fixes
            self.logger.info("Running security fixes...")
            results["security"] = self.run_security_fixes(files, create_backup)

            # Run best practices fixes
            self.logger.info("Running best practices fixes...")
            results["best_practices"] = self.run_best_practices_fixes(files, create_backup)

            # Run formatting
            self.logger.info("Running formatting...")
            results["formatting"] = self.run_formatting(files, create_backup)

        else:
            # Just scan for issues
            self.logger.info("Scanning for issues (no fixes will be applied)...")
            security_issues = []
            for file_path in files:
                issues = self.security_fixer.scan_file_for_issues(file_path)
                security_issues.extend(issues)
            
            results["security"] = {"issues_found": len(security_issues), "issues": security_issues}

        return results

    def print_results(self, results: dict) -> None:
        """
        Print formatted results.

        Args:
            results: Results dictionary
        """
        print("\n" + "=" * 60)
        print("PyGuard Analysis Results")
        print("=" * 60)
        
        if "security" in results:
            print("\n🔒 Security:")
            if "fixed" in results["security"]:
                print(f"   Files fixed: {results['security']['fixed']}/{results['security']['total']}")
                print(f"   Fixes applied: {len(results['security']['fixes'])}")
            elif "issues_found" in results["security"]:
                print(f"   Issues found: {results['security']['issues_found']}")
        
        if "best_practices" in results:
            print("\n✨ Best Practices:")
            print(f"   Files fixed: {results['best_practices']['fixed']}/{results['best_practices']['total']}")
            print(f"   Fixes applied: {len(results['best_practices']['fixes'])}")
        
        if "formatting" in results:
            print("\n🎨 Formatting:")
            print(f"   Files formatted: {results['formatting']['formatted']}/{results['formatting']['total']}")
        
        print("\n" + "=" * 60)
        print(f"✅ Analysis complete! Check logs/pyguard.jsonl for details.")
        print("=" * 60 + "\n")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PyGuard - Python QA and Auto-Fix Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        print("Error: No Python files found to analyze.")
        sys.exit(1)

    print(f"\n🐍 PyGuard - Found {len(all_files)} Python files to analyze\n")

    # Run analysis based on flags
    create_backup = not args.no_backup
    fix = not args.scan_only

    if args.security_only:
        results = {"security": cli.run_security_fixes(all_files, create_backup)}
    elif args.formatting_only:
        results = {"formatting": cli.run_formatting(
            all_files,
            create_backup,
            use_black=not args.no_black,
            use_isort=not args.no_isort,
        )}
    elif args.best_practices_only:
        results = {"best_practices": cli.run_best_practices_fixes(all_files, create_backup)}
    else:
        # Run full analysis
        results = cli.run_full_analysis(all_files, create_backup, fix)

    # Print results
    cli.print_results(results)


if __name__ == "__main__":
    main()
