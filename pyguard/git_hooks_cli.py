"""CLI for PyGuard git hooks management."""

import argparse
import sys
from pathlib import Path

from pyguard import __version__
from pyguard.lib.core import PyGuardLogger
from pyguard.lib.git_hooks import GitHooksManager


def main():
    """Main CLI entry point for git hooks management."""

    parser = argparse.ArgumentParser(
        description="PyGuard Git Hooks Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"PyGuard {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Install command
    install_parser = subparsers.add_parser("install", help="Install PyGuard as a git hook")
    install_parser.add_argument(
        "--type",
        choices=["pre-commit", "pre-push"],
        default="pre-commit",
        help="Type of git hook to install (default: pre-commit)",
    )
    install_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing hook if present"
    )
    install_parser.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Path to git repository (default: current directory)",
    )

    # Uninstall command
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall PyGuard git hook")
    uninstall_parser.add_argument(
        "--type",
        choices=["pre-commit", "pre-push"],
        default="pre-commit",
        help="Type of git hook to uninstall (default: pre-commit)",
    )
    uninstall_parser.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Path to git repository (default: current directory)",
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List all installed git hooks")
    list_parser.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Path to git repository (default: current directory)",
    )

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate", help="Validate PyGuard git hook installation"
    )
    validate_parser.add_argument(
        "--type",
        choices=["pre-commit", "pre-push"],
        default="pre-commit",
        help="Type of git hook to validate (default: pre-commit)",
    )
    validate_parser.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Path to git repository (default: current directory)",
    )

    # Test command
    test_parser = subparsers.add_parser("test", help="Test PyGuard git hook")
    test_parser.add_argument(
        "--type",
        choices=["pre-commit", "pre-push"],
        default="pre-commit",
        help="Type of git hook to test (default: pre-commit)",
    )
    test_parser.add_argument(
        "--path",
        type=Path,
        default=None,
        help="Path to git repository (default: current directory)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    logger = PyGuardLogger()
    manager = GitHooksManager(args.path)

    # Execute command
    if args.command == "install":
        try:
            success = manager.install_hook(args.type, args.force)
            if success:
                logger.info(f"[OK] Successfully installed {args.type} hook", category="GitHooks")
                sys.exit(0)
            else:
                logger.error(f"[X] Failed to install {args.type} hook", category="GitHooks")
                sys.exit(1)
        except ValueError as e:
            logger.error(str(e), category="GitHooks")
            sys.exit(1)

    elif args.command == "uninstall":
        success = manager.uninstall_hook(args.type)
        if success:
            logger.info(f"[OK] Successfully uninstalled {args.type} hook", category="GitHooks")
            sys.exit(0)
        else:
            logger.error(f"[X] Failed to uninstall {args.type} hook", category="GitHooks")
            sys.exit(1)

    elif args.command == "list":
        hooks = manager.list_hooks()
        if not hooks:
            logger.info("No git hooks installed", category="GitHooks")
        else:
            logger.info(f"Found {len(hooks)} installed hooks:", category="GitHooks")
            for hook in hooks:
                status = "[OK]" if hook["pyguard"] else "○"
                exec_status = "executable" if hook["executable"] else "not executable"
                logger.info(
                    f"  {status} {hook['name']} ({exec_status})",
                    category="GitHooks",
                    details={"path": hook["path"]},
                )
        sys.exit(0)

    elif args.command == "validate":
        result = manager.validate_hook(args.type)
        if result["valid"]:
            logger.info(f"[OK] {args.type} hook is valid and ready to use", category="GitHooks")
            sys.exit(0)
        else:
            logger.error(
                f"[X] {args.type} hook validation failed",
                category="GitHooks",
                details={"issues": result["issues"]},
            )
            sys.exit(1)

    elif args.command == "test":
        success = manager.test_hook(args.type)
        if success:
            logger.info(f"[OK] {args.type} hook test passed", category="GitHooks")
            sys.exit(0)
        else:
            logger.error(f"[X] {args.type} hook test failed", category="GitHooks")
            sys.exit(1)


if __name__ == "__main__":
    main()
