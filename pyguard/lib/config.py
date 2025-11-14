"""
PyGuard Configuration System.

Loads and validates .pyguard.toml configuration files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib
from typing import Any

# Validation constants
MIN_LINE_LENGTH = 50


@dataclass
class SecurityConfig:
    """Security check configuration."""

    enabled: bool = True
    severity_levels: list[str] = field(default_factory=lambda: ["HIGH", "MEDIUM", "LOW"])
    checks: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityConfig:
        """Create SecurityConfig from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            severity_levels=data.get("severity_levels", ["HIGH", "MEDIUM", "LOW"]),
            checks=data.get("checks", {}),
        )


@dataclass
class BestPracticesConfig:
    """Best practices configuration."""

    check_docstrings: bool = True
    check_naming_conventions: bool = True
    max_complexity: int = 10

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BestPracticesConfig:
        """Create BestPracticesConfig from dictionary."""
        return cls(
            check_docstrings=data.get("check_docstrings", True),
            check_naming_conventions=data.get("check_naming_conventions", True),
            max_complexity=data.get("max_complexity", 10),
        )


@dataclass
class FormattingConfig:
    """Formatting configuration."""

    line_length: int = 100
    use_black: bool = True
    use_isort: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FormattingConfig:
        """Create FormattingConfig from dictionary."""
        return cls(
            line_length=data.get("line_length", 100),
            use_black=data.get("use_black", True),
            use_isort=data.get("use_isort", True),
        )


@dataclass
class GeneralConfig:
    """General configuration."""

    log_level: str = "INFO"
    backup_dir: str = ".pyguard_backups"
    exclude_patterns: list[str] = field(
        default_factory=lambda: ["venv/*", ".venv/*", "*.egg-info/*", "build/*", "dist/*"]
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GeneralConfig:
        """Create GeneralConfig from dictionary."""
        return cls(
            log_level=data.get("log_level", "INFO"),
            backup_dir=data.get("backup_dir", ".pyguard_backups"),
            exclude_patterns=data.get(
                "exclude_patterns",
                ["venv/*", ".venv/*", "*.egg-info/*", "build/*", "dist/*"],
            ),
        )


@dataclass
class PyGuardConfig:
    """Complete PyGuard configuration."""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    best_practices: BestPracticesConfig = field(default_factory=BestPracticesConfig)
    formatting: FormattingConfig = field(default_factory=FormattingConfig)
    config_path: Path | None = None

    @classmethod
    def from_file(cls, config_path: Path) -> PyGuardConfig:
        """
        Load configuration from a TOML file.

        Args:
            config_path: Path to .pyguard.toml file

        Returns:
            PyGuardConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config file is invalid
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        try:
            with config_path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"Invalid TOML in config file: {e}") from e

        return cls(
            general=GeneralConfig.from_dict(data.get("general", {})),
            security=SecurityConfig.from_dict(data.get("security", {})),
            best_practices=BestPracticesConfig.from_dict(data.get("best_practices", {})),
            formatting=FormattingConfig.from_dict(data.get("formatting", {})),
            config_path=config_path,
        )

    @classmethod
    def find_and_load(cls, start_path: Path | None = None) -> PyGuardConfig | None:
        """
        Find and load .pyguard.toml from current directory or parents.

        Args:
            start_path: Starting directory (defaults to current directory)

        Returns:
            PyGuardConfig if found, None otherwise
        """
        if start_path is None:
            start_path = Path.cwd()

        # Search current directory and parents
        current = start_path if start_path.is_dir() else start_path.parent

        while True:
            config_file = current / ".pyguard.toml"
            if config_file.exists():
                try:
                    return cls.from_file(config_file)
                except (FileNotFoundError, ValueError):
                    return None

            # Move to parent directory
            parent = current.parent
            if parent == current:  # Reached root
                break
            current = parent

        return None

    @classmethod
    def get_default_config(cls) -> PyGuardConfig:
        """Get default configuration."""
        return cls()

    def to_toml(self) -> str:
        """
        Convert configuration to TOML string.

        Returns:
            TOML string representation
        """
        lines = [
            "[general]",
            f'log_level = "{self.general.log_level}"',
            f'backup_dir = "{self.general.backup_dir}"',
            f"exclude_patterns = {self.general.exclude_patterns!r}",
            "",
            "[security]",
            f"enabled = {str(self.security.enabled).lower()}",
            f"severity_levels = {self.security.severity_levels!r}",
            "",
            "[security.checks]",
        ]

        # Add security checks
        default_checks = {
            "hardcoded_passwords": True,
            "sql_injection": True,
            "command_injection": True,
            "eval_exec_usage": True,
            "weak_crypto": True,
            "path_traversal": True,
        }
        checks = {**default_checks, **self.security.checks}
        for check, enabled in checks.items():
            lines.append(f"{check} = {str(enabled).lower()}")

        lines.extend(
            [
                "",
                "[best_practices]",
                f"check_docstrings = {str(self.best_practices.check_docstrings).lower()}",
                f"check_naming_conventions = {str(self.best_practices.check_naming_conventions).lower()}",
                f"max_complexity = {self.best_practices.max_complexity}",
                "",
                "[formatting]",
                f"line_length = {self.formatting.line_length}",
                f"use_black = {str(self.formatting.use_black).lower()}",
                f"use_isort = {str(self.formatting.use_isort).lower()}",
            ]
        )

        return "\n".join(lines) + "\n"

    def validate(self) -> list[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.general.log_level not in valid_log_levels:
            errors.append(
                f"Invalid log_level: {self.general.log_level}. "
                f"Must be one of: {', '.join(valid_log_levels)}"
            )

        # Validate severity levels
        valid_severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for severity in self.security.severity_levels:
            if severity not in valid_severities:
                errors.append(
                    f"Invalid severity level: {severity}. "
                    f"Must be one of: {', '.join(valid_severities)}"
                )

        # Validate max complexity
        if self.best_practices.max_complexity < 1:
            errors.append("max_complexity must be at least 1")

        # Validate line length
        if self.formatting.line_length < MIN_LINE_LENGTH:
            errors.append(f"line_length must be at least {MIN_LINE_LENGTH}")

        return errors
