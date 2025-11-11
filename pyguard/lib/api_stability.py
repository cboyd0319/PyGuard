"""
API Stability Guarantees and Deprecation Management.

Provides framework for maintaining API stability through semantic versioning,
deprecation warnings, and compatibility tracking.

Features:
- API version tracking and compatibility checking
- Deprecation warnings with migration paths
- Stable API decorators for public interfaces
- Breaking change detection
- Migration guide generation
- Compatibility matrix for versions

Use Cases:
- Ensure backward compatibility across versions
- Provide clear deprecation warnings to users
- Track and document API changes
- Generate migration guides automatically
- Enable users to test compatibility before upgrading
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
import functools
import inspect
import logging
from typing import Any
import warnings

from packaging import version as pkg_version

logger = logging.getLogger(__name__)


class StabilityLevel(Enum):
    """API stability levels."""
    STABLE = "stable"  # Guaranteed stable, breaking changes require major version bump
    BETA = "beta"  # Generally stable, may change in minor versions with warnings
    ALPHA = "alpha"  # Experimental, may change at any time
    DEPRECATED = "deprecated"  # Scheduled for removal
    INTERNAL = "internal"  # Private API, no stability guarantees


class DeprecationPhase(Enum):
    """Phases of deprecation lifecycle."""
    PENDING = "pending"  # Announced but no warnings yet
    WARNING = "warning"  # Showing deprecation warnings
    ERROR = "error"  # Raising errors when used
    REMOVED = "removed"  # Completely removed


@dataclass
class APIVersion:
    """Represents an API version with semantic versioning."""
    major: int
    minor: int
    patch: int

    @classmethod
    def from_string(cls, version_str: str) -> 'APIVersion':
        """Parse version string (e.g., "1.2.3")."""
        parsed = pkg_version.parse(version_str)
        if isinstance(parsed, pkg_version.Version):
            return cls(
                major=parsed.major,
                minor=parsed.minor,
                patch=parsed.micro,
            )
        raise ValueError(f"Invalid version string: {version_str}")

    def __str__(self) -> str:
        """Convert to string."""
        return f"{self.major}.{self.minor}.{self.patch}"

    def __lt__(self, other: 'APIVersion') -> bool:
        """Compare versions."""
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __le__(self, other: 'APIVersion') -> bool:
        """Compare versions."""
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, APIVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __hash__(self) -> int:
        """Make the object hashable."""
        return hash((self.major, self.minor, self.patch))

    def is_compatible_with(self, other: 'APIVersion') -> bool:
        """
        Check if this version is compatible with another.

        Compatible if major version matches and this minor >= other minor.
        """
        return self.major == other.major and self.minor >= other.minor


@dataclass
class DeprecationInfo:
    """Information about a deprecated API."""
    name: str
    deprecated_in: APIVersion
    removal_in: APIVersion
    replacement: str | None = None
    reason: str | None = None
    migration_guide: str | None = None
    phase: DeprecationPhase = DeprecationPhase.WARNING

    def get_warning_message(self) -> str:
        """Generate deprecation warning message."""
        msg = f"{self.name} is deprecated since version {self.deprecated_in}"
        if self.removal_in:
            msg += f" and will be removed in version {self.removal_in}"
        if self.replacement:
            msg += f". Use {self.replacement} instead"
        if self.reason:
            msg += f". Reason: {self.reason}"
        if self.migration_guide:
            msg += f". See migration guide: {self.migration_guide}"
        return msg


@dataclass
class APIRegistration:
    """Registration of a stable API."""
    name: str
    stability_level: StabilityLevel
    introduced_in: APIVersion
    signature: str  # Function signature for tracking
    module: str
    deprecation_info: DeprecationInfo | None = None
    breaking_changes: list[str] = field(default_factory=list)

    def is_stable(self) -> bool:
        """Check if API is stable."""
        return self.stability_level == StabilityLevel.STABLE

    def is_deprecated(self) -> bool:
        """Check if API is deprecated."""
        return self.stability_level == StabilityLevel.DEPRECATED


class APIRegistry:
    """
    Central registry for tracking API stability and deprecations.

    Maintains catalog of public APIs with their stability levels,
    deprecation status, and version information.
    """

    def __init__(self, current_version: str = "0.8.0"):
        """
        Initialize API registry.

        Args:
            current_version: Current PyGuard version
        """
        self.current_version = APIVersion.from_string(current_version)
        self.apis: dict[str, APIRegistration] = {}
        self.deprecations: dict[str, DeprecationInfo] = {}
        logger.info(f"API registry initialized for version {self.current_version}")

    def register_api(
        self,
        name: str,
        stability_level: StabilityLevel,
        introduced_in: str,
        func: Callable | None = None,
    ) -> None:
        """
        Register an API with stability guarantees.

        Args:
            name: API name (fully qualified)
            stability_level: Stability level
            introduced_in: Version when introduced
            func: Function to extract signature from
        """
        signature = ""
        module = ""

        if func:
            signature = str(inspect.signature(func))
            module = func.__module__

        registration = APIRegistration(
            name=name,
            stability_level=stability_level,
            introduced_in=APIVersion.from_string(introduced_in),
            signature=signature,
            module=module,
        )

        self.apis[name] = registration
        logger.debug(f"Registered API: {name} ({stability_level.value})")

    def deprecate_api(  # noqa: PLR0913 - API deprecation requires many parameters for full context
        self,
        name: str,
        deprecated_in: str,
        removal_in: str,
        replacement: str | None = None,
        reason: str | None = None,
        migration_guide: str | None = None,
    ) -> None:
        """
        Mark an API as deprecated.

        Args:
            name: API name
            deprecated_in: Version when deprecated
            removal_in: Version when removed
            replacement: Replacement API
            reason: Deprecation reason
            migration_guide: URL to migration guide
        """
        deprecation = DeprecationInfo(
            name=name,
            deprecated_in=APIVersion.from_string(deprecated_in),
            removal_in=APIVersion.from_string(removal_in),
            replacement=replacement,
            reason=reason,
            migration_guide=migration_guide,
        )

        self.deprecations[name] = deprecation

        # Update API registration if exists
        if name in self.apis:
            self.apis[name].stability_level = StabilityLevel.DEPRECATED
            self.apis[name].deprecation_info = deprecation

        logger.info(f"Deprecated API: {name} (removal in {removal_in})")

    def check_compatibility(
        self,
        target_version: str,
    ) -> dict[str, Any]:
        """
        Check compatibility with a target version.

        Args:
            target_version: Version to check compatibility with

        Returns:
            Compatibility report
        """
        target = APIVersion.from_string(target_version)

        incompatible_apis = []
        removed_apis = []
        deprecated_apis = []

        for name, api in self.apis.items():
            # Check if API is removed in target version
            if api.deprecation_info:
                if target >= api.deprecation_info.removal_in:
                    removed_apis.append({
                        'name': name,
                        'removed_in': str(api.deprecation_info.removal_in),
                        'replacement': api.deprecation_info.replacement,
                    })
                elif target >= api.deprecation_info.deprecated_in:
                    deprecated_apis.append({
                        'name': name,
                        'deprecated_in': str(api.deprecation_info.deprecated_in),
                        'removal_in': str(api.deprecation_info.removal_in),
                        'replacement': api.deprecation_info.replacement,
                    })

            # Check if API introduced after target
            if api.introduced_in > target:
                incompatible_apis.append({
                    'name': name,
                    'introduced_in': str(api.introduced_in),
                    'reason': f"API not available in version {target}",
                })

        return {
            'current_version': str(self.current_version),
            'target_version': str(target),
            'compatible': len(removed_apis) == 0 and len(incompatible_apis) == 0,
            'removed_apis': removed_apis,
            'deprecated_apis': deprecated_apis,
            'incompatible_apis': incompatible_apis,
        }

    def get_migration_guide(
        self,
        from_version: str,
        to_version: str,
    ) -> dict[str, Any]:
        """
        Generate migration guide between versions.

        Args:
            from_version: Starting version
            to_version: Target version

        Returns:
            Migration guide with required changes
        """
        from_ver = APIVersion.from_string(from_version)
        to_ver = APIVersion.from_string(to_version)

        changes_required = []
        deprecation_warnings = []
        new_features = []

        for name, api in self.apis.items():
            # APIs deprecated in range
            if api.deprecation_info:
                deprecated = api.deprecation_info.deprecated_in
                if from_ver < deprecated <= to_ver:
                    deprecation_warnings.append({
                        'api': name,
                        'deprecated_in': str(deprecated),
                        'removal_in': str(api.deprecation_info.removal_in),
                        'replacement': api.deprecation_info.replacement,
                        'migration_guide': api.deprecation_info.migration_guide,
                    })

                # APIs removed in range
                removal = api.deprecation_info.removal_in
                if from_ver < removal <= to_ver:
                    changes_required.append({
                        'api': name,
                        'removed_in': str(removal),
                        'replacement': api.deprecation_info.replacement,
                        'action': 'REQUIRED: Update code before upgrading',
                    })

            # New APIs in range
            if from_ver < api.introduced_in <= to_ver:
                new_features.append({
                    'api': name,
                    'introduced_in': str(api.introduced_in),
                    'stability': api.stability_level.value,
                })

        return {
            'from_version': from_version,
            'to_version': to_version,
            'is_major_upgrade': to_ver.major > from_ver.major,
            'is_minor_upgrade': to_ver.minor > from_ver.minor and to_ver.major == from_ver.major,
            'changes_required': changes_required,
            'deprecation_warnings': deprecation_warnings,
            'new_features': new_features,
            'breaking_changes_count': len(changes_required),
        }


# Global registry instance
_global_registry = APIRegistry()


def get_registry() -> APIRegistry:
    """Get the global API registry."""
    return _global_registry


def stable_api(
    introduced_in: str,
    stability_level: StabilityLevel = StabilityLevel.STABLE,
) -> Callable:
    """
    Decorator to mark a function/class as part of the stable API.

    Args:
        introduced_in: Version when this API was introduced
        stability_level: Stability level

    Example:
        @stable_api(introduced_in="1.0.0")
        def my_public_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        # Register API
        name = f"{func.__module__}.{func.__qualname__}"
        _global_registry.register_api(
            name=name,
            stability_level=stability_level,
            introduced_in=introduced_in,
            func=func,
        )

        # Add metadata to function
        func.__api_stability__ = {'introduced_in': introduced_in, 'stability_level': stability_level.value}  # type: ignore[attr-defined]

        return func

    return decorator


def deprecated(
    deprecated_in: str,
    removal_in: str,
    replacement: str | None = None,
    reason: str | None = None,
    migration_guide: str | None = None,
) -> Callable:
    """
    Decorator to mark a function/class as deprecated.

    Args:
        deprecated_in: Version when deprecated
        removal_in: Version when removed
        replacement: Replacement API
        reason: Deprecation reason
        migration_guide: URL to migration guide

    Example:
        @deprecated(
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            replacement="new_function",
        )
        def old_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        name = f"{func.__module__}.{func.__qualname__}"

        # Register deprecation
        _global_registry.deprecate_api(
            name=name,
            deprecated_in=deprecated_in,
            removal_in=removal_in,
            replacement=replacement,
            reason=reason,
            migration_guide=migration_guide,
        )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Show deprecation warning
            deprecation_info = _global_registry.deprecations.get(name)
            if deprecation_info:
                warnings.warn(
                    deprecation_info.get_warning_message(),
                    DeprecationWarning,
                    stacklevel=2,
                )

            return func(*args, **kwargs)

        # Add metadata
        wrapper.__deprecated__ = {'deprecated_in': deprecated_in, 'removal_in': removal_in, 'replacement': replacement}  # type: ignore[attr-defined]

        return wrapper

    return decorator


def check_api_compatibility(target_version: str) -> dict[str, Any]:
    """
    Check if code is compatible with a target version.

    Args:
        target_version: Version to check compatibility with

    Returns:
        Compatibility report
    """
    return _global_registry.check_compatibility(target_version)


def generate_migration_guide(
    from_version: str,
    to_version: str,
) -> dict[str, Any]:
    """
    Generate migration guide between versions.

    Args:
        from_version: Starting version
        to_version: Target version

    Returns:
        Migration guide
    """
    return _global_registry.get_migration_guide(from_version, to_version)


# Pre-register core PyGuard APIs
def register_core_apis() -> None:
    """Register core PyGuard APIs with stability guarantees."""
    registry = get_registry()

    # Core scanning APIs (stable since 0.6.0)
    registry.register_api(
        "pyguard.api.scan_file",
        StabilityLevel.STABLE,
        "0.6.0",
    )

    registry.register_api(
        "pyguard.api.scan_directory",
        StabilityLevel.STABLE,
        "0.6.0",
    )

    # Configuration APIs (stable since 0.6.0)
    registry.register_api(
        "pyguard.api.load_config",
        StabilityLevel.STABLE,
        "0.6.0",
    )

    # Reporting APIs (stable since 0.6.0)
    registry.register_api(
        "pyguard.api.generate_report",
        StabilityLevel.STABLE,
        "0.6.0",
    )

    # Auto-fix APIs (stable since 0.6.0)
    registry.register_api(
        "pyguard.api.fix_issues",
        StabilityLevel.STABLE,
        "0.6.0",
    )

    # JSON-RPC API (beta since 0.8.0)
    registry.register_api(
        "pyguard.lib.jsonrpc_api.JSONRPCServer",
        StabilityLevel.BETA,
        "0.8.0",
    )

    # Webhook API (beta since 0.8.0)
    registry.register_api(
        "pyguard.lib.webhook_api.WebhookServer",
        StabilityLevel.BETA,
        "0.8.0",
    )

    # Plugin system (beta since 0.8.0)
    registry.register_api(
        "pyguard.lib.plugin_system.PluginManager",
        StabilityLevel.BETA,
        "0.8.0",
    )

    logger.info("Core APIs registered with stability guarantees")


# Initialize core APIs on module import
register_core_apis()
