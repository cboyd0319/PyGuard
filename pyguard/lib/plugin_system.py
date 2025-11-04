"""
Plugin System for PyGuard.

Allows users to extend PyGuard with custom plugins that can define
security rules, code quality checks, and auto-fixes.
"""

import ast
import importlib.util
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from pyguard.lib.custom_rules import CustomRule, CustomRuleEngine, RuleViolation


@dataclass
class PluginMetadata:
    """Metadata for a PyGuard plugin."""

    name: str
    version: str
    author: str
    description: str
    plugin_id: str
    enabled: bool = True
    dependencies: list[str] = field(default_factory=list)


class PluginInterface:
    """
    Base interface for PyGuard plugins.

    Plugins should inherit from this class and implement the desired hooks.
    """

    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.

        Returns:
            PluginMetadata instance
        """
        raise NotImplementedError("Plugins must implement get_metadata()")

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """
        Register custom rules with the engine.

        Args:
            engine: CustomRuleEngine to register rules with
        """
        pass

    def on_enable(self) -> None:
        """Called when the plugin is enabled."""
        pass

    def on_disable(self) -> None:
        """Called when the plugin is disabled."""
        pass

    def on_file_analyzed(self, file_path: Path, violations: list[RuleViolation]) -> None:
        """
        Called after a file is analyzed.

        Args:
            file_path: Path to analyzed file
            violations: List of violations found
        """
        pass


@dataclass
class PluginInfo:
    """Information about a loaded plugin."""

    metadata: PluginMetadata
    instance: PluginInterface
    module_path: Path
    loaded: bool = True


class PluginManager:
    """
    Manages PyGuard plugins.

    Handles plugin discovery, loading, lifecycle, and execution.
    """

    def __init__(self, rule_engine: CustomRuleEngine | None = None):
        """
        Initialize the plugin manager.

        Args:
            rule_engine: Optional CustomRuleEngine for rule registration
        """
        self.plugins: dict[str, PluginInfo] = {}
        self.rule_engine = rule_engine or CustomRuleEngine()
        self.plugin_paths: list[Path] = []

    def add_plugin_path(self, path: Path) -> None:
        """
        Add a directory to search for plugins.

        Args:
            path: Directory path containing plugins
        """
        if path.is_dir() and path not in self.plugin_paths:
            self.plugin_paths.append(path)

    def discover_plugins(self, plugin_dir: Path) -> list[Path]:
        """
        Discover plugin files in a directory.

        Plugins must follow naming conventions:
        - Start with 'plugin_' (e.g., plugin_example.py)
        - Match pattern '<word>_plugin.py' where <word> is alphanumeric

        Args:
            plugin_dir: Directory to search

        Returns:
            List of plugin file paths
        """
        if not plugin_dir.is_dir():
            return []

        plugin_files = []
        import re

        # Pattern: either 'plugin_*.py' or '<word>_plugin.py' where word is alphanumeric
        pattern = re.compile(r"^(plugin_\w+|[a-zA-Z0-9]+_plugin)\.py$")

        for file_path in plugin_dir.glob("*.py"):
            if pattern.match(file_path.name):
                plugin_files.append(file_path)

        return plugin_files

    def load_plugin(self, plugin_path: Path) -> PluginInfo | None:
        """
        Load a plugin from a file.

        Args:
            plugin_path: Path to plugin file

        Returns:
            PluginInfo if successful, None otherwise
        """
        try:
            # Load module
            spec = importlib.util.spec_from_file_location(
                f"pyguard_plugin_{plugin_path.stem}", plugin_path
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Find plugin class (must inherit from PluginInterface)
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, PluginInterface)
                    and obj is not PluginInterface
                    and obj.__module__ == module.__name__
                ):
                    plugin_class = obj
                    break

            if plugin_class is None:
                return None

            # Instantiate plugin
            plugin_instance = plugin_class()
            metadata = plugin_instance.get_metadata()

            # Register rules
            plugin_instance.register_rules(self.rule_engine)

            # Call on_enable hook
            plugin_instance.on_enable()

            plugin_info = PluginInfo(
                metadata=metadata,
                instance=plugin_instance,
                module_path=plugin_path,
                loaded=True,
            )

            self.plugins[metadata.plugin_id] = plugin_info
            return plugin_info

        except Exception as e:
            # Log error but don't crash
            print(f"Failed to load plugin {plugin_path}: {e}")
            return None

    def load_plugins_from_directory(self, plugin_dir: Path) -> int:
        """
        Load all plugins from a directory.

        Args:
            plugin_dir: Directory containing plugins

        Returns:
            Number of plugins successfully loaded
        """
        plugin_files = self.discover_plugins(plugin_dir)
        loaded_count = 0

        for plugin_file in plugin_files:
            if self.load_plugin(plugin_file):
                loaded_count += 1

        return loaded_count

    def get_plugin(self, plugin_id: str) -> PluginInfo | None:
        """
        Get a loaded plugin by ID.

        Args:
            plugin_id: Plugin identifier

        Returns:
            PluginInfo if found, None otherwise
        """
        return self.plugins.get(plugin_id)

    def list_plugins(self) -> list[PluginInfo]:
        """
        Get list of all loaded plugins.

        Returns:
            List of PluginInfo instances
        """
        return list(self.plugins.values())

    def enable_plugin(self, plugin_id: str) -> bool:
        """
        Enable a plugin.

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if successful, False otherwise
        """
        plugin = self.plugins.get(plugin_id)
        if plugin and not plugin.metadata.enabled:
            plugin.metadata.enabled = True
            plugin.instance.on_enable()
            # Re-register rules
            plugin.instance.register_rules(self.rule_engine)
            return True
        return False

    def disable_plugin(self, plugin_id: str) -> bool:
        """
        Disable a plugin.

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if successful, False otherwise
        """
        plugin = self.plugins.get(plugin_id)
        if plugin and plugin.metadata.enabled:
            plugin.metadata.enabled = False
            plugin.instance.on_disable()
            # Disable all rules from this plugin
            # Note: We'd need to track which rules came from which plugin
            return True
        return False

    def unload_plugin(self, plugin_id: str) -> bool:
        """
        Unload a plugin.

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if successful, False otherwise
        """
        plugin = self.plugins.get(plugin_id)
        if plugin:
            if plugin.metadata.enabled:
                self.disable_plugin(plugin_id)
            del self.plugins[plugin_id]
            return True
        return False

    def reload_plugin(self, plugin_id: str) -> bool:
        """
        Reload a plugin.

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if successful, False otherwise
        """
        plugin = self.plugins.get(plugin_id)
        if plugin:
            module_path = plugin.module_path
            self.unload_plugin(plugin_id)
            return self.load_plugin(module_path) is not None
        return False

    def notify_file_analyzed(
        self, file_path: Path, violations: list[RuleViolation]
    ) -> None:
        """
        Notify all enabled plugins that a file was analyzed.

        Args:
            file_path: Path to analyzed file
            violations: List of violations found
        """
        for plugin in self.plugins.values():
            if plugin.metadata.enabled:
                try:
                    plugin.instance.on_file_analyzed(file_path, violations)
                except Exception as e:
                    # Log but don't crash
                    print(f"Plugin {plugin.metadata.plugin_id} error: {e}")


# Example plugin for demonstration
class ExampleSecurityPlugin(PluginInterface):
    """
    Example security plugin demonstrating the plugin interface.

    This plugin adds a rule to detect hardcoded API keys.
    """

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="Example Security Plugin",
            version="1.0.0",
            author="PyGuard Team",
            description="Detects hardcoded API keys and secrets",
            plugin_id="example_security",
        )

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """Register security rules."""
        # Regex rule to detect API keys
        engine.add_regex_rule(
            rule_id="PLUGIN_EXAMPLE_001",
            name="Hardcoded API Key",
            pattern=r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']',
            severity="HIGH",
            category="Security",
            description="Hardcoded API key detected",
            suggestion="Use environment variables or a secrets manager",
        )

        # AST rule to detect eval() usage
        def check_eval_usage(tree: ast.AST) -> list[int]:
            """Detect eval() function calls."""
            lines = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "eval":
                        lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="PLUGIN_EXAMPLE_002",
            name="Dangerous eval() Usage",
            checker=check_eval_usage,
            severity="CRITICAL",
            category="Security",
            description="Usage of eval() can lead to code injection",
            suggestion="Use ast.literal_eval() for safe evaluation",
        )

    def on_enable(self) -> None:
        """Called when plugin is enabled."""
        print(f"[{self.get_metadata().name}] Enabled")

    def on_disable(self) -> None:
        """Called when plugin is disabled."""
        print(f"[{self.get_metadata().name}] Disabled")


def create_plugin_manager(
    plugin_dirs: list[str | Path] | None = None,
) -> PluginManager:
    """
    Create a plugin manager and load plugins from specified directories.

    Args:
        plugin_dirs: List of directories to search for plugins

    Returns:
        Configured PluginManager
    """
    manager = PluginManager()

    if plugin_dirs:
        for plugin_dir in plugin_dirs:
            path = Path(plugin_dir)
            if path.is_dir():
                manager.load_plugins_from_directory(path)

    return manager
