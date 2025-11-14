"""Tests for plugin system."""

from pathlib import Path

import pytest

from pyguard.lib.custom_rules import CustomRuleEngine
from pyguard.lib.plugin_system import (
    ExampleSecurityPlugin,
    PluginInfo,
    PluginInterface,
    PluginManager,
    PluginMetadata,
    create_plugin_manager,
)


class TestPluginMetadata:
    """Test PluginMetadata dataclass."""

    def test_create_metadata(self):
        """Test creating plugin metadata."""
        metadata = PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="Test description",
            plugin_id="test_plugin",
        )

        assert metadata.name == "Test Plugin"
        assert metadata.version == "1.0.0"
        assert metadata.enabled is True

    def test_metadata_with_dependencies(self):
        """Test metadata with dependencies."""
        metadata = PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="Test",
            plugin_id="test",
            dependencies=["plugin1", "plugin2"],
        )

        assert len(metadata.dependencies) == 2
        assert "plugin1" in metadata.dependencies


class TestPluginInterface:
    """Test PluginInterface base class."""

    def test_interface_must_implement_metadata(self):
        """Test that plugins must implement get_metadata()."""
        plugin = PluginInterface()

        with pytest.raises(NotImplementedError):
            plugin.get_metadata()

    def test_register_rules_default(self):
        """Test default register_rules does nothing."""
        plugin = PluginInterface()
        engine = CustomRuleEngine()

        # Should not raise
        plugin.register_rules(engine)

    def test_on_enable_default(self):
        """Test default on_enable does nothing."""
        plugin = PluginInterface()

        # Should not raise
        plugin.on_enable()

    def test_on_disable_default(self):
        """Test default on_disable does nothing."""
        plugin = PluginInterface()

        # Should not raise
        plugin.on_disable()


class SimpleTestPlugin(PluginInterface):
    """Simple test plugin for testing."""

    def __init__(self):
        """Initialize plugin."""
        self.enabled_called = False
        self.disabled_called = False
        self.register_called = False

    def get_metadata(self) -> PluginMetadata:
        """Get metadata."""
        return PluginMetadata(
            name="Simple Test Plugin",
            version="1.0.0",
            author="Test",
            description="Simple test plugin",
            plugin_id="simple_test",
        )

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """Register rules."""
        self.register_called = True
        engine.add_regex_rule(
            rule_id="SIMPLE_001",
            name="Test Rule",
            pattern=r"test_pattern",
            severity="MEDIUM",
            description="Test rule",
        )

    def on_enable(self) -> None:
        """Called when enabled."""
        self.enabled_called = True

    def on_disable(self) -> None:
        """Called when disabled."""
        self.disabled_called = True


class TestPluginManager:
    """Test PluginManager class."""

    def test_initialization(self):
        """Test manager initialization."""
        manager = PluginManager()

        assert manager is not None
        assert len(manager.plugins) == 0
        assert manager.rule_engine is not None

    def test_initialization_with_engine(self):
        """Test initialization with existing engine."""
        engine = CustomRuleEngine()
        manager = PluginManager(rule_engine=engine)

        assert manager.rule_engine is engine

    def test_add_plugin_path(self, tmp_path):
        """Test adding plugin search path."""
        manager = PluginManager()
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        manager.add_plugin_path(plugin_dir)

        assert plugin_dir in manager.plugin_paths

    def test_add_plugin_path_duplicate(self, tmp_path):
        """Test adding same path twice."""
        manager = PluginManager()
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        manager.add_plugin_path(plugin_dir)
        manager.add_plugin_path(plugin_dir)

        # Should only be added once
        assert manager.plugin_paths.count(plugin_dir) == 1

    def test_discover_plugins(self, tmp_path):
        """Test discovering plugin files."""
        manager = PluginManager()
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # Create plugin files
        (plugin_dir / "plugin_test1.py").write_text("# Plugin 1")
        (plugin_dir / "test2_plugin.py").write_text("# Plugin 2")
        (plugin_dir / "not_a_plugin.py").write_text("# Not a plugin")

        plugins = manager.discover_plugins(plugin_dir)

        assert len(plugins) == 2
        assert any(p.name == "plugin_test1.py" for p in plugins)
        assert any(p.name == "test2_plugin.py" for p in plugins)

    def test_discover_plugins_nonexistent_dir(self, tmp_path):
        """Test discovering plugins in non-existent directory."""
        manager = PluginManager()
        plugins = manager.discover_plugins(tmp_path / "nonexistent")

        assert len(plugins) == 0

    def test_load_plugin(self, tmp_path):
        """Test loading a plugin from file."""
        manager = PluginManager()

        # Create a plugin file
        plugin_file = tmp_path / "plugin_test.py"
        plugin_file.write_text(
            """
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata
from pyguard.lib.custom_rules import CustomRuleEngine

class TestPlugin(PluginInterface):
    # TODO: Add docstring
    def get_metadata(self):
        # TODO: Add docstring
        return PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test",
            description="Test",
            plugin_id="test_plugin_load"
        )

    def register_rules(self, engine):
        # TODO: Add docstring
        engine.add_regex_rule(
            rule_id="TEST001",
            name="Test",
            pattern=r"test"
        )
"""
        )

        plugin_info = manager.load_plugin(plugin_file)

        assert plugin_info is not None
        assert plugin_info.metadata.plugin_id == "test_plugin_load"
        assert plugin_info.loaded is True
        assert "TEST001" in manager.rule_engine.rules

    def test_load_plugin_invalid_file(self, tmp_path):
        """Test loading invalid plugin file."""
        manager = PluginManager()

        # Create invalid plugin
        plugin_file = tmp_path / "plugin_invalid.py"
        plugin_file.write_text("# No plugin class")

        plugin_info = manager.load_plugin(plugin_file)

        assert plugin_info is None

    def test_load_plugins_from_directory(self, tmp_path):
        """Test loading all plugins from directory."""
        manager = PluginManager()
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # Create valid plugin
        (plugin_dir / "plugin_valid.py").write_text(
            """
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata

class ValidPlugin(PluginInterface):
    # TODO: Add docstring
    def get_metadata(self):
        # TODO: Add docstring
        return PluginMetadata(
            name="Valid",
            version="1.0",
            author="Test",
            description="Test",
            plugin_id="valid"
        )
"""
        )

        count = manager.load_plugins_from_directory(plugin_dir)

        assert count == 1
        assert "valid" in manager.plugins

    def test_get_plugin(self):
        """Test getting a loaded plugin."""
        manager = PluginManager()
        plugin = SimpleTestPlugin()
        metadata = plugin.get_metadata()

        plugin_info = PluginInfo(
            metadata=metadata,
            instance=plugin,
            module_path=Path("test.py"),
        )
        manager.plugins[metadata.plugin_id] = plugin_info

        retrieved = manager.get_plugin("simple_test")

        assert retrieved is not None
        assert retrieved.metadata.plugin_id == "simple_test"

    def test_get_nonexistent_plugin(self):
        """Test getting non-existent plugin."""
        manager = PluginManager()
        plugin = manager.get_plugin("nonexistent")

        assert plugin is None

    def test_list_plugins(self):
        """Test listing all plugins."""
        manager = PluginManager()

        plugin1 = SimpleTestPlugin()
        plugin2 = SimpleTestPlugin()
        plugin2.get_metadata = lambda: PluginMetadata(
            name="Plugin 2",
            version="1.0",
            author="Test",
            description="Test",
            plugin_id="plugin2",
        )

        manager.plugins["simple_test"] = PluginInfo(
            metadata=plugin1.get_metadata(),
            instance=plugin1,
            module_path=Path("test.py"),
        )
        manager.plugins["plugin2"] = PluginInfo(
            metadata=plugin2.get_metadata(),
            instance=plugin2,
            module_path=Path("test2.py"),
        )

        plugins = manager.list_plugins()

        assert len(plugins) == 2

    def test_enable_plugin(self):
        """Test enabling a plugin."""
        manager = PluginManager()
        plugin = SimpleTestPlugin()
        metadata = plugin.get_metadata()
        metadata.enabled = False

        plugin_info = PluginInfo(
            metadata=metadata,
            instance=plugin,
            module_path=Path("test.py"),
        )
        manager.plugins[metadata.plugin_id] = plugin_info

        result = manager.enable_plugin("simple_test")

        assert result is True
        assert metadata.enabled is True
        assert plugin.enabled_called is True

    def test_disable_plugin(self):
        """Test disabling a plugin."""
        manager = PluginManager()
        plugin = SimpleTestPlugin()
        metadata = plugin.get_metadata()

        plugin_info = PluginInfo(
            metadata=metadata,
            instance=plugin,
            module_path=Path("test.py"),
        )
        manager.plugins[metadata.plugin_id] = plugin_info

        result = manager.disable_plugin("simple_test")

        assert result is True
        assert metadata.enabled is False
        assert plugin.disabled_called is True

    def test_unload_plugin(self):
        """Test unloading a plugin."""
        manager = PluginManager()
        plugin = SimpleTestPlugin()
        metadata = plugin.get_metadata()

        plugin_info = PluginInfo(
            metadata=metadata,
            instance=plugin,
            module_path=Path("test.py"),
        )
        manager.plugins[metadata.plugin_id] = plugin_info

        result = manager.unload_plugin("simple_test")

        assert result is True
        assert "simple_test" not in manager.plugins

    def test_reload_plugin(self, tmp_path):
        """Test reloading a plugin."""
        manager = PluginManager()

        # Create plugin file
        plugin_file = tmp_path / "plugin_reload.py"
        plugin_file.write_text(
            """
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata

class ReloadPlugin(PluginInterface):
    # TODO: Add docstring
    def get_metadata(self):
        # TODO: Add docstring
        return PluginMetadata(
            name="Reload",
            version="1.0",
            author="Test",
            description="Test",
            plugin_id="reload_test"
        )
"""
        )

        # Load initially
        manager.load_plugin(plugin_file)

        # Reload
        result = manager.reload_plugin("reload_test")

        assert result is True
        assert "reload_test" in manager.plugins

    def test_notify_file_analyzed(self):
        """Test notifying plugins of file analysis."""

        class NotifyPlugin(PluginInterface):
            # TODO: Add docstring
            def __init__(self):
                # TODO: Add docstring
                self.notified = False
                self.file_path = None

            def get_metadata(self):
                # TODO: Add docstring
                return PluginMetadata(
                    name="Notify",
                    version="1.0",
                    author="Test",
                    description="Test",
                    plugin_id="notify",
                )

            def on_file_analyzed(self, file_path, violations):
                # TODO: Add docstring
                self.notified = True
                self.file_path = file_path

        manager = PluginManager()
        plugin = NotifyPlugin()

        plugin_info = PluginInfo(
            metadata=plugin.get_metadata(),
            instance=plugin,
            module_path=Path("test.py"),
        )
        manager.plugins["notify"] = plugin_info

        test_path = Path("test.py")
        manager.notify_file_analyzed(test_path, [])

        assert plugin.notified is True
        assert plugin.file_path == test_path


class TestExampleSecurityPlugin:
    """Test example security plugin."""

    def test_metadata(self):
        """Test plugin metadata."""
        plugin = ExampleSecurityPlugin()
        metadata = plugin.get_metadata()

        assert metadata.name == "Example Security Plugin"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_id == "example_security"

    def test_register_rules(self):
        """Test rule registration."""
        plugin = ExampleSecurityPlugin()
        engine = CustomRuleEngine()

        plugin.register_rules(engine)

        assert "PLUGIN_EXAMPLE_001" in engine.rules
        assert "PLUGIN_EXAMPLE_002" in engine.rules

    def test_detect_api_key(self):
        """Test detecting hardcoded API keys."""
        plugin = ExampleSecurityPlugin()
        engine = CustomRuleEngine()
        plugin.register_rules(engine)

        code = '''
api_key = "sk_test_1234567890abcdefghijklmnop"  # SECURITY: Use environment variables or config files
'''

        violations = engine.check_code(code)

        # Should detect API key
        assert len(violations) > 0
        assert any(v.rule_id == "PLUGIN_EXAMPLE_001" for v in violations)

    def test_detect_eval(self):  # DANGEROUS: Avoid eval with untrusted input
        """Test detecting eval() usage."""  # DANGEROUS: Avoid eval with untrusted input
        plugin = ExampleSecurityPlugin()
        engine = CustomRuleEngine()
        plugin.register_rules(engine)

        code = """
result = eval(user_input)  # DANGEROUS: Avoid eval with untrusted input
"""

        violations = engine.check_code(code)

        # Should detect eval
        assert len(violations) > 0
        assert any(v.rule_id == "PLUGIN_EXAMPLE_002" for v in violations)


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_create_plugin_manager(self):
        """Test creating plugin manager."""
        manager = create_plugin_manager()

        assert isinstance(manager, PluginManager)
        assert manager.rule_engine is not None

    def test_create_plugin_manager_with_dirs(self, tmp_path):
        """Test creating manager with plugin directories."""
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # Create a plugin
        (plugin_dir / "plugin_test.py").write_text(
            """
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata

class TestPlugin(PluginInterface):
    # TODO: Add docstring
    def get_metadata(self):
        # TODO: Add docstring
        return PluginMetadata(
            name="Test",
            version="1.0",
            author="Test",
            description="Test",
            plugin_id="test"
        )
"""
        )

        manager = create_plugin_manager(plugin_dirs=[str(plugin_dir)])

        assert len(manager.plugins) == 1


class TestPluginInfo:
    """Test PluginInfo dataclass."""

    def test_create_plugin_info(self):
        """Test creating plugin info."""
        metadata = PluginMetadata(
            name="Test",
            version="1.0",
            author="Test",
            description="Test",
            plugin_id="test",
        )
        plugin = SimpleTestPlugin()

        info = PluginInfo(
            metadata=metadata,
            instance=plugin,
            module_path=Path("test.py"),
        )

        assert info.metadata == metadata
        assert info.instance == plugin
        assert info.loaded is True
