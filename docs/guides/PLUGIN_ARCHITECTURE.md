# PyGuard Plugin Architecture

Complete guide to extending PyGuard with custom plugins.

## Overview

PyGuard's plugin system allows you to extend the tool with custom security rules, code quality checks, and analysis features. Plugins are Python modules that implement the `PluginInterface` and can be dynamically loaded at runtime.

## Features

- **Dynamic Plugin Loading**: Load plugins from directories at runtime
- **Plugin Lifecycle Management**: Enable, disable, reload plugins without restarting
- **Custom Rule Registration**: Add regex-based or AST-based security rules
- **Event Hooks**: React to file analysis events
- **Plugin Discovery**: Automatic discovery of plugins following naming conventions
- **Metadata and Versioning**: Track plugin versions and dependencies

## Quick Start

### 1. Create a Plugin

Create a file named `plugin_example.py` or `example_plugin.py`:

```python
from pyguard.lib.plugin_system import PluginInterface, PluginMetadata
from pyguard.lib.custom_rules import CustomRuleEngine
import ast

class MySecurityPlugin(PluginInterface):
    """Custom security plugin example."""

    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return PluginMetadata(
            name="My Security Plugin",
            version="1.0.0",
            author="Your Name",
            description="Custom security checks for my project",
            plugin_id="my_security_plugin",
            dependencies=[]  # Optional: list of required plugin IDs
        )

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """Register custom security rules."""
        # Add a regex-based rule
        engine.add_regex_rule(
            rule_id="CUSTOM_001",
            name="Detect Hardcoded Secrets",
            pattern=r'SECRET_KEY\s*=\s*["\'][^"\']{10,}["\']',
            severity="HIGH",
            category="Security",
            description="Hardcoded secret key detected",
            suggestion="Use environment variables for secrets"
        )

        # Add an AST-based rule
        def check_dangerous_imports(tree: ast.AST) -> list[int]:
            """Detect imports of dangerous modules."""
            lines = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ['pickle', 'marshal']:
                            lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="CUSTOM_002",
            name="Dangerous Module Import",
            checker=check_dangerous_imports,
            severity="MEDIUM",
            category="Security",
            description="Import of potentially dangerous module",
            suggestion="Consider using safer alternatives"
        )

    def on_enable(self) -> None:
        """Called when plugin is enabled."""
        print(f"[{self.get_metadata().name}] Plugin enabled")

    def on_disable(self) -> None:
        """Called when plugin is disabled."""
        print(f"[{self.get_metadata().name}] Plugin disabled")

    def on_file_analyzed(self, file_path, violations) -> None:
        """Called after each file is analyzed."""
        if violations:
            print(f"Found {len(violations)} issues in {file_path}")
```

### 2. Load the Plugin

```python
from pyguard.lib.plugin_system import create_plugin_manager
from pathlib import Path

# Create plugin manager and load plugins
manager = create_plugin_manager(plugin_dirs=["./plugins"])

# List loaded plugins
for plugin in manager.list_plugins():
    print(f"Loaded: {plugin.metadata.name} v{plugin.metadata.version}")

# Check files with custom rules
violations = manager.rule_engine.check_file(Path("my_code.py"))
for violation in violations:
    print(f"{violation.severity}: {violation.message} at line {violation.line_number}")
```

## Plugin Naming Conventions

Plugins must follow these naming patterns to be auto-discovered:

- **Prefix pattern**: `plugin_*.py` (e.g., `plugin_security.py`, `plugin_custom.py`)
- **Suffix pattern**: `<name>_plugin.py` (e.g., `security_plugin.py`, `quality_plugin.py`)

The name part must be alphanumeric (a-z, A-Z, 0-9, underscore).

### Valid Plugin Names

```
✅ plugin_security.py
✅ plugin_mycompany.py
✅ security_plugin.py
✅ mycompany_plugin.py
✅ custom123_plugin.py
```

### Invalid Plugin Names

```
❌ my_plugin_file.py       (doesn't match pattern)
❌ not_a_plugin.py         (contains disqualifying words)
❌ security.py             (missing plugin indicator)
❌ plugin_.py              (empty name)
```

## Plugin Interface Reference

### Required Methods

#### `get_metadata() -> PluginMetadata`

Returns metadata about the plugin.

```python
def get_metadata(self) -> PluginMetadata:
    return PluginMetadata(
        name="My Plugin",           # Human-readable name
        version="1.0.0",           # Semantic version
        author="Author Name",       # Plugin author
        description="Description",  # Brief description
        plugin_id="unique_id",     # Unique identifier
        dependencies=[]            # Optional: required plugins
    )
```

### Optional Hooks

#### `register_rules(engine: CustomRuleEngine) -> None`

Register custom security and quality rules.

```python
def register_rules(self, engine: CustomRuleEngine) -> None:
    # Add regex-based rules
    engine.add_regex_rule(...)

    # Add AST-based rules
    engine.add_ast_rule(...)
```

#### `on_enable() -> None`

Called when the plugin is enabled. Use for initialization.

```python
def on_enable(self) -> None:
    self.cache = {}
    print("Plugin initialized")
```

#### `on_disable() -> None`

Called when the plugin is disabled. Use for cleanup.

```python
def on_disable(self) -> None:
    self.cache.clear()
    print("Plugin cleaned up")
```

#### `on_file_analyzed(file_path: Path, violations: list[RuleViolation]) -> None`

Called after each file is analyzed. Use for custom reporting or metrics.

```python
def on_file_analyzed(self, file_path: Path, violations: list[RuleViolation]) -> None:
    self.total_files += 1
    self.total_violations += len(violations)
```

## Plugin Manager API

### Creating a Plugin Manager

```python
from pyguard.lib.plugin_system import PluginManager

# Create with custom rule engine
manager = PluginManager(rule_engine=my_engine)

# Or use default engine
manager = PluginManager()
```

### Loading Plugins

```python
from pathlib import Path

# Load single plugin
plugin_info = manager.load_plugin(Path("plugins/security_plugin.py"))

# Load all plugins from directory
count = manager.load_plugins_from_directory(Path("plugins"))
print(f"Loaded {count} plugins")

# Discover plugins without loading
plugin_files = manager.discover_plugins(Path("plugins"))
```

### Managing Plugins

```python
# List all plugins
plugins = manager.list_plugins()
for plugin in plugins:
    print(f"{plugin.metadata.name}: {plugin.metadata.enabled}")

# Get specific plugin
plugin = manager.get_plugin("my_plugin_id")

# Enable/disable plugins
manager.enable_plugin("my_plugin_id")
manager.disable_plugin("my_plugin_id")

# Reload a plugin
manager.reload_plugin("my_plugin_id")

# Unload a plugin
manager.unload_plugin("my_plugin_id")
```

### Using Plugin Rules

```python
# Check a file
violations = manager.rule_engine.check_file(Path("code.py"))

# Check code string
code = "print('hello')"
violations = manager.rule_engine.check_code(code)

# Process violations
for v in violations:
    print(f"{v.severity}: {v.rule_name}")
    print(f"  {v.message} at line {v.line_number}")
    print(f"  Suggestion: {v.suggestion}")
```

## Advanced Examples

### Plugin with State

```python
class StatefulPlugin(PluginInterface):
    """Plugin that tracks statistics across files."""

    def __init__(self):
        self.stats = {
            'files_analyzed': 0,
            'total_violations': 0,
            'high_severity': 0
        }

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Statistics Plugin",
            version="1.0.0",
            author="Me",
            description="Tracks analysis statistics",
            plugin_id="stats_plugin"
        )

    def on_file_analyzed(self, file_path, violations):
        self.stats['files_analyzed'] += 1
        self.stats['total_violations'] += len(violations)
        self.stats['high_severity'] += sum(
            1 for v in violations if v.severity == "HIGH"
        )

    def on_disable(self):
        print(f"Final statistics: {self.stats}")
```

### Framework-Specific Plugin

```python
class DjangoSecurityPlugin(PluginInterface):
    """Security checks specific to Django projects."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Django Security Plugin",
            version="1.0.0",
            author="Security Team",
            description="Django-specific security checks",
            plugin_id="django_security"
        )

    def register_rules(self, engine: CustomRuleEngine):
        # Check for DEBUG = True in production
        engine.add_regex_rule(
            rule_id="DJANGO_001",
            name="Debug Mode in Production",
            pattern=r'DEBUG\s*=\s*True',
            severity="HIGH",
            category="Django Security",
            description="DEBUG should be False in production",
            suggestion="Set DEBUG = False in production settings"
        )

        # Check for missing CSRF middleware
        def check_csrf_middleware(tree: ast.AST) -> list[int]:
            lines = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "MIDDLEWARE":
                            # Check if CsrfViewMiddleware is in list
                            if isinstance(node.value, (ast.List, ast.Tuple)):
                                middleware_items = []
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant):
                                        middleware_items.append(elt.value)
                                if 'django.middleware.csrf.CsrfViewMiddleware' not in middleware_items:
                                    lines.append(node.lineno)
            return lines

        engine.add_ast_rule(
            rule_id="DJANGO_002",
            name="Missing CSRF Middleware",
            checker=check_csrf_middleware,
            severity="HIGH",
            category="Django Security",
            description="CSRF middleware not found in MIDDLEWARE setting",
            suggestion="Add CsrfViewMiddleware to MIDDLEWARE"
        )
```

### Plugin with Dependencies

```python
class AdvancedPlugin(PluginInterface):
    """Plugin that depends on another plugin."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="Advanced Plugin",
            version="2.0.0",
            author="Team",
            description="Advanced features",
            plugin_id="advanced_plugin",
            dependencies=["base_plugin", "security_plugin"]  # Required plugins
        )

    def register_rules(self, engine: CustomRuleEngine):
        # Can use rules from dependency plugins
        base_rule = engine.get_rule("BASE_001")
        if base_rule:
            # Extend or modify base rule behavior
            pass
```

## Integration with PyGuard CLI

### Plugin Configuration in pyguard.toml

```toml
[plugins]
enabled = true
plugin_dirs = ["./plugins", "~/.pyguard/plugins"]

# Enable/disable specific plugins
[plugins.enabled_plugins]
security_plugin = true
custom_plugin = true
experimental_plugin = false
```

### Command Line Usage

```bash
# Run PyGuard with plugins
pyguard scan --plugins ./plugins src/

# List available plugins
pyguard plugins list

# Enable a plugin
pyguard plugins enable my_plugin

# Disable a plugin
pyguard plugins disable my_plugin
```

## Best Practices

### 1. Plugin Organization

```
plugins/
├── security_plugin.py       # Security-focused rules
├── quality_plugin.py        # Code quality rules
├── company_plugin.py        # Company-specific checks
└── experimental_plugin.py   # Experimental features
```

### 2. Error Handling

Always handle errors gracefully in plugin hooks:

```python
def on_file_analyzed(self, file_path, violations):
    try:
        # Plugin logic
        self.process_violations(violations)
    except Exception as e:
        # Log but don't crash PyGuard
        print(f"Plugin error: {e}")
```

### 3. Performance

- Keep AST checkers efficient - they run on every file
- Use caching for expensive operations
- Avoid blocking operations in hooks

```python
def register_rules(self, engine: CustomRuleEngine):
    # Cache compiled patterns
    self.pattern = re.compile(r'expensive_regex_pattern')

    def efficient_checker(tree: ast.AST) -> list[int]:
        # Use self.pattern instead of compiling each time
        pass
```

### 4. Documentation

Document your plugin rules clearly:

```python
engine.add_regex_rule(
    rule_id="COMPANY_001",
    name="Legacy API Usage",
    pattern=r'legacy_api\.call',
    severity="MEDIUM",
    category="Company Standards",
    description="Usage of deprecated legacy API detected. "
                "The legacy API will be removed in v3.0.",
    suggestion="Migrate to the new API: new_api.call()"
)
```

### 5. Testing

Write tests for your plugins:

```python
def test_my_plugin():
    from pyguard.lib.plugin_system import PluginManager
    from my_plugin import MyPlugin

    manager = PluginManager()
    plugin = MyPlugin()
    plugin.register_rules(manager.rule_engine)

    # Test detection
    code = "SECRET_KEY = 'hardcoded_secret'"
    violations = manager.rule_engine.check_code(code)

    assert len(violations) > 0
    assert violations[0].rule_id == "CUSTOM_001"
```

## Troubleshooting

### Plugin Not Loading

Check naming convention:
```bash
# Valid names
plugin_security.py  ✅
security_plugin.py  ✅

# Invalid names
security.py         ❌
my_security.py      ❌
```

### Plugin Errors

Enable verbose logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

manager = PluginManager()
manager.load_plugins_from_directory(Path("plugins"))
```

### Rule Not Triggering

Test your rule in isolation:
```python
engine = CustomRuleEngine()
engine.add_regex_rule("TEST", "Test", r"pattern")

code = "test code with pattern"
violations = engine.check_code(code)
print(f"Found {len(violations)} violations")
```

## Security Considerations

### Plugin Trust

- Only load plugins from trusted sources
- Review plugin code before loading
- Plugins have full Python execution access

### Sandboxing

For untrusted plugins, consider:
- Running in separate process
- Using restricted execution environment
- Validating plugin signatures

## API Reference

### Complete PluginInterface

```python
class PluginInterface:
    def get_metadata(self) -> PluginMetadata:
        """Required: Return plugin metadata."""
        raise NotImplementedError

    def register_rules(self, engine: CustomRuleEngine) -> None:
        """Optional: Register custom rules."""
        pass

    def on_enable(self) -> None:
        """Optional: Called when plugin is enabled."""
        pass

    def on_disable(self) -> None:
        """Optional: Called when plugin is disabled."""
        pass

    def on_file_analyzed(self, file_path: Path, violations: list[RuleViolation]) -> None:
        """Optional: Called after file analysis."""
        pass
```

### PluginMetadata Fields

```python
@dataclass
class PluginMetadata:
    name: str                      # Human-readable plugin name
    version: str                   # Semantic version (e.g., "1.0.0")
    author: str                    # Plugin author
    description: str               # Brief description
    plugin_id: str                 # Unique identifier
    enabled: bool = True           # Whether plugin is enabled
    dependencies: list[str] = []   # Required plugin IDs
```

## Related Documentation

- [Custom Rules Guide](CUSTOM_RULES.md) - Creating custom security rules
- [Configuration Guide](CONFIGURATION.md) - PyGuard configuration options
- [API Reference](../reference/api-reference.md) - Complete API documentation

## Examples Repository

See the [examples/plugins/](../../examples/plugins/) directory for more plugin examples:

- `plugin_security_extended.py` - Extended security checks
- `plugin_company_standards.py` - Company-specific rules
- `plugin_metrics.py` - Code metrics and statistics
- `plugin_django_advanced.py` - Advanced Django checks

## Support

- **Issues**: [GitHub Issues](https://github.com/cboyd0319/PyGuard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cboyd0319/PyGuard/discussions)
- **Documentation**: [docs/index.md](../index.md)
