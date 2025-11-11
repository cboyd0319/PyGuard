"""Tests for API stability and deprecation management."""

import warnings

import pytest

from pyguard.lib.api_stability import (
    APIRegistration,
    APIRegistry,
    APIVersion,
    DeprecationInfo,
    StabilityLevel,
    check_api_compatibility,
    deprecated,
    generate_migration_guide,
    get_registry,
    stable_api,
)


class TestAPIVersion:
    """Test API version handling."""

    def test_version_creation(self):
        """Test creating API version."""
        version = APIVersion(major=1, minor=2, patch=3)
        assert version.major == 1
        assert version.minor == 2
        assert version.patch == 3

    def test_version_from_string(self):
        """Test parsing version from string."""
        version = APIVersion.from_string("1.2.3")
        assert version.major == 1
        assert version.minor == 2
        assert version.patch == 3

    def test_version_to_string(self):
        """Test converting version to string."""
        version = APIVersion(1, 2, 3)
        assert str(version) == "1.2.3"

    def test_version_comparison(self):
        """Test version comparison."""
        v1 = APIVersion(1, 0, 0)
        v2 = APIVersion(1, 1, 0)
        v3 = APIVersion(2, 0, 0)

        assert v1 < v2
        assert v2 < v3
        assert v1 < v3
        assert v1 <= v1
        assert v1 == APIVersion(1, 0, 0)

    def test_version_compatibility(self):
        """Test version compatibility checking."""
        v1_0_0 = APIVersion(1, 0, 0)
        v1_1_0 = APIVersion(1, 1, 0)
        v1_2_0 = APIVersion(1, 2, 0)
        v2_0_0 = APIVersion(2, 0, 0)

        # Same major, higher or equal minor = compatible
        assert v1_2_0.is_compatible_with(v1_0_0)
        assert v1_2_0.is_compatible_with(v1_1_0)
        assert v1_1_0.is_compatible_with(v1_1_0)

        # Lower minor = not compatible
        assert not v1_0_0.is_compatible_with(v1_1_0)

        # Different major = not compatible
        assert not v2_0_0.is_compatible_with(v1_0_0)


class TestDeprecationInfo:
    """Test deprecation information."""

    def test_deprecation_info_creation(self):
        """Test creating deprecation info."""
        info = DeprecationInfo(
            name="old_function",
            deprecated_in=APIVersion(1, 0, 0),
            removal_in=APIVersion(2, 0, 0),
            replacement="new_function",
            reason="Better implementation available",
        )

        assert info.name == "old_function"
        assert info.replacement == "new_function"

    def test_deprecation_warning_message(self):
        """Test generating deprecation warning message."""
        info = DeprecationInfo(
            name="old_function",
            deprecated_in=APIVersion(1, 0, 0),
            removal_in=APIVersion(2, 0, 0),
            replacement="new_function",
            reason="Better implementation available",
        )

        message = info.get_warning_message()

        assert "old_function" in message
        assert "1.0.0" in message
        assert "2.0.0" in message
        assert "new_function" in message
        assert "Better implementation available" in message


class TestAPIRegistration:
    """Test API registration."""

    def test_api_registration(self):
        """Test creating API registration."""
        registration = APIRegistration(
            name="test_function",
            stability_level=StabilityLevel.STABLE,
            introduced_in=APIVersion(1, 0, 0),
            signature="(arg1, arg2)",
            module="test.module",
        )

        assert registration.name == "test_function"
        assert registration.is_stable()
        assert not registration.is_deprecated()

    def test_deprecated_registration(self):
        """Test deprecated API registration."""
        registration = APIRegistration(
            name="old_function",
            stability_level=StabilityLevel.DEPRECATED,
            introduced_in=APIVersion(0, 5, 0),
            signature="()",
            module="test.module",
            deprecation_info=DeprecationInfo(
                name="old_function",
                deprecated_in=APIVersion(1, 0, 0),
                removal_in=APIVersion(2, 0, 0),
            ),
        )

        assert not registration.is_stable()
        assert registration.is_deprecated()


class TestAPIRegistry:
    """Test API registry."""

    @pytest.fixture
    def registry(self):
        """Create fresh registry."""
        return APIRegistry(current_version="1.0.0")

    def test_registry_initialization(self, registry):
        """Test registry initialization."""
        assert registry.current_version == APIVersion(1, 0, 0)
        assert len(registry.apis) == 0

    def test_register_api(self, registry):
        """Test registering an API."""
        registry.register_api(
            name="test.function",
            stability_level=StabilityLevel.STABLE,
            introduced_in="1.0.0",
        )

        assert "test.function" in registry.apis
        assert registry.apis["test.function"].is_stable()

    def test_deprecate_api(self, registry):
        """Test deprecating an API."""
        # Register API first
        registry.register_api(
            name="old.function",
            stability_level=StabilityLevel.STABLE,
            introduced_in="0.5.0",
        )

        # Deprecate it
        registry.deprecate_api(
            name="old.function",
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            replacement="new.function",
        )

        assert "old.function" in registry.deprecations
        assert registry.apis["old.function"].is_deprecated()

    def test_check_compatibility_compatible(self, registry):
        """Test checking compatibility with compatible version."""
        registry.register_api(
            name="api1",
            stability_level=StabilityLevel.STABLE,
            introduced_in="0.5.0",
        )

        result = registry.check_compatibility("1.0.0")

        assert result['compatible']
        assert len(result['removed_apis']) == 0
        assert len(result['incompatible_apis']) == 0

    def test_check_compatibility_removed_api(self, registry):
        """Test checking compatibility with removed API."""
        # Register and deprecate API
        registry.register_api(
            name="old.api",
            stability_level=StabilityLevel.STABLE,
            introduced_in="0.5.0",
        )

        registry.deprecate_api(
            name="old.api",
            deprecated_in="1.0.0",
            removal_in="2.0.0",
        )

        # Check compatibility with version after removal
        result = registry.check_compatibility("2.0.0")

        assert not result['compatible']
        assert len(result['removed_apis']) == 1
        assert result['removed_apis'][0]['name'] == "old.api"

    def test_check_compatibility_new_api(self, registry):
        """Test checking compatibility with API not yet introduced."""
        # Register API introduced in 1.5.0
        registry.register_api(
            name="new.api",
            stability_level=StabilityLevel.STABLE,
            introduced_in="1.5.0",
        )

        # Check compatibility with older version
        result = registry.check_compatibility("1.0.0")

        assert not result['compatible']
        assert len(result['incompatible_apis']) == 1
        assert result['incompatible_apis'][0]['name'] == "new.api"

    def test_get_migration_guide(self, registry):
        """Test generating migration guide."""
        # Register APIs
        registry.register_api(
            name="stable.api",
            stability_level=StabilityLevel.STABLE,
            introduced_in="0.5.0",
        )

        registry.register_api(
            name="new.api",
            stability_level=StabilityLevel.STABLE,
            introduced_in="1.5.0",
        )

        registry.register_api(
            name="old.api",
            stability_level=StabilityLevel.STABLE,
            introduced_in="0.3.0",
        )

        registry.deprecate_api(
            name="old.api",
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            replacement="new.api",
        )

        # Get migration guide from 0.9.0 to 1.6.0
        guide = registry.get_migration_guide("0.9.0", "1.6.0")

        assert guide['from_version'] == "0.9.0"
        assert guide['to_version'] == "1.6.0"
        # 0.9.0 to 1.6.0 crosses major version boundary
        assert guide['is_major_upgrade']
        assert not guide['is_minor_upgrade']

        # Should have deprecated warning for old.api
        assert len(guide['deprecation_warnings']) == 1
        assert guide['deprecation_warnings'][0]['api'] == "old.api"

        # Should have new feature for new.api
        assert len(guide['new_features']) == 1
        assert guide['new_features'][0]['api'] == "new.api"


class TestStableAPIDecorator:
    """Test stable API decorator."""

    def test_stable_api_decorator(self):
        """Test decorating function as stable API."""
        @stable_api(introduced_in="1.0.0")
        def my_function():
            return "result"

        assert hasattr(my_function, '__api_stability__')
        assert my_function.__api_stability__['introduced_in'] == "1.0.0"
        assert my_function.__api_stability__['stability_level'] == "stable"

        # Function should still work normally
        assert my_function() == "result"

    def test_beta_api_decorator(self):
        """Test decorating function as beta API."""
        @stable_api(introduced_in="0.8.0", stability_level=StabilityLevel.BETA)
        def beta_function():
            return "beta"

        assert beta_function.__api_stability__['stability_level'] == "beta"


class TestDeprecatedDecorator:
    """Test deprecated decorator."""

    def test_deprecated_decorator(self):
        """Test deprecating a function."""
        @deprecated(
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            replacement="new_function",
        )
        def old_function():
            return "old"

        assert hasattr(old_function, '__deprecated__')

        # Calling should show warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_function()

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "old_function" in str(w[0].message)
            assert "1.0.0" in str(w[0].message)
            assert "2.0.0" in str(w[0].message)
            assert "new_function" in str(w[0].message)

        # Function should still work
        assert result == "old"

    def test_deprecated_with_reason(self):
        """Test deprecation with reason."""
        @deprecated(
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            reason="Better implementation available",
        )
        def old_function():
            return "old"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_function()

            assert "Better implementation available" in str(w[0].message)


class TestGlobalFunctions:
    """Test global API functions."""

    def test_get_registry(self):
        """Test getting global registry."""
        registry = get_registry()
        assert isinstance(registry, APIRegistry)

    def test_check_api_compatibility(self):
        """Test compatibility checking function."""
        result = check_api_compatibility("1.0.0")
        assert 'compatible' in result
        assert 'current_version' in result

    def test_generate_migration_guide_function(self):
        """Test migration guide generation function."""
        guide = generate_migration_guide("0.6.0", "0.8.0")
        assert 'from_version' in guide
        assert 'to_version' in guide
        assert 'breaking_changes_count' in guide


class TestCoreAPIRegistration:
    """Test core API registrations."""

    def test_core_apis_registered(self):
        """Test that core APIs are registered on module import."""
        registry = get_registry()

        # Check some core APIs are registered
        assert "pyguard.api.scan_file" in registry.apis
        assert "pyguard.api.scan_directory" in registry.apis
        assert "pyguard.api.load_config" in registry.apis

        # Check stability levels
        assert registry.apis["pyguard.api.scan_file"].is_stable()


class TestComplexMigrationScenario:
    """Test complex migration scenarios."""

    @pytest.fixture
    def complex_registry(self):
        """Create registry with complex version history."""
        registry = APIRegistry(current_version="2.0.0")

        # API introduced in 0.5.0
        registry.register_api(
            "api.v1.scan",
            StabilityLevel.STABLE,
            "0.5.0",
        )

        # Deprecated in 1.0.0, removed in 2.0.0
        registry.deprecate_api(
            "api.v1.scan",
            deprecated_in="1.0.0",
            removal_in="2.0.0",
            replacement="api.v2.scan",
        )

        # New API introduced in 1.0.0
        registry.register_api(
            "api.v2.scan",
            StabilityLevel.STABLE,
            "1.0.0",
        )

        return registry

    def test_migration_across_major_version(self, complex_registry):
        """Test migration guide across major version."""
        guide = complex_registry.get_migration_guide("0.9.0", "2.0.0")

        assert guide['is_major_upgrade']
        assert guide['breaking_changes_count'] == 1

        # Should show removal of api.v1.scan
        assert len(guide['changes_required']) == 1
        assert guide['changes_required'][0]['api'] == "api.v1.scan"

        # Should show new feature api.v2.scan
        assert len(guide['new_features']) == 1
        assert guide['new_features'][0]['api'] == "api.v2.scan"

    def test_minor_version_upgrade(self, complex_registry):
        """Test migration within minor versions."""
        # Add minor version feature
        complex_registry.register_api(
            "api.experimental.feature",
            StabilityLevel.BETA,
            "1.5.0",
        )

        guide = complex_registry.get_migration_guide("1.0.0", "1.8.0")

        assert not guide['is_major_upgrade']
        assert guide['is_minor_upgrade']
        assert len(guide['changes_required']) == 0  # No breaking changes
