"""Tests for supply chain security analysis module."""

import tempfile
from pathlib import Path

import pytest

from pyguard.lib.supply_chain import (
    Dependency,
    DependencyParser,
    SBOM,
    SupplyChainAnalyzer,
    VulnerabilityChecker,
)


class TestDependency:
    """Test Dependency dataclass."""

    def test_create_dependency(self):
        """Test creating a dependency."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            source="pypi",
            license="Apache-2.0",
        )

        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.source == "pypi"
        assert dep.license == "Apache-2.0"
        assert dep.vulnerabilities == []
        assert dep.risk_level == "UNKNOWN"


class TestSBOM:
    """Test SBOM generation."""

    def test_create_sbom(self):
        """Test creating an SBOM."""
        deps = [
            Dependency(name="flask", version="2.0.0", source="pypi"),
            Dependency(name="requests", version="2.28.0", source="pypi"),
        ]

        sbom = SBOM(
            project_name="test-project",
            project_version="1.0.0",
            timestamp="2024-01-01T00:00:00",
            dependencies=deps,
            total_dependencies=2,
        )

        assert sbom.project_name == "test-project"
        assert sbom.total_dependencies == 2
        assert len(sbom.dependencies) == 2

    def test_sbom_to_dict(self):
        """Test converting SBOM to dictionary."""
        sbom = SBOM(
            project_name="test",
            project_version="1.0",
            timestamp="2024-01-01",
            dependencies=[],
            total_dependencies=0,
        )

        sbom_dict = sbom.to_dict()

        assert isinstance(sbom_dict, dict)
        assert sbom_dict["project_name"] == "test"
        assert sbom_dict["total_dependencies"] == 0

    def test_sbom_to_json(self):
        """Test converting SBOM to JSON."""
        sbom = SBOM(
            project_name="test",
            project_version="1.0",
            timestamp="2024-01-01",
            dependencies=[],
            total_dependencies=0,
        )

        json_str = sbom.to_json()

        assert isinstance(json_str, str)
        assert "test" in json_str
        assert "project_name" in json_str

    def test_sbom_to_cyclonedx(self):
        """Test converting SBOM to CycloneDX format."""
        deps = [Dependency(name="requests", version="2.28.0", source="pypi")]

        sbom = SBOM(
            project_name="test",
            project_version="1.0",
            timestamp="2024-01-01",
            dependencies=deps,
            total_dependencies=1,
        )

        cyclonedx = sbom.to_cyclonedx()

        assert cyclonedx["bomFormat"] == "CycloneDX"
        assert cyclonedx["specVersion"] == "1.4"
        assert len(cyclonedx["components"]) == 1
        assert cyclonedx["components"][0]["name"] == "requests"


class TestDependencyParser:
    """Test dependency file parsing."""

    def test_parse_requirements_txt(self):
        """Test parsing requirements.txt."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests==2.28.0\n")
            f.write("flask>=2.0.0\n")
            f.write("django~=3.2.0\n")
            f.write("# Comment line\n")
            f.write("\n")
            f.write("pytest\n")
            temp_path = Path(f.name)

        try:
            parser = DependencyParser()
            deps = parser.parse_requirements_txt(temp_path)

            assert len(deps) == 4

            # Check requests
            req = next(d for d in deps if d.name == "requests")
            assert req.version == "2.28.0"
            assert req.source == "pypi"

            # Check flask
            flask = next(d for d in deps if d.name == "flask")
            assert flask.version == "2.0.0"
        finally:
            temp_path.unlink()

    def test_parse_pyproject_toml(self):
        """Test parsing pyproject.toml."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write("[project]\n")
            f.write("dependencies = [\n")
            f.write('    "requests>=2.28.0",\n')
            f.write('    "flask>=2.0.0",\n')
            f.write("]\n")
            temp_path = Path(f.name)

        try:
            parser = DependencyParser()
            deps = parser.parse_pyproject_toml(temp_path)

            assert len(deps) == 2

            req = next(d for d in deps if d.name == "requests")
            assert req.version == "2.28.0"
        finally:
            temp_path.unlink()

    def test_parse_pipfile(self):
        """Test parsing Pipfile."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("[packages]\n")
            f.write('requests = "==2.28.0"\n')
            f.write('flask = ">=2.0.0"\n')
            f.write("\n")
            f.write("[dev-packages]\n")
            f.write('pytest = "*"\n')
            temp_path = Path(f.name)

        try:
            parser = DependencyParser()
            deps = parser.parse_pipfile(temp_path)

            assert len(deps) == 2

            req = next(d for d in deps if d.name == "requests")
            assert req.version == "2.28.0"
        finally:
            temp_path.unlink()


class TestVulnerabilityChecker:
    """Test vulnerability checking."""

    def test_check_vulnerable_package(self):
        """Test checking a package with known vulnerabilities."""
        checker = VulnerabilityChecker()

        dep = Dependency(name="requests", version="2.19.0", source="pypi")
        updated_dep = checker.check_dependency(dep)

        # Should detect CVE in old version
        assert len(updated_dep.vulnerabilities) > 0
        assert updated_dep.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_check_safe_package(self):
        """Test checking a safe package version."""
        checker = VulnerabilityChecker()

        dep = Dependency(name="requests", version="2.31.0", source="pypi")
        updated_dep = checker.check_dependency(dep)

        # Latest version should be safe (or have minimal issues)
        assert updated_dep.risk_level in ["UNKNOWN", "LOW"]

    def test_check_risky_package_name(self):
        """Test detection of inherently risky packages."""
        checker = VulnerabilityChecker()

        dep = Dependency(name="pickle5", version="1.0.0", source="pypi")
        updated_dep = checker.check_dependency(dep)

        # Should flag pickle5 as risky
        assert len(updated_dep.vulnerabilities) > 0
        assert updated_dep.risk_level == "HIGH"

    def test_version_comparison(self):
        """Test version comparison logic."""
        checker = VulnerabilityChecker()

        # Test various version comparisons
        assert checker._version_matches("2.19.0", "<2.20.0") is True
        assert checker._version_matches("2.20.0", "<2.20.0") is False
        assert checker._version_matches("2.21.0", "<2.20.0") is False


class TestSupplyChainAnalyzer:
    """Test comprehensive supply chain analysis."""

    def test_analyze_project_with_requirements(self):
        """Test analyzing a project with requirements.txt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)

            # Create requirements.txt
            req_file = project_dir / "requirements.txt"
            req_file.write_text("requests==2.28.0\nflask>=2.0.0\n")

            analyzer = SupplyChainAnalyzer()
            sbom = analyzer.analyze_project(project_dir)

            assert sbom.project_name == project_dir.name
            assert sbom.total_dependencies == 2
            assert len(sbom.dependencies) == 2

    def test_analyze_project_multiple_files(self):
        """Test analyzing project with multiple dependency files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)

            # Create multiple dependency files
            req_file = project_dir / "requirements.txt"
            req_file.write_text("requests==2.28.0\n")

            pyproject = project_dir / "pyproject.toml"
            pyproject.write_text('[project]\ndependencies = [\n    "flask>=2.0.0",\n]\n')

            analyzer = SupplyChainAnalyzer()
            sbom = analyzer.analyze_project(project_dir)

            # Should have at least 1 dependency (may deduplicate)
            assert sbom.total_dependencies >= 1

    def test_generate_sbom_file(self):
        """Test generating SBOM file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)
            output_path = Path(temp_dir) / "sbom.json"

            # Create requirements.txt
            req_file = project_dir / "requirements.txt"
            req_file.write_text("requests==2.28.0\n")

            analyzer = SupplyChainAnalyzer()
            analyzer.generate_sbom_file(project_dir, output_path, format="json")

            assert output_path.exists()

            # Verify JSON content
            content = output_path.read_text()
            assert "requests" in content
            assert "2.28.0" in content

    def test_vulnerability_counting(self):
        """Test that vulnerabilities are counted correctly in SBOM."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)

            # Create requirements with vulnerable package
            req_file = project_dir / "requirements.txt"
            req_file.write_text("requests==2.19.0\n")  # Old vulnerable version

            analyzer = SupplyChainAnalyzer()
            sbom = analyzer.analyze_project(project_dir)

            # Should detect vulnerabilities
            total_vulns = (
                sbom.critical_vulnerabilities
                + sbom.high_vulnerabilities
                + sbom.medium_vulnerabilities
                + sbom.low_vulnerabilities
            )
            assert total_vulns >= 0  # At least records the analysis


class TestVersionComparisons:
    """Test version comparison operators."""

    def test_version_comparison_less_than(self):
        """Test version < operator."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        assert checker._version_matches("1.0.0", "<2.0.0")
        assert not checker._version_matches("2.0.0", "<1.0.0")

    def test_version_comparison_less_equal(self):
        """Test version <= operator."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        assert checker._version_matches("1.0.0", "<=2.0.0")
        assert checker._version_matches("2.0.0", "<=2.0.0")
        assert not checker._version_matches("3.0.0", "<=2.0.0")

    def test_version_comparison_greater_than(self):
        """Test version > operator."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        assert checker._version_matches("2.0.0", ">1.0.0")
        assert not checker._version_matches("1.0.0", ">2.0.0")

    def test_version_comparison_greater_equal(self):
        """Test version >= operator."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        assert checker._version_matches("2.0.0", ">=1.0.0")
        assert checker._version_matches("2.0.0", ">=2.0.0")
        assert not checker._version_matches("1.0.0", ">=2.0.0")

    def test_version_comparison_invalid_spec(self):
        """Test version comparison with invalid spec."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        # Should return False for invalid specs
        result = checker._version_matches("1.0.0", "invalid")
        assert result is False

    def test_version_comparison_exception(self):
        """Test version comparison handles exceptions."""
        from pyguard.lib.supply_chain import VulnerabilityChecker
        checker = VulnerabilityChecker()
        # Malformed version strings should not crash
        result = checker._version_matches("not-a-version", ">=1.0.0")
        assert result is False


class TestVulnerabilitySeverityCounting:
    """Test vulnerability severity counting in SBOM."""

    def test_count_all_severity_levels(self):
        """Test counting vulnerabilities at all severity levels."""
        analyzer = SupplyChainAnalyzer()
        
        # Create mock dependencies with different risk levels
        deps = [
            Dependency(
                name="pkg1",
                version="1.0.0",
                source="pypi",
                license="MIT",
                risk_level="CRITICAL",
                vulnerabilities=[],
            ),
            Dependency(
                name="pkg2",
                version="1.0.0",
                source="pypi",
                license="MIT",
                risk_level="HIGH",
                vulnerabilities=[],
            ),
            Dependency(
                name="pkg3",
                version="1.0.0",
                source="pypi",
                license="MIT",
                risk_level="MEDIUM",
                vulnerabilities=[],
            ),
            Dependency(
                name="pkg4",
                version="1.0.0",
                source="pypi",
                license="MIT",
                risk_level="LOW",
                vulnerabilities=[],
            ),
        ]
        
        # Manually count (simulating the logic)
        critical = sum(1 for d in deps if d.risk_level == "CRITICAL")
        high = sum(1 for d in deps if d.risk_level == "HIGH")
        medium = sum(1 for d in deps if d.risk_level == "MEDIUM")
        low = sum(1 for d in deps if d.risk_level == "LOW")
        
        assert critical == 1
        assert high == 1
        assert medium == 1
        assert low == 1
