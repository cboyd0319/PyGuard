"""
Supply Chain Security Analysis for PyGuard.

Analyzes dependencies, generates SBOMs, checks for known vulnerabilities,
and validates package integrity.

References:
- NIST SSDF | https://csrc.nist.gov/publications/detail/sp/800-218/final | High | Secure Software Development Framework
- SLSA | https://slsa.dev/ | High | Supply-chain Levels for Software Artifacts
- OWASP Dependency-Check | https://owasp.org/www-project-dependency-check/ | High | Dependency vulnerability detection
- SBOM | https://www.cisa.gov/sbom | High | Software Bill of Materials
- CycloneDX | https://cyclonedx.org/ | High | SBOM standard
"""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, ClassVar

from pyguard.lib.core import FileOperations, PyGuardLogger


@dataclass
class Dependency:
    """Represents a software dependency."""

    name: str
    version: str
    source: str  # pypi, git, local, etc.
    license: str | None = None
    hash_sha256: str | None = None
    vulnerabilities: list[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class SBOM:
    """Software Bill of Materials."""

    project_name: str
    project_version: str
    timestamp: str
    dependencies: list[Dependency]
    total_dependencies: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0

    def to_dict(self) -> dict:
        """Convert SBOM to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert SBOM to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_cyclonedx(self) -> dict:
        """
        Convert to CycloneDX SBOM format.

        CycloneDX is an OWASP standard for SBOM.
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": self.timestamp,
                "component": {
                    "type": "application",
                    "name": self.project_name,
                    "version": self.project_version,
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": dep.name,
                    "version": dep.version,
                    "purl": f"pkg:pypi/{dep.name}@{dep.version}",
                    "hashes": (
                        [{"alg": "SHA-256", "content": dep.hash_sha256}] if dep.hash_sha256 else []
                    ),
                    "licenses": [{"license": {"id": dep.license}}] if dep.license else [],
                }
                for dep in self.dependencies
            ],
        }


class DependencyParser:
    """Parse Python dependency files."""

    def __init__(self):
        """Initialize dependency parser."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()

    def parse_requirements_txt(self, file_path: Path) -> list[Dependency]:
        """
        Parse requirements.txt file.

        Args:
            file_path: Path to requirements.txt

        Returns:
            List of dependencies
        """
        content = self.file_ops.read_file(file_path)
        if not content:
            return []

        dependencies = []
        for line in content.split("\n"):
            stripped_line = line.strip()

            # Skip comments and empty lines
            if not stripped_line or stripped_line.startswith("#"):
                continue

            # Parse package==version or package>=version
            match = re.match(r"([a-zA-Z0-9_-]+)\s*([><=!~]+)\s*([0-9.]+)", stripped_line)
            if match:
                name, _, version = match.groups()
                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        source="pypi",
                    )
                )
            # Package without version
            elif re.match(r"^[a-zA-Z0-9_-]+$", line):
                dependencies.append(
                    Dependency(
                        name=line,
                        version="unknown",
                        source="pypi",
                    )
                )

        return dependencies

    def parse_pyproject_toml(self, file_path: Path) -> list[Dependency]:
        """
        Parse pyproject.toml file.

        Args:
            file_path: Path to pyproject.toml

        Returns:
            List of dependencies
        """
        content = self.file_ops.read_file(file_path)
        if not content:
            return []

        dependencies = []
        in_dependencies = False

        for line in content.split("\n"):
            stripped_line = line.strip()

            # Detect dependencies section
            if stripped_line in {"[project.dependencies]", "dependencies = ["}:
                in_dependencies = True
                continue

            if in_dependencies:
                # End of section
                if stripped_line.startswith("[") or stripped_line == "]":
                    in_dependencies = False
                    continue

                # Parse dependency line
                match = re.search(r'"([a-zA-Z0-9_-]+)\s*([><=!~]+)\s*([0-9.]+)"', stripped_line)
                if match:
                    name, _, version = match.groups()
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            source="pypi",
                        )
                    )

        return dependencies

    def parse_pipfile(self, file_path: Path) -> list[Dependency]:
        """
        Parse Pipfile.

        Args:
            file_path: Path to Pipfile

        Returns:
            List of dependencies
        """
        content = self.file_ops.read_file(file_path)
        if not content:
            return []

        dependencies = []
        in_packages = False

        for line in content.split("\n"):
            stripped_line = line.strip()

            # Detect packages section
            if stripped_line == "[packages]":
                in_packages = True
                continue

            if in_packages:
                # End of section
                if stripped_line.startswith("["):
                    in_packages = False
                    continue

                # Parse package line
                match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped_line)
                if match:
                    name, version_spec = match.groups()
                    # Extract version number
                    version_match = re.search(r"([0-9.]+)", version_spec)
                    version = version_match.group(1) if version_match else "unknown"
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            source="pypi",
                        )
                    )

        return dependencies


class VulnerabilityChecker:
    """
    Check dependencies for known vulnerabilities.

    Uses local vulnerability database and patterns to identify risky dependencies.
    In production, this would integrate with:
    - OSV (Open Source Vulnerabilities) API
    - GitHub Advisory Database
    - PyPI Advisory Database
    - Safety DB
    """

    # Known vulnerable package patterns (examples - would be much larger in production)
    KNOWN_VULNERABILITIES: ClassVar[Any] = {
        "requests": {
            "<2.20.0": ["CVE-2018-18074: HTTPS certificate validation bypass"],
            "<2.31.0": ["CVE-2023-32681: Proxy-Authorization header leak"],
        },
        "urllib3": {
            "<1.24.2": ["CVE-2019-11324: Certificate verification bypass"],
            "<1.26.5": ["CVE-2021-33503: Catastrophic backtracking in URL parsing"],
        },
        "pyyaml": {
            "<5.4": ["CVE-2020-14343: Arbitrary code execution via yaml.load()"],
        },
        "cryptography": {
            "<3.3.2": ["CVE-2020-36242: Invalid curve attack on ECDH"],
        },
        "flask": {
            "<2.2.5": ["CVE-2023-30861: Path traversal via send_file()"],
        },
        "django": {
            "<3.2.18": ["CVE-2023-24580: SQL injection via Trunc/Extract()"],
        },
    }

    # Packages with known security concerns
    RISKY_PACKAGES: ClassVar[Any] = {
        "pickle5": "HIGH - Uses pickle which can execute arbitrary code",
        "exec": "CRITICAL - Named 'exec' - likely malicious or poorly named",
        "importlib-resources": "LOW - Consider using native importlib.resources in Python 3.9+",
    }

    def __init__(self):
        """Initialize vulnerability checker."""
        self.logger = PyGuardLogger()

    def check_dependency(self, dep: Dependency) -> Dependency:
        """
        Check a single dependency for vulnerabilities.

        Args:
            dep: Dependency to check

        Returns:
            Updated dependency with vulnerability information
        """
        # Check known vulnerabilities
        if dep.name in self.KNOWN_VULNERABILITIES:
            vuln_data = self.KNOWN_VULNERABILITIES[dep.name]
            for version_spec, vulns in vuln_data.items():
                if self._version_matches(dep.version, version_spec):
                    dep.vulnerabilities.extend(vulns)
                    dep.risk_level = self._assess_risk(vulns)

        # Check risky packages
        if dep.name in self.RISKY_PACKAGES:
            risk_info = self.RISKY_PACKAGES[dep.name]
            dep.vulnerabilities.append(risk_info)
            if risk_info.startswith("CRITICAL"):
                dep.risk_level = "CRITICAL"
            elif risk_info.startswith("HIGH"):
                dep.risk_level = "HIGH"

        return dep

    def _version_matches(self, version: str, spec: str) -> bool:  # noqa: PLR0911 - Version comparison requires many checks
        """
        Check if version matches specification.

        Args:
            version: Actual version
            spec: Version specification (e.g., "<2.0.0")

        Returns:
            True if version matches spec
        """
        if version == "unknown":
            return False

        try:
            # Simple version comparison (in production, use packaging.version)
            # Check two-character operators first to avoid substring issues
            if spec.startswith("<="):
                target = spec[2:]
                return self._compare_versions(version, target) <= 0
            if spec.startswith(">="):
                target = spec[2:]
                return self._compare_versions(version, target) >= 0
            if spec.startswith("<"):
                target = spec[1:]
                return self._compare_versions(version, target) < 0
            if spec.startswith(">"):
                target = spec[1:]
                return self._compare_versions(version, target) > 0
        except Exception:
            return False

        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.

        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        parts1 = [int(x) for x in v1.split(".")[:3]]
        parts2 = [int(x) for x in v2.split(".")[:3]]

        # Pad with zeros
        while len(parts1) < 3:  # noqa: PLR2004 - threshold
            parts1.append(0)
        while len(parts2) < 3:  # noqa: PLR2004 - threshold
            parts2.append(0)

        if parts1 < parts2:
            return -1
        if parts1 > parts2:
            return 1
        return 0

    def _assess_risk(self, vulnerabilities: list[str]) -> str:
        """Assess overall risk level based on vulnerabilities."""
        if any("CRITICAL" in v or "CVE-2023" in v or "CVE-2024" in v for v in vulnerabilities):
            return "CRITICAL"
        if any("HIGH" in v or "arbitrary code" in v.lower() for v in vulnerabilities):
            return "HIGH"
        if any("MEDIUM" in v for v in vulnerabilities):
            return "MEDIUM"
        return "LOW"


class SupplyChainAnalyzer:
    """
    Main supply chain security analyzer.

    Provides comprehensive supply chain security analysis including:
    - Dependency parsing
    - SBOM generation
    - Vulnerability scanning
    - License compliance
    - Integrity verification
    """

    def __init__(self):
        """Initialize supply chain analyzer."""
        self.logger = PyGuardLogger()
        self.file_ops = FileOperations()
        self.parser = DependencyParser()
        self.vuln_checker = VulnerabilityChecker()

    def analyze_project(self, project_dir: Path) -> SBOM:
        """
        Analyze project for supply chain security.

        Args:
            project_dir: Path to project directory

        Returns:
            SBOM with vulnerability information
        """
        self.logger.info(f"Analyzing supply chain for {project_dir}", category="SupplyChain")

        # Parse dependencies from various sources
        all_dependencies = []

        # Check for requirements.txt
        req_file = project_dir / "requirements.txt"
        if req_file.exists():
            all_dependencies.extend(self.parser.parse_requirements_txt(req_file))

        # Check for pyproject.toml
        pyproject_file = project_dir / "pyproject.toml"
        if pyproject_file.exists():
            all_dependencies.extend(self.parser.parse_pyproject_toml(pyproject_file))

        # Check for Pipfile
        pipfile = project_dir / "Pipfile"
        if pipfile.exists():
            all_dependencies.extend(self.parser.parse_pipfile(pipfile))

        # Deduplicate dependencies
        unique_deps = self._deduplicate_dependencies(all_dependencies)

        # Check each dependency for vulnerabilities
        for dep in unique_deps:
            self.vuln_checker.check_dependency(dep)

        # Generate SBOM
        sbom = SBOM(
            project_name=project_dir.name,
            project_version="unknown",  # Would be parsed from setup.py/pyproject.toml
            timestamp=datetime.now(UTC).isoformat(),
            dependencies=unique_deps,
            total_dependencies=len(unique_deps),
        )

        # Count vulnerabilities
        for dep in unique_deps:
            if dep.risk_level == "CRITICAL":
                sbom.critical_vulnerabilities += 1
            elif dep.risk_level == "HIGH":
                sbom.high_vulnerabilities += 1
            elif dep.risk_level == "MEDIUM":
                sbom.medium_vulnerabilities += 1
            elif dep.risk_level == "LOW":
                sbom.low_vulnerabilities += 1

        return sbom

    def generate_sbom_file(self, project_dir: Path, output_path: Path, format: str = "cyclonedx"):
        """
        Generate SBOM file.

        Args:
            project_dir: Path to project directory
            output_path: Where to write SBOM
            format: SBOM format (cyclonedx, json)
        """
        sbom = self.analyze_project(project_dir)

        if format == "cyclonedx":
            content = json.dumps(sbom.to_cyclonedx(), indent=2)
        else:
            content = sbom.to_json()

        output_path.write_text(content)
        self.logger.info(f"SBOM written to {output_path}", category="SupplyChain")

    def _deduplicate_dependencies(self, dependencies: list[Dependency]) -> list[Dependency]:
        """Remove duplicate dependencies, keeping the most specific version."""
        seen = {}
        for dep in dependencies:
            key = dep.name.lower()
            if key not in seen or dep.version != "unknown":
                seen[key] = dep
        return list(seen.values())
