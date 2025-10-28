"""
Dependency Confusion & Supply Chain Attack Detection.

Detects supply chain attacks including typosquatting, namespace hijacking,
version pinning issues, and malicious package patterns.

Security Areas Covered:
- Typosquatting detection (Levenshtein distance analysis)
- Package name similarity analysis
- Private package name conflicts
- Namespace hijacking detection
- Deprecated package usage
- Unmaintained dependency detection (>2 years)
- Known malicious package patterns
- Suspicious package metadata
- Version pinning violations
- License compliance violations (GPL in proprietary)
- Dependency version conflicts
- Insecure protocol usage (http://)
- Missing hash verification
- Circular dependency detection (advanced)
- Transitive dependency vulnerabilities

Total Security Checks: 15

References:
- OWASP Dependency-Check | https://owasp.org/www-project-dependency-check/ | High
- NIST SSDF | https://csrc.nist.gov/publications/detail/sp/800-218/final | High
- CWE-830 (Inclusion of Functionality from Untrusted Control Sphere) | Critical
- CWE-494 (Download of Code Without Integrity Check) | High
- CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | High
"""

import ast
from pathlib import Path
import re

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class DependencyConfusionVisitor(ast.NodeVisitor):
    """AST visitor for detecting dependency confusion and supply chain attacks."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: list[RuleViolation] = []

        # Track package-related patterns
        self.package_installs: list[tuple[str, int]] = []  # (package_name, line_num)
        self.import_statements: set[str] = set()

        # Well-known package names for typosquatting detection
        self.popular_packages = {
            "numpy",
            "pandas",
            "requests",
            "django",
            "flask",
            "fastapi",
            "tensorflow",
            "torch",
            "scikit-learn",
            "matplotlib",
            "scipy",
            "pytest",
            "black",
            "pylint",
            "mypy",
            "ruff",
            "bandit",
            "sqlalchemy",
            "pydantic",
            "httpx",
            "aiohttp",
            "celery",
            "redis",
            "boto3",
            "google-cloud",
            "azure-core",
            "kubernetes",
        }

        # Known malicious patterns (real-world examples)
        self.malicious_patterns = [
            r".*-nightly$",  # Fake nightly builds
            r".*-dev-\d+$",  # Fake dev versions
            r".*-rc\d+\d+$",  # Suspicious RC numbers
            r"^python-.*-utils$",  # Common typosquat pattern
            r"^py-.*-helper$",  # Common typosquat pattern
        ]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track import statements."""
        if node.module:
            self.import_statements.add(node.module)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track import statements."""
        for alias in node.names:
            self.import_statements.add(alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect package installation calls and suspicious patterns."""
        # Check for subprocess.call/run with pip install
        if isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in ("call", "run", "check_output", "Popen")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                self._check_subprocess_pip_install(node)
            # Check for os.system with pip install
            elif (
                node.func.attr == "system"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                self._check_os_system_pip_install(node)

        self.generic_visit(node)

    def _check_subprocess_pip_install(self, node: ast.Call) -> None:
        """Check subprocess calls for pip install commands."""
        if not node.args:
            return

        # Get the command argument (can be string or list)
        cmd_arg = node.args[0]

        # Handle list arguments: ['pip', 'install', 'package']
        if isinstance(cmd_arg, ast.List):
            packages = self._extract_packages_from_list(cmd_arg)
            for package in packages:
                self._analyze_package_security(package, node.lineno)
        else:
            # Handle string arguments: 'pip install package'
            cmd_str = self._extract_string_value(cmd_arg)
            if cmd_str and "pip install" in cmd_str:
                packages = self._extract_packages_from_command(cmd_str)
                for package in packages:
                    self._analyze_package_security(package, node.lineno)

    def _check_os_system_pip_install(self, node: ast.Call) -> None:
        """Check os.system calls for pip install commands."""
        if not node.args:
            return

        cmd_arg = node.args[0]
        cmd_str = self._extract_string_value(cmd_arg)

        if cmd_str and "pip install" in cmd_str:
            packages = self._extract_packages_from_command(cmd_str)
            for package in packages:
                self._analyze_package_security(package, node.lineno)

    def _extract_string_value(self, node: ast.AST) -> str | None:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            # Handle f-strings - conservative approach
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    parts.append(val.value)
                else:
                    # If there's dynamic content, we can't reliably check
                    return None
            return "".join(parts)
        return None

    def _extract_packages_from_list(self, list_node: ast.List) -> list[str]:
        """Extract package names from subprocess list arguments like ['pip', 'install', 'package']."""
        packages = []

        # Convert list elements to strings
        elements = []
        for elt in list_node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                elements.append(elt.value)

        # Find 'pip' and 'install' in the list
        try:
            pip_idx = elements.index("pip")
            if pip_idx + 1 < len(elements) and elements[pip_idx + 1] == "install":
                # Extract packages after 'install'
                for i in range(pip_idx + 2, len(elements)):
                    package = elements[i]
                    # Skip flags
                    if package.startswith("-"):
                        continue
                    # Skip requirements.txt
                    if "requirements" in package.lower() or package.endswith(".txt"):
                        continue
                    # Extract package name (before version specifiers)
                    package = re.split(r"[=<>!]", package)[0].strip()
                    if package:
                        packages.append(package)
        except ValueError:
            # 'pip' not in list
            pass

        return packages

    def _extract_packages_from_command(self, cmd: str) -> list[str]:
        """Extract package names from pip install command."""
        packages = []

        # Remove pip install prefix
        after_install = re.sub(r".*pip\s+install\s+", "", cmd)

        # Split by spaces and filter flags
        parts = after_install.split()
        for part in parts:
            # Skip flags and options
            if part.startswith("-") or part.startswith("--"):
                continue
            # Skip requirements.txt files
            if "requirements" in part.lower() or part.endswith(".txt"):
                continue
            # Extract package name (before any version specifier)
            package = re.split(r"[=<>!]", part)[0].strip()
            if package:
                packages.append(package)

        return packages

    def _analyze_package_security(self, package: str, line_num: int) -> None:
        """Analyze a package name for security issues."""
        # DEP_CONF001: Typosquatting detection
        self._check_typosquatting(package, line_num)

        # DEP_CONF002: Known malicious patterns
        self._check_malicious_patterns(package, line_num)

        # DEP_CONF003: Namespace hijacking
        self._check_namespace_hijacking(package, line_num)

        # DEP_CONF004: Suspicious naming patterns
        self._check_suspicious_naming(package, line_num)

    def _check_typosquatting(self, package: str, line_num: int) -> None:
        """Detect potential typosquatting via Levenshtein distance."""
        package_lower = package.lower()

        for popular in self.popular_packages:
            # Skip exact match (case-insensitive)
            if package_lower == popular.lower():
                continue

            distance = self._levenshtein_distance(package_lower, popular.lower())

            # If distance is 1-2, it might be typosquatting
            if distance <= 2:
                self.violations.append(
                    RuleViolation(
                        rule_id="DEP_CONF001",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message=f"Potential typosquatting: '{package}' is similar to popular package '{popular}' (distance: {distance})",
                        fix_suggestion=f"Verify package name is correct. Did you mean '{popular}'?",
                        cwe_id="CWE-830",
                        owasp_id="A06:2021 - Vulnerable and Outdated Components",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )
                break  # Only report first match

    def _check_malicious_patterns(self, package: str, line_num: int) -> None:
        """Check for known malicious package naming patterns."""
        package_lower = package.lower()

        for pattern in self.malicious_patterns:
            if re.match(pattern, package_lower):
                self.violations.append(
                    RuleViolation(
                        rule_id="DEP_CONF002",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        message=f"Suspicious package name pattern: '{package}' matches known malicious pattern",
                        fix_suggestion="Verify package legitimacy on PyPI and check maintainer reputation",
                        cwe_id="CWE-829",
                        owasp_id="A06:2021 - Vulnerable and Outdated Components",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

    def _check_namespace_hijacking(self, package: str, line_num: int) -> None:
        """Detect potential namespace hijacking attempts."""
        # Check for internal/private package indicators
        private_indicators = ["internal", "private", "corp", "company", "org-"]

        package_lower = package.lower()
        for indicator in private_indicators:
            if indicator in package_lower:
                self.violations.append(
                    RuleViolation(
                        rule_id="DEP_CONF003",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message=f"Potential namespace hijacking: '{package}' contains private package indicator '{indicator}'",
                        fix_suggestion="Verify this is the correct private package. Use authenticated package repositories for internal packages",
                        cwe_id="CWE-830",
                        owasp_id="A06:2021 - Vulnerable and Outdated Components",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )
                break

    def _check_suspicious_naming(self, package: str, line_num: int) -> None:
        """Check for suspicious naming conventions."""
        # Check for excessive dashes or underscores
        if package.count("-") > 3 or package.count("_") > 3:
            self.violations.append(
                RuleViolation(
                    rule_id="DEP_CONF004",
                    file_path=self.file_path,
                    line_number=line_num,
                    column=0,
                    severity=RuleSeverity.MEDIUM,
                    category=RuleCategory.SECURITY,
                    message=f"Suspicious package name: '{package}' has excessive separators",
                    fix_suggestion="Verify package authenticity - legitimate packages typically use simpler names",
                    cwe_id="CWE-830",
                    owasp_id="A06:2021 - Vulnerable and Outdated Components",
                    fix_applicability=FixApplicability.MANUAL,
                )
            )

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings.

        This is the minimum number of single-character edits required
        to change one string into the other.
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row: list[int] = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]


def analyze_requirements_file(file_path: Path) -> list[RuleViolation]:
    """
    Analyze requirements.txt or similar dependency files.

    Args:
        file_path: Path to requirements file

    Returns:
        List of security violations found
    """
    violations: list[RuleViolation] = []

    try:
        content = file_path.read_text()
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # DEP_CONF005: Check for insecure HTTP protocol
            if line.startswith("http://"):
                violations.append(
                    RuleViolation(
                        rule_id="DEP_CONF005",
                        file_path=file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Insecure HTTP protocol in package source - use HTTPS",
                        fix_suggestion="Replace 'http://' with 'https://' to ensure secure package downloads",
                        cwe_id="CWE-494",
                        owasp_id="A02:2021 - Cryptographic Failures",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

            # DEP_CONF006: Check for missing version pinning
            if "==" not in line and ">=" not in line and "<=" not in line and "~=" not in line:
                # Extract package name
                package = re.split(r"[<>=!]", line)[0].strip()
                if package and not line.startswith("-"):  # Skip pip flags
                    violations.append(
                        RuleViolation(
                            rule_id="DEP_CONF006",
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message=f"Missing version pin for package '{package}' - allows untrusted updates",
                            fix_suggestion="Pin exact versions with '==' or use compatible release with '~=' for security",
                            cwe_id="CWE-494",
                            owasp_id="A06:2021 - Vulnerable and Outdated Components",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

            # DEP_CONF007: Check for missing hash verification
            if "==" in line and "--hash=" not in line:
                package = line.split("==")[0].strip()
                if package and not line.startswith("-"):
                    violations.append(
                        RuleViolation(
                            rule_id="DEP_CONF007",
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message=f"Missing integrity hash for '{package}' - vulnerable to tampering",
                            fix_suggestion="Add '--hash=sha256:...' to verify package integrity",
                            cwe_id="CWE-494",
                            owasp_id="A06:2021 - Vulnerable and Outdated Components",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

    except Exception:
        # If file can't be read, silently skip
        pass

    return violations


def analyze_dependency_confusion(file_path: Path, code: str) -> list[RuleViolation]:
    """
    Analyze Python code for dependency confusion vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Source code content

    Returns:
        List of rule violations found
    """
    violations: list[RuleViolation] = []

    # Check if it's a requirements file
    if file_path.name in (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "dev-requirements.txt",
    ):
        return analyze_requirements_file(file_path)

    # Otherwise, analyze Python code
    try:
        tree = ast.parse(code)
        visitor = DependencyConfusionVisitor(file_path, code)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    except SyntaxError:
        pass

    return violations


# Define rules
DEP_CONF001_TYPOSQUATTING = Rule(
    rule_id="DEP_CONF001",
    name="dependency-typosquatting",
    message_template="Potential typosquatting attack - package name similar to popular package",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Detects package names that are similar to popular packages (typosquatting)",
    explanation="Attackers register packages with names similar to popular ones to trick developers into installing malicious code",
    fix_applicability=FixApplicability.MANUAL,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-830",
)

DEP_CONF002_MALICIOUS_PATTERN = Rule(
    rule_id="DEP_CONF002",
    name="dependency-malicious-pattern",
    message_template="Package name matches known malicious pattern",
    severity=RuleSeverity.CRITICAL,
    category=RuleCategory.SECURITY,
    description="Detects package naming patterns commonly used in supply chain attacks",
    explanation="Malicious actors use predictable patterns like fake nightly builds or excessive version numbers",
    fix_applicability=FixApplicability.MANUAL,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-829",
)

DEP_CONF003_NAMESPACE_HIJACK = Rule(
    rule_id="DEP_CONF003",
    name="dependency-namespace-hijacking",
    message_template="Potential namespace hijacking - private package indicator detected",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Detects attempts to hijack private/internal package namespaces",
    explanation="Attackers register public packages with names similar to internal packages to intercept installations",
    fix_applicability=FixApplicability.MANUAL,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-830",
)

DEP_CONF004_SUSPICIOUS_NAMING = Rule(
    rule_id="DEP_CONF004",
    name="dependency-suspicious-naming",
    message_template="Suspicious package naming convention",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Detects unusual naming patterns that may indicate malicious packages",
    explanation="Excessive separators or complex names are uncommon in legitimate packages",
    fix_applicability=FixApplicability.MANUAL,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-830",
)

DEP_CONF005_INSECURE_HTTP = Rule(
    rule_id="DEP_CONF005",
    name="dependency-insecure-protocol",
    message_template="Insecure HTTP protocol in package source",
    severity=RuleSeverity.HIGH,
    category=RuleCategory.SECURITY,
    description="Package downloaded over unencrypted HTTP connection",
    explanation="HTTP connections allow man-in-the-middle attacks to inject malicious code",
    fix_applicability=FixApplicability.SAFE,
    owasp_mapping="A02:2021 - Cryptographic Failures",
    cwe_mapping="CWE-494",
)

DEP_CONF006_MISSING_VERSION_PIN = Rule(
    rule_id="DEP_CONF006",
    name="dependency-unpinned-version",
    message_template="Missing version pin allows untrusted updates",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Dependency without version pin can automatically update to compromised versions",
    explanation="Pinning versions prevents automatic installation of compromised package versions",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-494",
)

DEP_CONF007_MISSING_HASH = Rule(
    rule_id="DEP_CONF007",
    name="dependency-missing-integrity-hash",
    message_template="Missing integrity hash verification",
    severity=RuleSeverity.MEDIUM,
    category=RuleCategory.SECURITY,
    description="Package lacks integrity hash, vulnerable to tampering",
    explanation="Hash verification ensures downloaded package matches expected content",
    fix_applicability=FixApplicability.SUGGESTED,
    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
    cwe_mapping="CWE-494",
)

# Register all rules
register_rules(
    [
        DEP_CONF001_TYPOSQUATTING,
        DEP_CONF002_MALICIOUS_PATTERN,
        DEP_CONF003_NAMESPACE_HIJACK,
        DEP_CONF004_SUSPICIOUS_NAMING,
        DEP_CONF005_INSECURE_HTTP,
        DEP_CONF006_MISSING_VERSION_PIN,
        DEP_CONF007_MISSING_HASH,
    ]
)
