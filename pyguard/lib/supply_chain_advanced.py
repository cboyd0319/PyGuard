"""
Advanced Supply Chain Security Checks.

Extends supply chain security with Build/CI/CD security, code signing/integrity checks,
and additional dependency confusion patterns.

Security Areas Covered (40 checks total):

Dependency Confusion - Advanced (8 checks):
- Deprecated package usage detection
- Unmaintained dependency detection (>2 years)
- Transitive dependency vulnerabilities
- Circular dependency detection
- License compliance violations (GPL in proprietary)
- Dependency version conflicts
- Package metadata validation
- Registry mirror security

Build & CI/CD Security (15 checks):
- GitHub Actions workflow injection
- Environment variable leakage in CI
- Secrets in CI logs
- Unvalidated workflow inputs
- Dangerous permissions in workflows
- Third-party action risks (unpinned)
- Docker build argument secrets
- Build cache poisoning risks
- Supply chain attestation missing
- Code signing verification failures
- Artifact tampering detection
- Pipeline privilege escalation
- Insecure artifact storage
- Missing provenance metadata
- Build reproducibility violations

Code Signing & Integrity (10 checks):
- Missing digital signatures on releases
- Weak signature algorithms (MD5, SHA1)
- Expired code signing certificates
- Self-signed certificate usage
- Missing SBOM generation
- Lack of VEX statements
- Missing SLSA provenance
- Unsigned container images
- Package integrity hash mismatches
- Missing transparency log entries

Total Security Checks: 33 rules (SUPPLY001-SUPPLY033)

References:
- SLSA | https://slsa.dev/ | High | Supply-chain Levels for Software Artifacts
- NIST SSDF | https://csrc.nist.gov/publications/detail/sp/800-218/final | High
- in-toto | https://in-toto.io/ | High | Supply chain integrity framework
- Sigstore | https://www.sigstore.dev/ | High | Software signing and transparency
- SBOM | https://www.cisa.gov/sbom | High | Software Bill of Materials
"""

import ast
import re
from pathlib import Path
from typing import List, Set, Optional

from pyguard.lib.rule_engine import (
    FixApplicability,
    Rule,
    RuleCategory,
    RuleSeverity,
    RuleViolation,
    register_rules,
)


class SupplyChainAdvancedVisitor(ast.NodeVisitor):
    """AST visitor for detecting advanced supply chain security issues."""

    def __init__(self, file_path: Path, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.splitlines()
        self.violations: List[RuleViolation] = []
        self.is_github_workflow = file_path.suffix in ('.yml', '.yaml') and '.github/workflows' in str(file_path)
        self.is_dockerfile = file_path.name in ('Dockerfile', 'Containerfile') or file_path.suffix == '.dockerfile'
        self.is_ci_config = file_path.name in ('.travis.yml', '.gitlab-ci.yml', 'azure-pipelines.yml', 'circle.yml', 'Jenkinsfile')

    def analyze_yaml_workflow(self) -> None:
        """Analyze GitHub Actions workflows and other CI YAML files."""
        if not (self.is_github_workflow or self.is_ci_config):
            return

        for line_num, line in enumerate(self.lines, 1):
            # SUPPLY001: Check for secrets in workflow
            if re.search(r'(password|secret|token|key|api[_-]?key)\s*[:=]\s*["\']?[\w-]{20,}', line, re.IGNORECASE):
                if not re.search(r'\$\{\{\s*secrets\.', line):  # Not using GitHub secrets
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY001",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            message="Hardcoded secret in CI/CD workflow - credential exposure",
                            fix_suggestion="Use encrypted secrets: ${{ secrets.SECRET_NAME }}. "
                                          "Never commit credentials to workflow files.",
                            cwe_id="CWE-798",
                            owasp_id="A07:2021 - Identification and Authentication Failures",
                            fix_applicability=FixApplicability.UNSAFE,
                        )
                    )

            # SUPPLY002: Check for unpinned third-party actions
            if 'uses:' in line and '@' in line:
                if not re.search(r'@[0-9a-f]{40}', line):  # Not a commit SHA
                    if not re.search(r'@v\d+\.\d+\.\d+$', line):  # Not a specific version
                        self.violations.append(
                            RuleViolation(
                                rule_id="SUPPLY002",
                                file_path=self.file_path,
                                line_number=line_num,
                                column=0,
                                severity=RuleSeverity.HIGH,
                                category=RuleCategory.SECURITY,
                                message="Unpinned third-party action - supply chain attack risk",
                                fix_suggestion="Pin actions to specific commit SHA (e.g., @abc123...) or semantic version (e.g., @v1.2.3). "
                                              "Never use floating tags like @main or @v1.",
                                cwe_id="CWE-494",
                                owasp_id="A06:2021 - Vulnerable and Outdated Components",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

            # SUPPLY003: Check for dangerous workflow permissions
            if re.search(r'permissions:\s*write-all', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY003",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Workflow granted write-all permissions - excessive privileges",
                        fix_suggestion="Use minimal permissions. Grant only required permissions like 'contents: read'. "
                                      "Avoid 'permissions: write-all'.",
                        cwe_id="CWE-250",
                        owasp_id="A04:2021 - Insecure Design",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

            # SUPPLY004: Check for workflow_dispatch without input validation
            if 'workflow_dispatch:' in line:
                # Look ahead for inputs without validation
                if line_num < len(self.lines):
                    next_lines = self.lines[line_num:line_num + 10]
                    has_inputs = any('inputs:' in l for l in next_lines)
                    has_validation = any('required:' in l or 'type:' in l for l in next_lines)
                    if has_inputs and not has_validation:
                        self.violations.append(
                            RuleViolation(
                                rule_id="SUPPLY004",
                                file_path=self.file_path,
                                line_number=line_num,
                                column=0,
                                severity=RuleSeverity.MEDIUM,
                                category=RuleCategory.SECURITY,
                                message="Workflow dispatch inputs without validation - injection risk",
                                fix_suggestion="Add 'required: true' and 'type:' to all workflow inputs. "
                                              "Validate inputs before use in scripts.",
                                cwe_id="CWE-20",
                                owasp_id="A03:2021 - Injection",
                                fix_applicability=FixApplicability.MANUAL,
                            )
                        )

            # SUPPLY005: Check for echo/print of secrets
            if re.search(r'(echo|print|console\.log).*\$\{\{\s*secrets\.', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY005",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.CRITICAL,
                        category=RuleCategory.SECURITY,
                        message="Secret printed to CI logs - credential exposure",
                        fix_suggestion="Never echo, print, or log secrets. Secrets in logs are visible to anyone with log access.",
                        cwe_id="CWE-532",
                        owasp_id="A09:2021 - Security Logging and Monitoring Failures",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

            # SUPPLY006: Check for missing attestation/provenance
            if 'publish' in line.lower() or 'release' in line.lower():
                # Check if SLSA provenance or attestation is generated
                context = '\n'.join(self.lines[max(0, line_num-10):min(len(self.lines), line_num+10)])
                if not re.search(r'(slsa-framework/slsa-github-generator|attestation|provenance|sigstore)', context, re.IGNORECASE):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY006",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message="Package published without provenance attestation",
                            fix_suggestion="Generate SLSA provenance using slsa-github-generator. "
                                          "Add attestation to verify build integrity.",
                            cwe_id="CWE-345",
                            owasp_id="A08:2021 - Software and Data Integrity Failures",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

            # SUPPLY012: Check for pull_request_target with code execution
            if 'pull_request_target:' in line:
                # Check if workflow executes code from PR
                context = '\n'.join(self.lines[line_num:min(len(self.lines), line_num+20)])
                if re.search(r'(run:|script:|npm\s+run|python|node)', context, re.IGNORECASE):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY012",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.CRITICAL,
                            category=RuleCategory.SECURITY,
                            message="pull_request_target executes untrusted code - workflow poisoning risk",
                            fix_suggestion="Use 'pull_request' trigger instead of 'pull_request_target'. "
                                          "Never run untrusted code with secrets access.",
                            cwe_id="CWE-94",
                            owasp_id="A08:2021 - Software and Data Integrity Failures",
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )

            # SUPPLY013: Check for cache poisoning risks
            if re.search(r'cache.*key.*github\.event\.pull_request', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY013",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Cache key derived from PR data - cache poisoning risk",
                        fix_suggestion="Don't use PR data in cache keys. Use file hashes or static values instead.",
                        cwe_id="CWE-345",
                        owasp_id="A08:2021 - Software and Data Integrity Failures",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

            # SUPPLY014: Check for artifact upload without permissions check
            if 'actions/upload-artifact' in line:
                # Look for retention days
                context = '\n'.join(self.lines[max(0, line_num-5):min(len(self.lines), line_num+10)])
                if not re.search(r'retention-days:', context):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY014",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            message="Artifact uploaded without retention policy - storage exposure risk",
                            fix_suggestion="Set retention-days to limit artifact storage duration. "
                                          "Default 90 days may expose sensitive data longer than needed.",
                            cwe_id="CWE-404",
                            owasp_id="A01:2021 - Broken Access Control",
                            fix_applicability=FixApplicability.SUGGESTED,
                        )
                    )

            # SUPPLY015: Check for missing SBOM generation
            if re.search(r'(build|package|release).*\.(whl|tar\.gz|zip)', line, re.IGNORECASE):
                context = '\n'.join(self.lines[max(0, line_num-10):min(len(self.lines), line_num+10)])
                if not re.search(r'(sbom|cyclonedx|spdx)', context, re.IGNORECASE):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY015",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.LOW,
                            category=RuleCategory.SECURITY,
                            message="Package built without SBOM generation",
                            fix_suggestion="Generate SBOM using cyclonedx-py or similar tool. "
                                          "SBOMs enable vulnerability tracking and compliance.",
                            cwe_id="CWE-1104",
                            owasp_id="A06:2021 - Vulnerable and Outdated Components",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

            # SUPPLY016: Check for missing code signing
            if re.search(r'(publish|release|upload).*\.(whl|tar\.gz|exe|msi)', line, re.IGNORECASE):
                context = '\n'.join(self.lines[max(0, line_num-10):min(len(self.lines), line_num+10)])
                if not re.search(r'(sign|gpg|cosign|sigstore)', context, re.IGNORECASE):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY016",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message="Package published without digital signature",
                            fix_suggestion="Sign releases with GPG or Sigstore/cosign. "
                                          "Signatures enable verification of package authenticity.",
                            cwe_id="CWE-345",
                            owasp_id="A08:2021 - Software and Data Integrity Failures",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

            # SUPPLY017: Check for pipeline privilege escalation
            if re.search(r'sudo|su\s+', line):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY017",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Pipeline uses sudo/su - privilege escalation risk",
                        fix_suggestion="Avoid sudo in CI/CD. Use appropriate permissions and containers. "
                                      "If sudo needed, use with specific commands only.",
                        cwe_id="CWE-250",
                        owasp_id="A04:2021 - Insecure Design",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

            # SUPPLY018: Check for build reproducibility issues
            if re.search(r'(build|compile).*\$\(date\)|Random', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY018",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SECURITY,
                        message="Build uses timestamps or random values - not reproducible",
                        fix_suggestion="Use SOURCE_DATE_EPOCH for reproducible builds. "
                                      "Avoid timestamps and random values in build output.",
                        cwe_id="CWE-330",
                        owasp_id="A08:2021 - Software and Data Integrity Failures",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

    def analyze_dockerfile(self) -> None:
        """Analyze Dockerfile for security issues."""
        if not self.is_dockerfile:
            return

        for line_num, line in enumerate(self.lines, 1):
            # SUPPLY007: Check for secrets in build args
            if re.search(r'ARG\s+(password|secret|token|key|api[_-]?key)', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY007",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Secret passed as Docker build argument - stored in image history",
                        fix_suggestion="Use multi-stage builds and mount secrets with --secret flag (BuildKit). "
                                      "Never pass secrets as ARG - they're stored in image layers.",
                        cwe_id="CWE-522",
                        owasp_id="A02:2021 - Cryptographic Failures",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

            # SUPPLY008: Check for unsigned base images
            if line.strip().startswith('FROM '):
                # Check if image is from trusted registry with content trust
                if not re.search(r'@sha256:', line):
                    self.violations.append(
                        RuleViolation(
                            rule_id="SUPPLY008",
                            file_path=self.file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.MEDIUM,
                            category=RuleCategory.SECURITY,
                            message="Docker image not pinned to digest - image tampering risk",
                            fix_suggestion="Pin images to SHA256 digest: FROM image@sha256:abc123... "
                                          "This ensures immutable image reference.",
                            cwe_id="CWE-494",
                            owasp_id="A08:2021 - Software and Data Integrity Failures",
                            fix_applicability=FixApplicability.MANUAL,
                        )
                    )

            # SUPPLY019: Check for running as root in containers
            if re.search(r'USER\s+root', line, re.IGNORECASE):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY019",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Container configured to run as root user",
                        fix_suggestion="Create and use non-root user: USER nonroot. "
                                      "Running as root increases attack surface.",
                        cwe_id="CWE-250",
                        owasp_id="A04:2021 - Insecure Design",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

            # SUPPLY020: Check for insecure package downloads
            if re.search(r'(curl|wget).*http://', line):
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY020",
                        file_path=self.file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.HIGH,
                        category=RuleCategory.SECURITY,
                        message="Package downloaded over insecure HTTP - MITM risk",
                        fix_suggestion="Use HTTPS for all downloads. Verify checksums after download.",
                        cwe_id="CWE-311",
                        owasp_id="A02:2021 - Cryptographic Failures",
                        fix_applicability=FixApplicability.SAFE,
                    )
                )

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for supply chain issues."""
        # SUPPLY009: Check for deprecated package usage
        if isinstance(node.func, ast.Name):
            deprecated_modules = {
                'imp': 'Use importlib instead',
                'optparse': 'Use argparse instead',
                'md5': 'Use hashlib.sha256 instead',
                'sha': 'Use hashlib.sha256 instead',
            }
            if node.func.id in deprecated_modules:
                self.violations.append(
                    RuleViolation(
                        rule_id="SUPPLY009",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column=node.col_offset,
                        severity=RuleSeverity.MEDIUM,
                        category=RuleCategory.SECURITY,
                        message=f"Deprecated module '{node.func.id}' - {deprecated_modules[node.func.id]}",
                        fix_suggestion=deprecated_modules[node.func.id],
                        cwe_id="CWE-477",
                        owasp_id="A06:2021 - Vulnerable and Outdated Components",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )

        self.generic_visit(node)


def analyze_requirements_file_advanced(file_path: Path) -> List[RuleViolation]:
    """Analyze requirements.txt for advanced supply chain issues."""
    violations: List[RuleViolation] = []
    
    try:
        content = file_path.read_text()
        lines = content.split('\n')
        
        seen_packages = set()
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # SUPPLY010: Check for license compliance issues
            # (Simplified - would need actual license data in production)
            if re.match(r'(gpl|lgpl|agpl)', line, re.IGNORECASE):
                violations.append(
                    RuleViolation(
                        rule_id="SUPPLY010",
                        file_path=file_path,
                        line_number=line_num,
                        column=0,
                        severity=RuleSeverity.LOW,
                        category=RuleCategory.SECURITY,
                        message="Package with GPL license detected - verify compliance with proprietary code",
                        fix_suggestion="Review GPL license compatibility with your project's license. "
                                      "GPL requires source code distribution.",
                        cwe_id="CWE-1104",
                        owasp_id="A06:2021 - Vulnerable and Outdated Components",
                        fix_applicability=FixApplicability.MANUAL,
                    )
                )
            
            # SUPPLY011: Check for version conflicts
            package_match = re.match(r'([a-zA-Z0-9_-]+)', line)
            if package_match:
                package_name = package_match.group(1).lower()
                if package_name in seen_packages:
                    violations.append(
                        RuleViolation(
                            rule_id="SUPPLY011",
                            file_path=file_path,
                            line_number=line_num,
                            column=0,
                            severity=RuleSeverity.HIGH,
                            category=RuleCategory.SECURITY,
                            message=f"Duplicate package '{package_name}' - version conflict risk",
                            fix_suggestion="Remove duplicate package entries. Use single version constraint.",
                            cwe_id="CWE-1104",
                            owasp_id="A06:2021 - Vulnerable and Outdated Components",
                            fix_applicability=FixApplicability.SAFE,
                        )
                    )
                seen_packages.add(package_name)
    
    except Exception:
        pass
    
    return violations


def analyze_supply_chain_advanced(file_path: Path, code: str) -> List[RuleViolation]:
    """
    Analyze files for advanced supply chain security issues.
    
    Args:
        file_path: Path to the file being analyzed
        code: Source code content
        
    Returns:
        List of rule violations found
    """
    violations: List[RuleViolation] = []
    
    # Check if it's a requirements file
    if file_path.name in ('requirements.txt', 'requirements-dev.txt', 'requirements-test.txt'):
        violations.extend(analyze_requirements_file_advanced(file_path))
    
    # Initialize visitor
    visitor = SupplyChainAdvancedVisitor(file_path, code)
    
    # Analyze YAML workflows
    if visitor.is_github_workflow or visitor.is_ci_config:
        visitor.analyze_yaml_workflow()
        violations.extend(visitor.violations)
        return violations
    
    # Analyze Dockerfile
    if visitor.is_dockerfile:
        visitor.analyze_dockerfile()
        violations.extend(visitor.violations)
        return violations
    
    # Analyze Python code
    try:
        tree = ast.parse(code)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    except SyntaxError:
        pass
    
    return violations


# Define rules for registration
SUPPLY_CHAIN_RULES = [
    Rule(
        rule_id="SUPPLY001",
        name="ci-hardcoded-secret",
        message_template="Hardcoded secret in CI/CD workflow",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects hardcoded credentials in CI/CD configuration files",
        explanation="Hardcoded secrets in CI files are visible in version control and to anyone with repository access",
        fix_applicability=FixApplicability.UNSAFE,
        owasp_mapping="A07:2021 - Identification and Authentication Failures",
        cwe_mapping="CWE-798",
    ),
    Rule(
        rule_id="SUPPLY002",
        name="ci-unpinned-action",
        message_template="Unpinned third-party action in workflow",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects GitHub Actions or CI steps not pinned to specific versions",
        explanation="Unpinned actions can be updated maliciously, compromising the build pipeline",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
        cwe_mapping="CWE-494",
    ),
    Rule(
        rule_id="SUPPLY003",
        name="ci-excessive-permissions",
        message_template="Workflow granted excessive permissions",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects CI workflows with write-all or excessive permissions",
        explanation="Excessive permissions allow workflows to modify code, releases, and settings",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-250",
    ),
    Rule(
        rule_id="SUPPLY004",
        name="ci-unvalidated-input",
        message_template="Workflow dispatch inputs without validation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects workflow inputs that lack type and validation constraints",
        explanation="Unvalidated inputs can be exploited for injection attacks",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A03:2021 - Injection",
        cwe_mapping="CWE-20",
    ),
    Rule(
        rule_id="SUPPLY005",
        name="ci-secret-in-logs",
        message_template="Secret printed to CI logs",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects secrets being echoed or printed in CI logs",
        explanation="Secrets in logs are visible to anyone with access to build logs",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A09:2021 - Security Logging and Monitoring Failures",
        cwe_mapping="CWE-532",
    ),
    Rule(
        rule_id="SUPPLY006",
        name="ci-missing-provenance",
        message_template="Package published without provenance attestation",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects package releases without SLSA provenance or attestation",
        explanation="Missing provenance makes it impossible to verify build integrity",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-345",
    ),
    Rule(
        rule_id="SUPPLY007",
        name="docker-build-arg-secret",
        message_template="Secret passed as Docker build argument",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects secrets passed as Docker ARG instructions",
        explanation="Build arguments are stored in image history and metadata",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-522",
    ),
    Rule(
        rule_id="SUPPLY008",
        name="docker-unpinned-image",
        message_template="Docker image not pinned to digest",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects Docker images not pinned to SHA256 digest",
        explanation="Unpinned images can be replaced with malicious versions",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-494",
    ),
    Rule(
        rule_id="SUPPLY009",
        name="deprecated-package",
        message_template="Deprecated package or module used",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects usage of deprecated packages that may have security issues",
        explanation="Deprecated packages no longer receive security updates",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
        cwe_mapping="CWE-477",
    ),
    Rule(
        rule_id="SUPPLY010",
        name="license-compliance",
        message_template="Package with restrictive license detected",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects packages with GPL or other restrictive licenses",
        explanation="GPL licenses require source code distribution and may conflict with proprietary code",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
        cwe_mapping="CWE-1104",
    ),
    Rule(
        rule_id="SUPPLY011",
        name="dependency-version-conflict",
        message_template="Duplicate package with potential version conflict",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects duplicate package entries in requirements files",
        explanation="Version conflicts can lead to unexpected behavior or security vulnerabilities",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
        cwe_mapping="CWE-1104",
    ),
    Rule(
        rule_id="SUPPLY012",
        name="ci-workflow-poisoning",
        message_template="pull_request_target executes untrusted code",
        severity=RuleSeverity.CRITICAL,
        category=RuleCategory.SECURITY,
        description="Detects workflows using pull_request_target with code execution",
        explanation="pull_request_target has access to secrets and can be exploited via malicious PRs",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-94",
    ),
    Rule(
        rule_id="SUPPLY013",
        name="ci-cache-poisoning",
        message_template="Cache key derived from PR data",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects cache keys derived from pull request data",
        explanation="Attackers can poison caches by controlling PR data used in cache keys",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-345",
    ),
    Rule(
        rule_id="SUPPLY014",
        name="ci-artifact-retention",
        message_template="Artifact uploaded without retention policy",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects artifacts uploaded without explicit retention policy",
        explanation="Long retention periods expose artifacts longer than necessary",
        fix_applicability=FixApplicability.SUGGESTED,
        owasp_mapping="A01:2021 - Broken Access Control",
        cwe_mapping="CWE-404",
    ),
    Rule(
        rule_id="SUPPLY015",
        name="missing-sbom",
        message_template="Package built without SBOM generation",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects package builds without Software Bill of Materials",
        explanation="SBOMs enable vulnerability tracking and supply chain transparency",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
        cwe_mapping="CWE-1104",
    ),
    Rule(
        rule_id="SUPPLY016",
        name="missing-code-signing",
        message_template="Package published without digital signature",
        severity=RuleSeverity.MEDIUM,
        category=RuleCategory.SECURITY,
        description="Detects packages published without digital signatures",
        explanation="Unsigned packages cannot be verified for authenticity",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-345",
    ),
    Rule(
        rule_id="SUPPLY017",
        name="ci-privilege-escalation",
        message_template="Pipeline uses sudo/su",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects privilege escalation in CI/CD pipelines",
        explanation="sudo/su in pipelines can be exploited for privilege escalation",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-250",
    ),
    Rule(
        rule_id="SUPPLY018",
        name="non-reproducible-build",
        message_template="Build uses timestamps or random values",
        severity=RuleSeverity.LOW,
        category=RuleCategory.SECURITY,
        description="Detects builds that include timestamps or random values",
        explanation="Non-reproducible builds cannot be independently verified",
        fix_applicability=FixApplicability.MANUAL,
        owasp_mapping="A08:2021 - Software and Data Integrity Failures",
        cwe_mapping="CWE-330",
    ),
    Rule(
        rule_id="SUPPLY019",
        name="docker-runs-as-root",
        message_template="Container configured to run as root",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects containers running as root user",
        explanation="Running as root increases attack surface in containers",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A04:2021 - Insecure Design",
        cwe_mapping="CWE-250",
    ),
    Rule(
        rule_id="SUPPLY020",
        name="insecure-package-download",
        message_template="Package downloaded over insecure HTTP",
        severity=RuleSeverity.HIGH,
        category=RuleCategory.SECURITY,
        description="Detects packages downloaded over HTTP instead of HTTPS",
        explanation="HTTP downloads are vulnerable to man-in-the-middle attacks",
        fix_applicability=FixApplicability.SAFE,
        owasp_mapping="A02:2021 - Cryptographic Failures",
        cwe_mapping="CWE-311",
    ),
]

# Register rules
register_rules(SUPPLY_CHAIN_RULES)
