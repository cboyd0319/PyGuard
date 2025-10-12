"""
Enhanced Standards Integration for PyGuard.

Integrates with additional security and compliance frameworks:
- NIST Cybersecurity Framework (CSF)
- ISO/IEC 27001:2022
- SOC 2 Type II
- PCI DSS 4.0
- GDPR technical requirements
- HIPAA Security Rule

References:
- NIST CSF v1.1 | https://nist.gov/cyberframework | High | Cybersecurity framework
- ISO 27001:2022 | https://iso.org/standard/27001 | High | Information security management
- SOC 2 | https://aicpa.org/soc2 | Medium | Service organization controls
- PCI DSS 4.0 | https://pcisecuritystandards.org | High | Payment card industry standards
- GDPR | https://gdpr.eu | High | EU data protection regulation
- HIPAA | https://hhs.gov/hipaa | Medium | Health information privacy
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from pyguard.lib.core import PyGuardLogger


@dataclass
class ComplianceRequirement:
    """Represents a compliance requirement from a standard."""

    standard: str  # NIST-CSF, ISO27001, SOC2, etc.
    control_id: str
    category: str
    description: str
    technical_controls: List[str]
    severity: str


@dataclass
class ComplianceMapping:
    """Maps PyGuard checks to compliance requirements."""

    pyguard_check: str
    standards: List[ComplianceRequirement]
    remediation: str


class StandardsMapper:
    """
    Maps security issues to multiple compliance frameworks.

    Helps organizations demonstrate compliance with various standards
    by showing how PyGuard checks align with requirements.
    """

    def __init__(self):
        """Initialize standards mapper."""
        self.logger = PyGuardLogger()
        self._initialize_mappings()

    def _initialize_mappings(self):
        """Initialize mappings between PyGuard checks and standards."""

        # NIST Cybersecurity Framework mappings
        self.nist_csf_mappings = {
            "code_injection": ComplianceRequirement(
                standard="NIST-CSF",
                control_id="PR.AC-4",
                category="PROTECT - Access Control",
                description="Access permissions and authorizations are managed",
                technical_controls=[
                    "Input validation",
                    "Least privilege",
                    "Code review",
                ],
                severity="HIGH",
            ),
            "hardcoded_credentials": ComplianceRequirement(
                standard="NIST-CSF",
                control_id="PR.AC-1",
                category="PROTECT - Access Control",
                description="Identities and credentials are issued, managed, verified",
                technical_controls=[
                    "Secrets management",
                    "Credential rotation",
                    "Access control",
                ],
                severity="HIGH",
            ),
            "weak_cryptography": ComplianceRequirement(
                standard="NIST-CSF",
                control_id="PR.DS-5",
                category="PROTECT - Data Security",
                description="Protections against data leaks are implemented",
                technical_controls=[
                    "Strong encryption",
                    "Key management",
                    "Algorithm selection",
                ],
                severity="MEDIUM",
            ),
        }

        # ISO 27001:2022 mappings
        self.iso27001_mappings = {
            "code_injection": ComplianceRequirement(
                standard="ISO-27001",
                control_id="8.8",
                category="Management of technical vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained",
                technical_controls=[
                    "Vulnerability scanning",
                    "Patch management",
                    "Secure coding",
                ],
                severity="HIGH",
            ),
            "hardcoded_credentials": ComplianceRequirement(
                standard="ISO-27001",
                control_id="8.5",
                category="Secure authentication",
                description="Secure authentication technologies shall be implemented",
                technical_controls=[
                    "Multi-factor authentication",
                    "Credential storage",
                    "Access management",
                ],
                severity="HIGH",
            ),
            "sql_injection": ComplianceRequirement(
                standard="ISO-27001",
                control_id="8.14",
                category="Secure coding",
                description="Secure coding principles shall be applied",
                technical_controls=[
                    "Input validation",
                    "Parameterized queries",
                    "Code review",
                ],
                severity="HIGH",
            ),
        }

        # SOC 2 Type II mappings
        self.soc2_mappings = {
            "code_injection": ComplianceRequirement(
                standard="SOC-2",
                control_id="CC6.1",
                category="Logical and Physical Access Controls",
                description="System access is restricted to authorized users",
                technical_controls=[
                    "Input validation",
                    "Authentication",
                    "Authorization",
                ],
                severity="HIGH",
            ),
            "hardcoded_credentials": ComplianceRequirement(
                standard="SOC-2",
                control_id="CC6.1",
                category="Logical and Physical Access Controls",
                description="Credentials are managed securely",
                technical_controls=[
                    "Secrets management",
                    "Credential rotation",
                    "Audit logging",
                ],
                severity="HIGH",
            ),
            "logging_sensitive_data": ComplianceRequirement(
                standard="SOC-2",
                control_id="CC7.2",
                category="System Monitoring",
                description="System monitoring excludes sensitive information",
                technical_controls=[
                    "Log sanitization",
                    "Data classification",
                    "Privacy controls",
                ],
                severity="MEDIUM",
            ),
        }

        # PCI DSS 4.0 mappings
        self.pci_dss_mappings = {
            "hardcoded_credentials": ComplianceRequirement(
                standard="PCI-DSS",
                control_id="8.2.1",
                category="User Authentication",
                description="Strong cryptography for authentication credentials",
                technical_controls=[
                    "Credential encryption",
                    "Key management",
                    "Secure storage",
                ],
                severity="HIGH",
            ),
            "weak_cryptography": ComplianceRequirement(
                standard="PCI-DSS",
                control_id="4.2",
                category="Encryption",
                description="Strong cryptography and security protocols",
                technical_controls=[
                    "TLS 1.2+",
                    "Strong ciphers",
                    "Key rotation",
                ],
                severity="HIGH",
            ),
            "sql_injection": ComplianceRequirement(
                standard="PCI-DSS",
                control_id="6.5.1",
                category="Secure Development",
                description="Protection against injection flaws",
                technical_controls=[
                    "Input validation",
                    "Parameterized queries",
                    "WAF rules",
                ],
                severity="HIGH",
            ),
        }

    def get_compliance_mappings(self, issue_type: str) -> List[ComplianceRequirement]:
        """
        Get all compliance requirements for a specific issue type.

        Args:
            issue_type: Type of security issue

        Returns:
            List of compliance requirements across all standards
        """
        mappings = []

        # Check all standard mappings
        for mapping_dict in [
            self.nist_csf_mappings,
            self.iso27001_mappings,
            self.soc2_mappings,
            self.pci_dss_mappings,
        ]:
            if issue_type in mapping_dict:
                mappings.append(mapping_dict[issue_type])

        return mappings

    def generate_compliance_report(
        self, issues: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """
        Generate a compliance report showing how issues map to standards.

        Args:
            issues: List of detected security issues

        Returns:
            Dictionary mapping standards to their requirements
        """
        report = {
            "NIST-CSF": [],
            "ISO-27001": [],
            "SOC-2": [],
            "PCI-DSS": [],
        }

        for issue in issues:
            issue_type = issue.get("type", "unknown")
            mappings = self.get_compliance_mappings(issue_type)

            for mapping in mappings:
                report[mapping.standard].append(
                    {
                        "control_id": mapping.control_id,
                        "category": mapping.category,
                        "issue_type": issue_type,
                        "severity": mapping.severity,
                    }
                )

        return report

    def check_standard_compliance(
        self, standard: str, issues: List[Dict]
    ) -> Dict[str, any]:
        """
        Check compliance with a specific standard.

        Args:
            standard: Standard to check (NIST-CSF, ISO-27001, etc.)
            issues: List of detected issues

        Returns:
            Compliance status and gaps
        """
        mapping_dict = {
            "NIST-CSF": self.nist_csf_mappings,
            "ISO-27001": self.iso27001_mappings,
            "SOC-2": self.soc2_mappings,
            "PCI-DSS": self.pci_dss_mappings,
        }.get(standard)

        if not mapping_dict:
            return {"error": f"Unknown standard: {standard}"}

        # Identify violations
        violations = []
        for issue in issues:
            issue_type = issue.get("type", "unknown")
            if issue_type in mapping_dict:
                violations.append(
                    {
                        "control_id": mapping_dict[issue_type].control_id,
                        "issue": issue,
                        "requirement": mapping_dict[issue_type].description,
                    }
                )

        return {
            "standard": standard,
            "total_violations": len(violations),
            "violations": violations,
            "compliant": len(violations) == 0,
        }


class GDPRTechnicalControls:
    """
    GDPR technical requirements mapper.

    Maps security issues to GDPR Articles requiring technical measures.
    """

    def __init__(self):
        """Initialize GDPR mapper."""
        self.logger = PyGuardLogger()

    def check_gdpr_technical_requirements(
        self, issues: List[Dict]
    ) -> Dict[str, any]:
        """
        Check GDPR technical requirements.

        Args:
            issues: List of detected issues

        Returns:
            GDPR compliance status
        """
        # Article 32: Security of processing
        security_issues = [
            issue
            for issue in issues
            if issue.get("severity") in ["HIGH", "CRITICAL"]
        ]

        # Article 25: Data protection by design and by default
        privacy_issues = [
            issue
            for issue in issues
            if "logging" in issue.get("type", "").lower()
            or "data" in issue.get("type", "").lower()
        ]

        return {
            "article_32_violations": len(security_issues),
            "article_25_violations": len(privacy_issues),
            "compliant": len(security_issues) == 0 and len(privacy_issues) == 0,
            "recommendations": [
                "Implement encryption at rest and in transit",
                "Regular security testing and assessment",
                "Pseudonymization of personal data",
                "Data minimization in logging",
            ],
        }


class HIPAASecurityRule:
    """
    HIPAA Security Rule mapper.

    Maps security issues to HIPAA technical safeguards.
    """

    def __init__(self):
        """Initialize HIPAA mapper."""
        self.logger = PyGuardLogger()

    def check_hipaa_compliance(self, issues: List[Dict]) -> Dict[str, any]:
        """
        Check HIPAA Security Rule compliance.

        Args:
            issues: List of detected issues

        Returns:
            HIPAA compliance status
        """
        # Technical Safeguards
        access_control_issues = [
            issue
            for issue in issues
            if "credential" in issue.get("type", "").lower()
            or "authentication" in issue.get("type", "").lower()
        ]

        encryption_issues = [
            issue
            for issue in issues
            if "crypto" in issue.get("type", "").lower()
            or "encryption" in issue.get("type", "").lower()
        ]

        audit_issues = [
            issue
            for issue in issues
            if "logging" in issue.get("type", "").lower()
        ]

        return {
            "access_control_violations": len(access_control_issues),
            "encryption_violations": len(encryption_issues),
            "audit_control_violations": len(audit_issues),
            "compliant": (
                len(access_control_issues) == 0
                and len(encryption_issues) == 0
                and len(audit_issues) == 0
            ),
            "safeguards_status": {
                "164.312(a)(1)": "PASS" if len(access_control_issues) == 0 else "FAIL",
                "164.312(a)(2)(iv)": "PASS" if len(encryption_issues) == 0 else "FAIL",
                "164.312(b)": "PASS" if len(audit_issues) == 0 else "FAIL",
            },
        }
