"""
Enhanced Standards Integration for PyGuard.

Integrates with comprehensive security and compliance frameworks:
- NIST Cybersecurity Framework (CSF)
- ISO/IEC 27001:2022
- SOC 2 Type II
- PCI DSS 4.0
- GDPR technical requirements
- HIPAA Security Rule
- SANS CWE Top 25 (2024)
- CERT Secure Coding Standards
- IEEE 12207:2017 (Software Lifecycle)
- Mitre ATT&CK Framework

References:
- NIST CSF v1.1 | https://nist.gov/cyberframework | High | Cybersecurity framework
- ISO 27001:2022 | https://iso.org/standard/27001 | High | Information security management
- SOC 2 | https://aicpa.org/soc2 | Medium | Service organization controls
- PCI DSS 4.0 | https://pcisecuritystandards.org | High | Payment card industry standards
- GDPR | https://gdpr.eu | High | EU data protection regulation
- HIPAA | https://hhs.gov/hipaa | Medium | Health information privacy
- SANS Top 25 | https://sans.org/top25-software-errors | High | Most dangerous software errors
- CERT C/C++/Java | https://sei.cmu.edu/publications/books/secure-coding/ | High | SEI CERT secure coding
- IEEE 12207 | https://iso.org/standard/63712.html | High | Systems and software engineering lifecycle
- Mitre ATT&CK | https://attack.mitre.org | High | Adversarial tactics and techniques
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

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
        report: Dict[str, List[str]] = {
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
    ) -> Dict[str, Any]:
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
    ) -> Dict[str, Any]:
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

    def check_hipaa_compliance(self, issues: List[Dict]) -> Dict[str, Any]:
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


class SANSTop25Mapper:
    """
    SANS CWE Top 25 Most Dangerous Software Weaknesses Mapper (2024).
    
    Maps PyGuard detections to SANS Top 25 rankings for prioritization.
    
    Reference: SANS Top 25 | https://sans.org/top25-software-errors | High
    """

    # SANS CWE Top 25 2024 (Official Rankings)
    SANS_TOP_25_2024 = {
        1: ("CWE-787", "Out-of-bounds Write"),
        2: ("CWE-79", "Cross-site Scripting"),
        3: ("CWE-89", "SQL Injection"),
        4: ("CWE-20", "Improper Input Validation"),
        5: ("CWE-125", "Out-of-bounds Read"),
        6: ("CWE-78", "OS Command Injection"),
        7: ("CWE-416", "Use After Free"),
        8: ("CWE-22", "Path Traversal"),
        9: ("CWE-352", "CSRF"),
        10: ("CWE-434", "Unrestricted Upload"),
        11: ("CWE-306", "Missing Authentication"),
        12: ("CWE-862", "Missing Authorization"),
        13: ("CWE-476", "NULL Pointer Dereference"),
        14: ("CWE-287", "Improper Authentication"),
        15: ("CWE-190", "Integer Overflow"),
        16: ("CWE-502", "Deserialization of Untrusted Data"),
        17: ("CWE-77", "Command Injection"),
        18: ("CWE-119", "Buffer Errors"),
        19: ("CWE-798", "Hardcoded Credentials"),
        20: ("CWE-918", "SSRF"),
        21: ("CWE-306", "Missing Authentication for Critical Function"),
        22: ("CWE-362", "Race Condition"),
        23: ("CWE-269", "Improper Privilege Management"),
        24: ("CWE-94", "Code Injection"),
        25: ("CWE-863", "Incorrect Authorization"),
    }

    def __init__(self):
        """Initialize SANS Top 25 mapper."""
        self.logger = PyGuardLogger()

    def get_sans_ranking(self, cwe_id: str) -> Optional[int]:
        """
        Get SANS Top 25 ranking for a CWE ID.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            
        Returns:
            Ranking (1-25) or None if not in Top 25
        """
        for rank, (cwe, _) in self.SANS_TOP_25_2024.items():
            if cwe == cwe_id:
                return rank
        return None

    def prioritize_issues(self, issues: List[Dict]) -> List[Dict]:
        """
        Prioritize issues based on SANS Top 25 rankings.
        
        Args:
            issues: List of security issues
            
        Returns:
            Issues sorted by SANS ranking (most critical first)
        """
        def get_priority(issue):
            cwe_id = issue.get("cwe_id", "")
            rank = self.get_sans_ranking(cwe_id)
            # Issues in Top 25 get their rank, others get 999
            return rank if rank else 999
        
        return sorted(issues, key=get_priority)

    def generate_sans_report(self, issues: List[Dict]) -> Dict[str, Any]:
        """
        Generate SANS Top 25 compliance report.
        
        Args:
            issues: List of security issues
            
        Returns:
            Report showing coverage of SANS Top 25
        """
        top25_found: Dict[int, List[str]] = {}
        
        for issue in issues:
            cwe_id = issue.get("cwe_id", "")
            rank = self.get_sans_ranking(cwe_id)
            
            if rank:
                if rank not in top25_found:
                    top25_found[rank] = []
                top25_found[rank].append(issue)
        
        return {
            "total_top25_weaknesses_found": len(top25_found),
            "weaknesses_by_rank": {
                rank: {
                    "cwe": self.SANS_TOP_25_2024[rank][0],
                    "name": self.SANS_TOP_25_2024[rank][1],
                    "count": len(issues_list),
                }
                for rank, issues_list in sorted(top25_found.items())
            },
            "coverage_percentage": (len(top25_found) / 25) * 100,
        }


class CERTSecureCodingMapper:
    """
    CERT Secure Coding Standards Mapper.
    
    Maps PyGuard detections to SEI CERT secure coding recommendations.
    
    Reference: CERT Secure Coding | https://sei.cmu.edu/publications/ | High
    """

    # CERT Python Secure Coding Rules
    CERT_PYTHON_RULES = {
        "IDS01-PY": "Normalize strings before validation",
        "IDS08-PY": "Sanitize untrusted data passed to eval/exec",
        "STR02-PY": "Sanitize data within services",
        "FIO02-PY": "Do not open files in write mode without checking existence",
        "FIO51-PY": "Close files after use",
        "EXP00-PY": "Use parentheses for clarity in expressions",
        "EXP52-PY": "Use is when comparing to None",
        "SER01-PY": "Use caution when serializing objects",
        "SEC02-PY": "Do not use unpredictable sources of randomness",
        "SEC03-PY": "Encrypt sensitive data",
    }

    def __init__(self):
        """Initialize CERT mapper."""
        self.logger = PyGuardLogger()

    def map_to_cert_rules(self, issue_type: str) -> List[str]:
        """
        Map PyGuard issue type to CERT rules.
        
        Args:
            issue_type: Type of security issue
            
        Returns:
            List of applicable CERT rule IDs
        """
        mappings = {
            "code_injection": ["IDS08-PY"],
            "eval_usage": ["IDS08-PY"],
            "insecure_random": ["SEC02-PY"],
            "weak_cryptography": ["SEC03-PY"],
            "unsafe_deserialization": ["SER01-PY"],
            "none_comparison": ["EXP52-PY"],
        }
        
        return mappings.get(issue_type, [])

    def generate_cert_report(self, issues: List[Dict]) -> Dict[str, Any]:
        """
        Generate CERT Secure Coding compliance report.
        
        Args:
            issues: List of security issues
            
        Returns:
            Report showing CERT rule violations
        """
        violations_by_rule: Dict[str, List[str]] = {}
        
        for issue in issues:
            issue_type = issue.get("type", "unknown")
            cert_rules = self.map_to_cert_rules(issue_type)
            
            for rule_id in cert_rules:
                if rule_id not in violations_by_rule:
                    violations_by_rule[rule_id] = []
                violations_by_rule[rule_id].append(issue)
        
        return {
            "total_cert_violations": sum(len(v) for v in violations_by_rule.values()),
            "violations_by_rule": {
                rule_id: {
                    "rule_name": self.CERT_PYTHON_RULES.get(rule_id, "Unknown"),
                    "violation_count": len(issues_list),
                }
                for rule_id, issues_list in violations_by_rule.items()
            },
        }


class IEEE12207Mapper:
    """
    IEEE 12207:2017 Software Lifecycle Processes Mapper.
    
    Maps PyGuard quality checks to IEEE 12207 lifecycle requirements.
    
    Reference: IEEE 12207 | https://iso.org/standard/63712.html | High
    """

    # IEEE 12207 Process Areas relevant to code quality
    IEEE_PROCESSES = {
        "6.4.3": "Software Construction - Implementation and unit testing",
        "6.4.4": "Software Integration",
        "6.4.5": "Software Qualification Testing",
        "6.4.7": "Software Maintenance",
        "7.1.2": "Quality Assurance Process",
        "7.1.3": "Verification Process",
        "7.1.4": "Validation Process",
        "7.2.2": "Software Review Process",
    }

    def __init__(self):
        """Initialize IEEE 12207 mapper."""
        self.logger = PyGuardLogger()

    def map_to_lifecycle_processes(self, issue_category: str) -> List[str]:
        """
        Map issue category to IEEE 12207 lifecycle processes.
        
        Args:
            issue_category: Category of issue (security, quality, etc.)
            
        Returns:
            List of applicable IEEE process IDs
        """
        mappings = {
            "security": ["6.4.3", "7.1.2", "7.1.3"],
            "quality": ["6.4.3", "7.1.2", "7.2.2"],
            "complexity": ["6.4.3", "7.2.2"],
            "maintainability": ["6.4.7", "7.1.2"],
        }
        
        return mappings.get(issue_category, ["7.1.2"])  # Default to QA

    def generate_lifecycle_report(self, issues: List[Dict]) -> Dict[str, Any]:
        """
        Generate IEEE 12207 lifecycle compliance report.
        
        Args:
            issues: List of security and quality issues
            
        Returns:
            Report showing lifecycle process compliance
        """
        process_violations: Dict[str, List[str]] = {}
        
        for issue in issues:
            category = issue.get("category", "quality")
            processes = self.map_to_lifecycle_processes(category)
            
            for process_id in processes:
                if process_id not in process_violations:
                    process_violations[process_id] = []
                process_violations[process_id].append(issue)
        
        return {
            "lifecycle_compliance": "PARTIAL" if process_violations else "FULL",
            "process_gaps": {
                process_id: {
                    "process_name": self.IEEE_PROCESSES.get(process_id, "Unknown"),
                    "issue_count": len(issues_list),
                }
                for process_id, issues_list in process_violations.items()
            },
        }


class MitreATTACKMapper:
    """
    Mitre ATT&CK Framework Mapper.
    
    Maps detected vulnerabilities to ATT&CK techniques for threat modeling.
    
    Reference: Mitre ATT&CK | https://attack.mitre.org | High
    """

    # ATT&CK Techniques relevant to application security
    ATTACK_TECHNIQUES = {
        "T1059": "Command and Scripting Interpreter",
        "T1055": "Process Injection",
        "T1203": "Exploitation for Client Execution",
        "T1210": "Exploitation of Remote Services",
        "T1552": "Unsecured Credentials",
        "T1082": "System Information Discovery",
        "T1083": "File and Directory Discovery",
        "T1056": "Input Capture",
        "T1557": "Adversary-in-the-Middle",
        "T1027": "Obfuscated Files or Information",
    }

    def __init__(self):
        """Initialize Mitre ATT&CK mapper."""
        self.logger = PyGuardLogger()

    def map_to_attack_techniques(self, issue_type: str) -> List[str]:
        """
        Map security issue to ATT&CK techniques.
        
        Args:
            issue_type: Type of security vulnerability
            
        Returns:
            List of applicable ATT&CK technique IDs
        """
        mappings = {
            "code_injection": ["T1059", "T1203"],
            "command_injection": ["T1059"],
            "hardcoded_credentials": ["T1552"],
            "weak_cryptography": ["T1557"],
            "path_traversal": ["T1083"],
            "sql_injection": ["T1210"],
        }
        
        return mappings.get(issue_type, [])

    def generate_threat_model(self, issues: List[Dict]) -> Dict[str, Any]:
        """
        Generate ATT&CK-based threat model.
        
        Args:
            issues: List of security issues
            
        Returns:
            Threat model showing potential ATT&CK techniques enabled
        """
        techniques_enabled: Dict[str, Dict[str, Any]] = {}
        
        for issue in issues:
            issue_type = issue.get("type", "unknown")
            techniques = self.map_to_attack_techniques(issue_type)
            
            for technique_id in techniques:
                if technique_id not in techniques_enabled:
                    techniques_enabled[technique_id] = {
                        "name": self.ATTACK_TECHNIQUES.get(technique_id, "Unknown"),
                        "issues": [],
                    }
                techniques_enabled[technique_id]["issues"].append(issue)
        
        return {
            "threat_exposure": "HIGH" if len(techniques_enabled) > 5 else "MEDIUM" if len(techniques_enabled) > 2 else "LOW",
            "techniques_enabled": len(techniques_enabled),
            "attack_surface": techniques_enabled,
            "recommendations": [
                "Implement defense-in-depth strategies",
                "Apply security patches immediately",
                "Enable application security monitoring",
                "Conduct regular threat modeling exercises",
            ],
        }
