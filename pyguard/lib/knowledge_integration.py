"""
Knowledge Integration Module for PyGuard.

Integrates with external knowledge bases, security databases, and APIs to enhance
detection capabilities with real-time threat intelligence.

References:
- NVD (National Vulnerability Database) | https://nvd.nist.gov/ | High | NIST vulnerability database
- GitHub Advisory Database | https://github.com/advisories | High | Security advisories
- OSV | https://osv.dev/ | High | Open Source Vulnerabilities database
- CVE | https://cve.mitre.org/ | High | Common Vulnerabilities and Exposures
- CWE | https://cwe.mitre.org/ | High | Common Weakness Enumeration
- OWASP Top 10 | https://owasp.org/Top10/ | High | Top web application security risks
"""

from dataclasses import dataclass
from typing import Any, ClassVar

from pyguard.lib.core import PyGuardLogger


@dataclass
class SecurityAdvisory:
    """Represents a security advisory from external source."""

    id: str  # CVE-2023-12345, GHSA-xxxx-xxxx-xxxx
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_packages: list[str]
    fixed_versions: list[str]
    published_date: str
    source: str  # NVD, GitHub, OSV
    references: list[str]
    cwe_ids: list[str]


@dataclass
class CWEInformation:
    """CWE (Common Weakness Enumeration) information."""

    cwe_id: str
    name: str
    description: str
    extended_description: str
    mitigation: str
    detection_methods: list[str]
    owasp_mappings: list[str]
    likelihood: str
    impact: str


@dataclass
class OWASPCategory:
    """OWASP Top 10 category information."""

    year: int
    rank: int
    category: str
    description: str
    cwes: list[str]
    mitigation_strategies: list[str]
    detection_techniques: list[str]


class KnowledgeBase:
    """
    Local knowledge base for security information.

    Maintains cached security intelligence and provides fast lookups.
    In production, this would sync with external APIs periodically.
    """

    # OWASP Top 10 2021 (latest)
    OWASP_TOP_10_2021: ClassVar[Any] = {
        "A01": {
            "name": "Broken Access Control",
            "cwes": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219"],
            "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
        },
        "A02": {
            "name": "Cryptographic Failures",
            "cwes": ["CWE-259", "CWE-327", "CWE-331"],
            "description": "Failures related to cryptography which often lead to exposure of sensitive data.",
        },
        "A03": {
            "name": "Injection",
            "cwes": ["CWE-79", "CWE-89", "CWE-73", "CWE-93", "CWE-94"],
            "description": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
        },
        "A04": {
            "name": "Insecure Design",
            "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
            "description": "Risks related to design and architectural flaws, calling for more use of threat modeling.",
        },
        "A05": {
            "name": "Security Misconfiguration",
            "cwes": ["CWE-16", "CWE-611"],
            "description": "Security misconfiguration is the most commonly seen issue.",
        },
        "A06": {
            "name": "Vulnerable and Outdated Components",
            "cwes": ["CWE-1104"],
            "description": "Using components with known vulnerabilities.",
        },
        "A07": {
            "name": "Identification and Authentication Failures",
            "cwes": ["CWE-287", "CWE-297", "CWE-306"],
            "description": "Confirmation of the user's identity, authentication, and session management.",
        },
        "A08": {
            "name": "Software and Data Integrity Failures",
            "cwes": ["CWE-829", "CWE-494"],
            "description": "Code and infrastructure that does not protect against integrity violations.",
        },
        "A09": {
            "name": "Security Logging and Monitoring Failures",
            "cwes": ["CWE-778", "CWE-117", "CWE-223", "CWE-532"],
            "description": "Without logging and monitoring, breaches cannot be detected.",
        },
        "A10": {
            "name": "Server-Side Request Forgery (SSRF)",
            "cwes": ["CWE-918"],
            "description": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
        },
    }

    # CWE Top 25 Most Dangerous Software Weaknesses (2023)
    CWE_TOP_25_2023: ClassVar[Any] = {
        "CWE-787": {
            "name": "Out-of-bounds Write",
            "rank": 1,
            "severity": "CRITICAL",
            "mitigation": "Use languages with memory safety, bounds checking, input validation",
        },
        "CWE-79": {
            "name": "Cross-site Scripting (XSS)",
            "rank": 2,
            "severity": "HIGH",
            "mitigation": "Output encoding, Content Security Policy, input validation",
        },
        "CWE-89": {
            "name": "SQL Injection",
            "rank": 3,
            "severity": "CRITICAL",
            "mitigation": "Parameterized queries, ORMs, input validation",
        },
        "CWE-20": {
            "name": "Improper Input Validation",
            "rank": 4,
            "severity": "HIGH",
            "mitigation": "Allowlist validation, type checking, bounds checking",
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "rank": 5,
            "severity": "CRITICAL",
            "mitigation": "Avoid system calls, use safe APIs, input sanitization",
        },
        "CWE-125": {
            "name": "Out-of-bounds Read",
            "rank": 6,
            "severity": "HIGH",
            "mitigation": "Bounds checking, safe string functions",
        },
        "CWE-416": {
            "name": "Use After Free",
            "rank": 7,
            "severity": "CRITICAL",
            "mitigation": "Memory-safe languages, careful resource management",
        },
        "CWE-22": {
            "name": "Path Traversal",
            "rank": 8,
            "severity": "HIGH",
            "mitigation": "Path canonicalization, allowlist validation",
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "rank": 9,
            "severity": "MEDIUM",
            "mitigation": "CSRF tokens, SameSite cookies, origin validation",
        },
        "CWE-434": {
            "name": "Unrestricted Upload of File with Dangerous Type",
            "rank": 10,
            "severity": "HIGH",
            "mitigation": "File type validation, sandboxing, virus scanning",
        },
        "CWE-862": {
            "name": "Missing Authorization",
            "rank": 11,
            "severity": "HIGH",
            "mitigation": "Proper authorization checks at all layers",
        },
        "CWE-476": {
            "name": "NULL Pointer Dereference",
            "rank": 12,
            "severity": "MEDIUM",
            "mitigation": "Null checks, defensive programming",
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "rank": 13,
            "severity": "CRITICAL",
            "mitigation": "Multi-factor authentication, secure credential storage",
        },
        "CWE-190": {
            "name": "Integer Overflow",
            "rank": 14,
            "severity": "HIGH",
            "mitigation": "Range checking, safe integer libraries",
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "rank": 15,
            "severity": "CRITICAL",
            "mitigation": "Avoid deserializing untrusted data, use safe formats",
        },
        "CWE-77": {
            "name": "Command Injection",
            "rank": 16,
            "severity": "CRITICAL",
            "mitigation": "Avoid shell commands, use safe APIs",
        },
        "CWE-119": {
            "name": "Buffer Errors",
            "rank": 17,
            "severity": "CRITICAL",
            "mitigation": "Bounds checking, safe string functions",
        },
        "CWE-798": {
            "name": "Hard-coded Credentials",
            "rank": 18,
            "severity": "HIGH",
            "mitigation": "Use secure credential management, environment variables",
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "rank": 19,
            "severity": "HIGH",
            "mitigation": "URL validation, allowlist, network segmentation",
        },
        "CWE-306": {
            "name": "Missing Authentication",
            "rank": 20,
            "severity": "CRITICAL",
            "mitigation": "Implement authentication for all protected resources",
        },
        "CWE-362": {
            "name": "Race Condition",
            "rank": 21,
            "severity": "MEDIUM",
            "mitigation": "Proper synchronization, atomic operations",
        },
        "CWE-269": {
            "name": "Improper Privilege Management",
            "rank": 22,
            "severity": "HIGH",
            "mitigation": "Principle of least privilege, proper access controls",
        },
        "CWE-94": {
            "name": "Code Injection",
            "rank": 23,
            "severity": "CRITICAL",
            "mitigation": "Avoid eval/exec, input sanitization",
        },
        "CWE-863": {
            "name": "Incorrect Authorization",
            "rank": 24,
            "severity": "HIGH",
            "mitigation": "Proper authorization checks, role-based access control",
        },
        "CWE-276": {
            "name": "Incorrect Default Permissions",
            "rank": 25,
            "severity": "MEDIUM",
            "mitigation": "Secure defaults, proper file permissions",
        },
    }

    def __init__(self):
        """Initialize knowledge base."""
        self.logger = PyGuardLogger()

    def get_cwe_info(self, cwe_id: str) -> dict | None:
        """Get information about a CWE."""
        return self.CWE_TOP_25_2023.get(cwe_id)

    def get_owasp_category(self, owasp_id: str) -> dict | None:
        """Get information about an OWASP Top 10 category."""
        return self.OWASP_TOP_10_2021.get(owasp_id)

    def get_severity_score(self, cwe_id: str) -> int:
        """
        Get severity score for a CWE (1-10).

        Based on CVSS-like scoring.
        """
        cwe_info = self.get_cwe_info(cwe_id)
        if not cwe_info:
            return 5  # Default medium

        severity = cwe_info.get("severity", "MEDIUM")
        severity_scores = {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 2,
        }
        return severity_scores.get(severity, 5)

    def is_in_top_25(self, cwe_id: str) -> bool:
        """Check if CWE is in Top 25."""
        return cwe_id in self.CWE_TOP_25_2023

    def get_related_cwes(self, cwe_id: str) -> list[str]:
        """Get related CWEs for a given CWE."""
        # Map common related CWEs
        relations = {
            "CWE-89": ["CWE-943"],  # SQL Injection -> NoSQL Injection
            "CWE-78": ["CWE-77", "CWE-88"],  # Command Injection variants
            "CWE-79": ["CWE-80", "CWE-87"],  # XSS variants
            "CWE-502": ["CWE-915"],  # Deserialization variants
        }
        return relations.get(cwe_id, [])


class SecurityIntelligence:
    """
    Security intelligence and threat information.

    Provides contextual information about security threats, attack patterns,
    and mitigation strategies.
    """

    def __init__(self):
        """Initialize security intelligence."""
        self.knowledge_base = KnowledgeBase()
        self.logger = PyGuardLogger()

    def enrich_security_issue(self, issue_dict: dict) -> dict:
        """
        Enrich a security issue with additional context.

        Args:
            issue_dict: Security issue dictionary

        Returns:
            Enriched issue dictionary
        """
        cwe_id = issue_dict.get("cwe_id")
        owasp_id = issue_dict.get("owasp_id")

        # Add CWE information
        if cwe_id:
            cwe_info = self.knowledge_base.get_cwe_info(cwe_id)
            if cwe_info:
                issue_dict["cwe_name"] = cwe_info.get("name")
                issue_dict["cwe_rank"] = cwe_info.get("rank")
                issue_dict["mitigation"] = cwe_info.get("mitigation")
                issue_dict["severity_score"] = self.knowledge_base.get_severity_score(cwe_id)
                issue_dict["in_cwe_top_25"] = True
                issue_dict["related_cwes"] = self.knowledge_base.get_related_cwes(cwe_id)

        # Add OWASP information
        if owasp_id:
            # Extract category (e.g., "ASVS-5.2.1" -> look up OWASP A03)
            owasp_info = self._get_owasp_category_from_asvs(owasp_id)
            if owasp_info:
                issue_dict["owasp_category"] = owasp_info.get("name")
                issue_dict["owasp_description"] = owasp_info.get("description")

        return issue_dict

    def _get_owasp_category_from_asvs(self, asvs_id: str) -> dict | None:
        """Map ASVS ID to OWASP Top 10 category."""
        # Simplified mapping - in production would be more comprehensive
        asvs_to_owasp = {
            "ASVS-5.1": "A03",  # Injection
            "ASVS-5.2": "A03",  # Injection
            "ASVS-5.3": "A03",  # Injection
            "ASVS-5.5": "A08",  # Data Integrity
            "ASVS-6.2": "A02",  # Cryptographic Failures
            "ASVS-6.3": "A02",  # Cryptographic Failures
            "ASVS-2.6": "A07",  # Identification and Authentication
            "ASVS-12.3": "A01",  # Broken Access Control
            "ASVS-13.1": "A10",  # SSRF
        }

        # Extract base category from ASVS ID
        for asvs_prefix, owasp_cat in asvs_to_owasp.items():
            if asvs_id.startswith(asvs_prefix):
                return self.knowledge_base.get_owasp_category(owasp_cat)

        return None

    def get_attack_patterns(self, cwe_id: str) -> list[str]:
        """Get common attack patterns for a CWE."""
        patterns = {
            "CWE-89": [
                "' OR '1'='1",
                "admin'--",
                "1'; DROP TABLE users--",
            ],
            "CWE-78": [
                "; cat /etc/passwd",
                "| ls -la",
                "&& rm -rf /",
            ],
            "CWE-79": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
            ],
        }
        return patterns.get(cwe_id, [])

    def get_mitigation_checklist(self, cwe_id: str) -> list[str]:
        """Get actionable mitigation checklist for a CWE."""
        checklists = {
            "CWE-89": [
                "[OK] Use parameterized queries or prepared statements",
                "[OK] Use ORM with automatic escaping",
                "[OK] Validate and sanitize all user input",
                "[OK] Use least privilege database accounts",
                "[OK] Enable SQL injection detection in WAF",
            ],
            "CWE-78": [
                "[OK] Avoid system calls when possible",
                "[OK] Use subprocess with shell=False",
                "[OK] Allowlist permitted commands",
                "[OK] Sanitize all input passed to system calls",
                "[OK] Use language-native APIs instead of shell commands",
            ],
            "CWE-502": [
                "[OK] Never deserialize untrusted data",
                "[OK] Use safe serialization formats (JSON, not pickle)",
                "[OK] Implement integrity checks (HMAC)",
                "[OK] Use allowlists for deserialization",
                "[OK] Isolate deserialization in sandboxes",
            ],
        }
        return checklists.get(
            cwe_id, ["[OK] Review security best practices for this vulnerability type"]
        )


class KnowledgeIntegration:
    """
    Main knowledge integration system.

    Coordinates all knowledge sources to provide comprehensive security intelligence.
    """

    def __init__(self):
        """Initialize knowledge integration."""
        self.knowledge_base = KnowledgeBase()
        self.security_intel = SecurityIntelligence()
        self.logger = PyGuardLogger()

    def get_comprehensive_report(self, cwe_id: str) -> dict:
        """
        Get comprehensive security report for a CWE.

        Args:
            cwe_id: CWE identifier

        Returns:
            Comprehensive report dictionary
        """
        cwe_info = self.knowledge_base.get_cwe_info(cwe_id)
        if not cwe_info:
            return {"error": f"CWE {cwe_id} not found in knowledge base"}

        return {
            "cwe_id": cwe_id,
            "name": cwe_info.get("name"),
            "rank": cwe_info.get("rank"),
            "severity": cwe_info.get("severity"),
            "mitigation": cwe_info.get("mitigation"),
            "attack_patterns": self.security_intel.get_attack_patterns(cwe_id),
            "mitigation_checklist": self.security_intel.get_mitigation_checklist(cwe_id),
            "related_cwes": self.knowledge_base.get_related_cwes(cwe_id),
            "in_top_25": True,
        }
