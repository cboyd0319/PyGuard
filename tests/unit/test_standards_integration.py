"""Unit tests for standards integration module."""

import pytest

from pyguard.lib.standards_integration import (
    CERTSecureCodingMapper,
    ComplianceRequirement,
    GDPRTechnicalControls,
    HIPAASecurityRule,
    IEEE12207Mapper,
    MitreATTACKMapper,
    SANSTop25Mapper,
    StandardsMapper,
)


class TestStandardsMapper:
    """Test standards mapping functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = StandardsMapper()

    def test_initialization(self):
        """Test mapper initialization."""
        assert self.mapper is not None
        assert len(self.mapper.nist_csf_mappings) > 0
        assert len(self.mapper.iso27001_mappings) > 0
        assert len(self.mapper.soc2_mappings) > 0
        assert len(self.mapper.pci_dss_mappings) > 0

    def test_get_compliance_mappings(self):
        """Test getting compliance mappings for an issue."""
        mappings = self.mapper.get_compliance_mappings("code_injection")

        assert len(mappings) > 0
        assert all(isinstance(m, ComplianceRequirement) for m in mappings)

    def test_multiple_standards_mapped(self):
        """Test that issues map to multiple standards."""
        mappings = self.mapper.get_compliance_mappings("hardcoded_credentials")

        # Should map to multiple standards
        standards = set(m.standard for m in mappings)
        assert len(standards) >= 2

    def test_unknown_issue_type(self):
        """Test handling unknown issue type."""
        mappings = self.mapper.get_compliance_mappings("unknown_issue")

        assert len(mappings) == 0

    def test_generate_compliance_report(self):
        """Test generating compliance report."""
        issues = [
            {"type": "code_injection", "severity": "HIGH"},
            {"type": "hardcoded_credentials", "severity": "HIGH"},
        ]

        report = self.mapper.generate_compliance_report(issues)

        assert isinstance(report, dict)
        assert "NIST-CSF" in report
        assert "ISO-27001" in report
        assert "SOC-2" in report
        assert "PCI-DSS" in report

    def test_check_standard_compliance_nist(self):
        """Test checking NIST CSF compliance."""
        issues = [{"type": "code_injection", "severity": "HIGH"}]

        result = self.mapper.check_standard_compliance("NIST-CSF", issues)

        assert result["standard"] == "NIST-CSF"
        assert result["total_violations"] > 0
        assert result["compliant"] is False
        assert len(result["violations"]) > 0

    def test_check_standard_compliance_clean(self):
        """Test compliance check with no issues."""
        issues = []

        result = self.mapper.check_standard_compliance("ISO-27001", issues)

        assert result["total_violations"] == 0
        assert result["compliant"] is True

    def test_check_unknown_standard(self):
        """Test checking unknown standard."""
        result = self.mapper.check_standard_compliance("UNKNOWN", [])

        assert "error" in result


class TestComplianceRequirement:
    """Test ComplianceRequirement dataclass."""

    def test_create_requirement(self):
        """Test creating a compliance requirement."""
        req = ComplianceRequirement(
            standard="NIST-CSF",
            control_id="PR.AC-4",
            category="Access Control",
            description="Test description",
            technical_controls=["Control 1", "Control 2"],
            severity="HIGH",
        )

        assert req.standard == "NIST-CSF"
        assert req.control_id == "PR.AC-4"
        assert len(req.technical_controls) == 2
        assert req.severity == "HIGH"


class TestGDPRTechnicalControls:
    """Test GDPR technical controls."""

    def setup_method(self):
        """Set up test fixtures."""
        self.gdpr = GDPRTechnicalControls()

    def test_initialization(self):
        """Test GDPR mapper initialization."""
        assert self.gdpr is not None

    def test_check_gdpr_requirements_with_violations(self):
        """Test GDPR check with violations."""
        issues = [
            {"type": "code_injection", "severity": "HIGH"},
            {"type": "logging_sensitive_data", "severity": "MEDIUM"},
        ]

        result = self.gdpr.check_gdpr_technical_requirements(issues)

        assert "article_32_violations" in result
        assert "article_25_violations" in result
        assert result["article_32_violations"] > 0
        assert result["compliant"] is False

    def test_check_gdpr_requirements_clean(self):
        """Test GDPR check with no issues."""
        issues = []

        result = self.gdpr.check_gdpr_technical_requirements(issues)

        assert result["article_32_violations"] == 0
        assert result["article_25_violations"] == 0
        assert result["compliant"] is True

    def test_gdpr_recommendations_present(self):
        """Test that recommendations are provided."""
        result = self.gdpr.check_gdpr_technical_requirements([])

        assert "recommendations" in result
        assert len(result["recommendations"]) > 0


class TestHIPAASecurityRule:
    """Test HIPAA Security Rule compliance."""

    def setup_method(self):
        """Set up test fixtures."""
        self.hipaa = HIPAASecurityRule()

    def test_initialization(self):
        """Test HIPAA mapper initialization."""
        assert self.hipaa is not None

    def test_check_hipaa_compliance_with_violations(self):
        """Test HIPAA check with violations."""
        issues = [
            {"type": "hardcoded_credentials", "severity": "HIGH"},
            {"type": "weak_cryptography", "severity": "MEDIUM"},
            {"type": "logging_issue", "severity": "LOW"},
        ]

        result = self.hipaa.check_hipaa_compliance(issues)

        assert "access_control_violations" in result
        assert "encryption_violations" in result
        assert "audit_control_violations" in result
        assert result["compliant"] is False

    def test_check_hipaa_compliance_clean(self):
        """Test HIPAA check with no issues."""
        issues = []

        result = self.hipaa.check_hipaa_compliance(issues)

        assert result["access_control_violations"] == 0
        assert result["encryption_violations"] == 0
        assert result["audit_control_violations"] == 0
        assert result["compliant"] is True

    def test_hipaa_safeguards_status(self):
        """Test HIPAA safeguards status reporting."""
        issues = []

        result = self.hipaa.check_hipaa_compliance(issues)

        assert "safeguards_status" in result
        safeguards = result["safeguards_status"]
        assert "164.312(a)(1)" in safeguards
        assert all(status in ["PASS", "FAIL"] for status in safeguards.values())

    def test_hipaa_safeguards_fail_on_violations(self):
        """Test that safeguards fail with violations."""
        issues = [{"type": "hardcoded_credentials", "severity": "HIGH"}]

        result = self.hipaa.check_hipaa_compliance(issues)

        safeguards = result["safeguards_status"]
        # Should have at least one FAIL
        assert any(status == "FAIL" for status in safeguards.values())


class TestSANSTop25Mapper:
    """Test SANS CWE Top 25 mapper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = SANSTop25Mapper()

    def test_initialization(self):
        """Test SANS mapper initialization."""
        assert self.mapper is not None
        assert len(self.mapper.SANS_TOP_25_2024) == 25

    def test_get_sans_ranking(self):
        """Test getting SANS ranking for CWE."""
        rank = self.mapper.get_sans_ranking("CWE-89")  # SQL Injection
        assert rank == 3

        rank = self.mapper.get_sans_ranking("CWE-78")  # OS Command Injection
        assert rank == 6

    def test_get_sans_ranking_not_in_top25(self):
        """Test getting ranking for CWE not in Top 25."""
        rank = self.mapper.get_sans_ranking("CWE-9999")
        assert rank is None

    def test_prioritize_issues(self):
        """Test prioritizing issues by SANS ranking."""
        issues = [
            {"type": "sql_injection", "cwe_id": "CWE-89"},  # Rank 3
            {"type": "command_injection", "cwe_id": "CWE-78"},  # Rank 6
            {"type": "other", "cwe_id": "CWE-9999"},  # Not in Top 25
        ]

        prioritized = self.mapper.prioritize_issues(issues)

        # Should be ordered by SANS rank
        assert prioritized[0]["cwe_id"] == "CWE-89"  # Rank 3 first
        assert prioritized[1]["cwe_id"] == "CWE-78"  # Rank 6 second
        assert prioritized[2]["cwe_id"] == "CWE-9999"  # Non-Top25 last

    def test_generate_sans_report(self):
        """Test generating SANS Top 25 report."""
        issues = [
            {"type": "sql_injection", "cwe_id": "CWE-89"},
            {"type": "command_injection", "cwe_id": "CWE-78"},
        ]

        report = self.mapper.generate_sans_report(issues)

        assert "total_top25_weaknesses_found" in report
        assert report["total_top25_weaknesses_found"] == 2
        assert "coverage_percentage" in report


class TestCERTSecureCodingMapper:
    """Test CERT Secure Coding mapper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = CERTSecureCodingMapper()

    def test_initialization(self):
        """Test CERT mapper initialization."""
        assert self.mapper is not None
        assert len(self.mapper.CERT_PYTHON_RULES) > 0

    def test_map_to_cert_rules(self):
        """Test mapping issues to CERT rules."""
        rules = self.mapper.map_to_cert_rules("code_injection")
        assert "IDS08-PY" in rules

        rules = self.mapper.map_to_cert_rules("insecure_random")
        assert "SEC02-PY" in rules

    def test_map_unknown_issue(self):
        """Test mapping unknown issue type."""
        rules = self.mapper.map_to_cert_rules("unknown_issue")
        assert rules == []

    def test_generate_cert_report(self):
        """Test generating CERT compliance report."""
        issues = [
            {"type": "code_injection", "severity": "HIGH"},
            {"type": "insecure_random", "severity": "MEDIUM"},
        ]

        report = self.mapper.generate_cert_report(issues)

        assert "total_cert_violations" in report
        assert report["total_cert_violations"] > 0
        assert "violations_by_rule" in report


class TestIEEE12207Mapper:
    """Test IEEE 12207 lifecycle mapper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = IEEE12207Mapper()

    def test_initialization(self):
        """Test IEEE mapper initialization."""
        assert self.mapper is not None
        assert len(self.mapper.IEEE_PROCESSES) > 0

    def test_map_to_lifecycle_processes(self):
        """Test mapping to lifecycle processes."""
        processes = self.mapper.map_to_lifecycle_processes("security")
        assert len(processes) > 0
        assert "6.4.3" in processes

    def test_map_quality_issues(self):
        """Test mapping quality issues to processes."""
        processes = self.mapper.map_to_lifecycle_processes("quality")
        assert len(processes) > 0

    def test_generate_lifecycle_report(self):
        """Test generating lifecycle compliance report."""
        issues = [
            {"category": "security", "severity": "HIGH"},
            {"category": "quality", "severity": "MEDIUM"},
        ]

        report = self.mapper.generate_lifecycle_report(issues)

        assert "lifecycle_compliance" in report
        assert report["lifecycle_compliance"] in ["FULL", "PARTIAL"]


class TestMitreATTACKMapper:
    """Test Mitre ATT&CK framework mapper."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mapper = MitreATTACKMapper()

    def test_initialization(self):
        """Test ATT&CK mapper initialization."""
        assert self.mapper is not None
        assert len(self.mapper.ATTACK_TECHNIQUES) > 0

    def test_map_to_attack_techniques(self):
        """Test mapping issues to ATT&CK techniques."""
        techniques = self.mapper.map_to_attack_techniques("code_injection")
        assert len(techniques) > 0
        assert "T1059" in techniques

    def test_map_credentials_issue(self):
        """Test mapping credential issues."""
        techniques = self.mapper.map_to_attack_techniques("hardcoded_credentials")
        assert "T1552" in techniques

    def test_generate_threat_model(self):
        """Test generating ATT&CK threat model."""
        issues = [
            {"type": "code_injection", "severity": "HIGH"},
            {"type": "hardcoded_credentials", "severity": "HIGH"},
        ]

        model = self.mapper.generate_threat_model(issues)

        assert "threat_exposure" in model
        assert model["threat_exposure"] in ["LOW", "MEDIUM", "HIGH"]
        assert "techniques_enabled" in model
        assert "attack_surface" in model
        assert "recommendations" in model
