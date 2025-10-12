"""Unit tests for standards integration module."""

import pytest

from pyguard.lib.standards_integration import (
    ComplianceRequirement,
    GDPRTechnicalControls,
    HIPAASecurityRule,
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
