"""Tests for knowledge integration module."""

import pytest

from pyguard.lib.knowledge_integration import (
    KnowledgeBase,
    KnowledgeIntegration,
    SecurityIntelligence,
)


class TestKnowledgeBase:
    """Test knowledge base functionality."""

    def test_get_cwe_info(self):
        """Test retrieving CWE information."""
        kb = KnowledgeBase()

        # Get SQL Injection CWE
        cwe_info = kb.get_cwe_info("CWE-89")

        assert cwe_info is not None
        assert cwe_info["name"] == "SQL Injection"
        assert cwe_info["rank"] == 3
        assert cwe_info["severity"] == "CRITICAL"

    def test_get_cwe_info_not_found(self):
        """Test retrieving non-existent CWE."""
        kb = KnowledgeBase()

        cwe_info = kb.get_cwe_info("CWE-99999")

        assert cwe_info is None

    def test_get_owasp_category(self):
        """Test retrieving OWASP Top 10 category."""
        kb = KnowledgeBase()

        # Get Injection category
        owasp_info = kb.get_owasp_category("A03")

        assert owasp_info is not None
        assert owasp_info["name"] == "Injection"
        assert "CWE-89" in owasp_info["cwes"]

    def test_get_severity_score(self):
        """Test severity scoring."""
        kb = KnowledgeBase()

        # CRITICAL severity
        score = kb.get_severity_score("CWE-89")
        assert score == 10

        # HIGH severity
        score = kb.get_severity_score("CWE-78")
        assert score >= 8

        # Unknown CWE should return default
        score = kb.get_severity_score("CWE-99999")
        assert score == 5

    def test_is_in_top_25(self):
        """Test checking if CWE is in Top 25."""
        kb = KnowledgeBase()

        # SQL Injection is in Top 25
        assert kb.is_in_top_25("CWE-89") is True

        # Random CWE not in Top 25
        assert kb.is_in_top_25("CWE-99999") is False

    def test_get_related_cwes(self):
        """Test getting related CWEs."""
        kb = KnowledgeBase()

        # SQL Injection has NoSQL Injection as related
        related = kb.get_related_cwes("CWE-89")
        assert "CWE-943" in related

        # Unknown CWE returns empty list
        related = kb.get_related_cwes("CWE-99999")
        assert related == []

    def test_owasp_top_10_complete(self):
        """Test that OWASP Top 10 2021 is complete."""
        kb = KnowledgeBase()

        # Should have all 10 categories
        assert len(kb.OWASP_TOP_10_2021) == 10

        # Check key categories exist
        for category in ["A01", "A02", "A03", "A10"]:
            assert category in kb.OWASP_TOP_10_2021

    def test_cwe_top_25_complete(self):
        """Test that CWE Top 25 is complete."""
        kb = KnowledgeBase()

        # Should have all 25 entries
        assert len(kb.CWE_TOP_25_2023) == 25

        # Check ranks are 1-25
        ranks = [info["rank"] for info in kb.CWE_TOP_25_2023.values()]
        assert set(ranks) == set(range(1, 26))


class TestSecurityIntelligence:
    """Test security intelligence functionality."""

    def test_enrich_security_issue(self):
        """Test enriching a security issue with additional context."""
        intel = SecurityIntelligence()

        issue = {
            "severity": "HIGH",
            "category": "SQL Injection",
            "message": "Potential SQL injection",
            "cwe_id": "CWE-89",
        }

        enriched = intel.enrich_security_issue(issue)

        assert "cwe_name" in enriched
        assert enriched["cwe_name"] == "SQL Injection"
        assert "cwe_rank" in enriched
        assert enriched["cwe_rank"] == 3
        assert "mitigation" in enriched
        assert enriched["in_cwe_top_25"] is True

    def test_enrich_issue_with_owasp(self):
        """Test enriching issue with OWASP information."""
        intel = SecurityIntelligence()

        issue = {
            "severity": "HIGH",
            "cwe_id": "CWE-89",
            "owasp_id": "ASVS-5.3.4",
        }

        enriched = intel.enrich_security_issue(issue)

        assert "owasp_category" in enriched
        assert enriched["owasp_category"] == "Injection"

    def test_get_attack_patterns(self):
        """Test retrieving attack patterns for CWE."""
        intel = SecurityIntelligence()

        # SQL Injection patterns
        patterns = intel.get_attack_patterns("CWE-89")
        assert len(patterns) > 0
        assert any("OR" in p for p in patterns)

        # Unknown CWE returns empty list
        patterns = intel.get_attack_patterns("CWE-99999")
        assert patterns == []

    def test_get_mitigation_checklist(self):
        """Test retrieving mitigation checklist."""
        intel = SecurityIntelligence()

        # SQL Injection checklist
        checklist = intel.get_mitigation_checklist("CWE-89")
        assert len(checklist) > 0
        assert all(item.startswith("✓") for item in checklist)
        assert any("parameterized" in item.lower() for item in checklist)

        # Unknown CWE returns default
        checklist = intel.get_mitigation_checklist("CWE-99999")
        assert len(checklist) > 0


class TestKnowledgeIntegration:
    """Test comprehensive knowledge integration."""

    def test_get_comprehensive_report(self):
        """Test getting comprehensive security report."""
        ki = KnowledgeIntegration()

        report = ki.get_comprehensive_report("CWE-89")

        assert "cwe_id" in report
        assert report["cwe_id"] == "CWE-89"
        assert "name" in report
        assert report["name"] == "SQL Injection"
        assert "rank" in report
        assert report["rank"] == 3
        assert "severity" in report
        assert "mitigation" in report
        assert "attack_patterns" in report
        assert "mitigation_checklist" in report
        assert report["in_top_25"] is True

    def test_comprehensive_report_unknown_cwe(self):
        """Test report for unknown CWE."""
        ki = KnowledgeIntegration()

        report = ki.get_comprehensive_report("CWE-99999")

        assert "error" in report

    def test_comprehensive_report_includes_related(self):
        """Test that report includes related CWEs."""
        ki = KnowledgeIntegration()

        report = ki.get_comprehensive_report("CWE-89")

        assert "related_cwes" in report
        assert isinstance(report["related_cwes"], list)

    def test_integration_initialization(self):
        """Test that knowledge integration initializes correctly."""
        ki = KnowledgeIntegration()

        assert ki.knowledge_base is not None
        assert ki.security_intel is not None
        assert ki.logger is not None
