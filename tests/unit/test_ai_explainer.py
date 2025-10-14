"""Tests for AI-powered explanation system."""

import pytest

from pyguard.lib.ai_explainer import (
    AIExplainer,
    FixRationale,
    SecurityExplanation,
    explain,
)


class TestAIExplainer:
    """Tests for AIExplainer class."""

    def test_initialization(self):
        """Test explainer initialization."""
        explainer = AIExplainer()
        assert explainer is not None
        assert hasattr(explainer, "logger")
        assert len(explainer.EXPLANATIONS) > 0

    def test_explain_sql_injection(self):
        """Test SQL injection explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("SQL_INJECTION")

        assert explanation is not None
        assert explanation.vulnerability_name == "SQL Injection"
        assert explanation.severity == "CRITICAL"
        assert "parameterized" in explanation.how_to_fix.lower()
        assert explanation.cwe_id == "CWE-89"
        assert len(explanation.references) > 0

    def test_explain_command_injection(self):
        """Test command injection explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("COMMAND_INJECTION")

        assert explanation is not None
        assert explanation.vulnerability_name == "Command Injection"
        assert explanation.severity == "CRITICAL"
        assert "subprocess" in explanation.how_to_fix.lower()
        assert "shell=False" in explanation.example_secure

    def test_explain_code_injection(self):
        """Test code injection explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("CODE_INJECTION")

        assert explanation is not None
        assert "eval" in explanation.description
        assert "ast.literal_eval" in explanation.how_to_fix
        assert explanation.cwe_id == "CWE-95"

    def test_explain_hardcoded_secret(self):
        """Test hardcoded secret explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("HARDCODED_SECRET")

        assert explanation is not None
        assert explanation.severity == "HIGH"
        assert "environment" in explanation.how_to_fix.lower()
        assert explanation.difficulty_level == "beginner"

    def test_explain_unsafe_deserialization(self):
        """Test unsafe deserialization explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("UNSAFE_DESERIALIZATION")

        assert explanation is not None
        assert "pickle" in explanation.description.lower()
        assert "json" in explanation.how_to_fix.lower()
        assert explanation.cwe_id == "CWE-502"

    def test_explain_xss(self):
        """Test XSS explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("XSS")

        assert explanation is not None
        assert "Cross-Site Scripting" in explanation.vulnerability_name
        assert "escape" in explanation.how_to_fix.lower()
        assert explanation.cwe_id == "CWE-79"

    def test_explain_path_traversal(self):
        """Test path traversal explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("PATH_TRAVERSAL")

        assert explanation is not None
        assert "Path Traversal" in explanation.vulnerability_name
        assert "../" in explanation.how_to_exploit
        assert "Path.resolve()" in explanation.how_to_fix

    def test_explain_unknown_vulnerability(self):
        """Test explaining unknown vulnerability returns None."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("UNKNOWN_VULN")

        assert explanation is None

    def test_explain_case_insensitive(self):
        """Test vulnerability type is case-insensitive."""
        explainer = AIExplainer()

        exp1 = explainer.explain_vulnerability("sql_injection")
        exp2 = explainer.explain_vulnerability("SQL_INJECTION")
        exp3 = explainer.explain_vulnerability("Sql_Injection")

        assert exp1 is not None
        assert exp2 is not None
        assert exp3 is not None
        assert exp1.vulnerability_name == exp2.vulnerability_name == exp3.vulnerability_name

    def test_adjust_explanation_level_beginner(self):
        """Test explanation adjustment for beginners."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("SQL_INJECTION", "beginner")

        assert explanation is not None
        assert explanation.difficulty_level == "beginner"
        assert "Technical details omitted" in explanation.how_to_exploit
        # Should have fewer references
        assert len(explanation.references) <= 1

    def test_adjust_explanation_level_intermediate(self):
        """Test intermediate level explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("SQL_INJECTION", "intermediate")

        assert explanation is not None
        # Should have full content

    def test_adjust_explanation_level_advanced(self):
        """Test advanced level explanation."""
        explainer = AIExplainer()
        explanation = explainer.explain_vulnerability("COMMAND_INJECTION", "advanced")

        assert explanation is not None
        # Advanced gets all details

    def test_explain_fix_sql_injection(self):
        """Test fix explanation for SQL injection."""
        explainer = AIExplainer()

        original = "query = f'SELECT * FROM users WHERE id = {user_id}'"
        fixed = "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))"

        rationale = explainer.explain_fix(original, fixed, "SQL_INJECTION")

        assert isinstance(rationale, FixRationale)
        assert rationale.original_code == original
        assert rationale.fixed_code == fixed
        assert "parameterized" in rationale.why_this_fix.lower()
        assert len(rationale.alternatives) > 0
        assert rationale.security_impact != ""
        assert rationale.performance_impact != ""

    def test_explain_fix_command_injection(self):
        """Test fix explanation for command injection."""
        explainer = AIExplainer()

        original = "os.system(f'cat {filename}')"
        fixed = "subprocess.run(['cat', filename], shell=False)"

        rationale = explainer.explain_fix(original, fixed, "COMMAND_INJECTION")

        assert isinstance(rationale, FixRationale)
        assert "argument" in rationale.why_this_fix.lower()
        assert len(rationale.alternatives) > 0

    def test_explain_fix_code_injection(self):
        """Test fix explanation for code injection."""
        explainer = AIExplainer()

        original = "result = eval(user_input)"
        fixed = "result = ast.literal_eval(user_input)"

        rationale = explainer.explain_fix(original, fixed, "CODE_INJECTION")

        assert isinstance(rationale, FixRationale)
        assert "literal" in rationale.why_this_fix.lower()
        assert rationale.fix_type == "automated_security_fix"

    def test_explain_fix_hardcoded_secret(self):
        """Test fix explanation for hardcoded secrets."""
        explainer = AIExplainer()

        original = "API_KEY = 'sk-1234567890abcdef'"
        fixed = "API_KEY = os.environ['API_KEY']"

        rationale = explainer.explain_fix(original, fixed, "HARDCODED_SECRET")

        assert isinstance(rationale, FixRationale)
        assert "environment" in rationale.why_this_fix.lower()
        assert "credential" in rationale.security_impact.lower()

    def test_explain_fix_unknown_vulnerability(self):
        """Test fix explanation for unknown vulnerability."""
        explainer = AIExplainer()

        rationale = explainer.explain_fix("bad_code", "good_code", "UNKNOWN_VULN")

        assert isinstance(rationale, FixRationale)
        assert rationale.why_this_fix != ""  # Should have default explanation

    def test_generate_learning_content(self):
        """Test learning content generation."""
        explainer = AIExplainer()
        content = explainer.generate_learning_content("SQL_INJECTION")

        assert isinstance(content, dict)
        assert "title" in content
        assert "summary" in content
        assert "risk_level" in content
        assert "learning_objectives" in content
        assert "vulnerable_pattern" in content
        assert "secure_pattern" in content
        assert "quiz_question" in content
        assert "further_reading" in content

        # Check learning objectives
        assert isinstance(content["learning_objectives"], list)
        assert len(content["learning_objectives"]) > 0

        # Check quiz
        quiz = content["quiz_question"]
        assert "question" in quiz
        assert "options" in quiz
        assert "correct" in quiz
        assert "explanation" in quiz

    def test_generate_learning_content_command_injection(self):
        """Test learning content for command injection."""
        explainer = AIExplainer()
        content = explainer.generate_learning_content("COMMAND_INJECTION")

        assert content["title"] == "Command Injection"
        assert content["risk_level"] == "CRITICAL"

        quiz = content["quiz_question"]
        assert "shell=True" in quiz["question"]
        assert len(quiz["options"]) == 4

    def test_generate_learning_content_unknown(self):
        """Test learning content for unknown vulnerability."""
        explainer = AIExplainer()
        content = explainer.generate_learning_content("UNKNOWN_VULN")

        assert isinstance(content, dict)
        assert len(content) == 0  # Empty dict for unknown

    def test_quiz_question_structure(self):
        """Test quiz question structure."""
        explainer = AIExplainer()
        content = explainer.generate_learning_content("SQL_INJECTION")

        quiz = content["quiz_question"]
        assert isinstance(quiz["question"], str)
        assert isinstance(quiz["options"], list)
        assert len(quiz["options"]) == 4
        assert isinstance(quiz["correct"], int)
        assert 0 <= quiz["correct"] < 4
        assert isinstance(quiz["explanation"], str)

    def test_all_explanations_have_required_fields(self):
        """Test all explanations have required fields."""
        explainer = AIExplainer()

        for vuln_type, explanation in explainer.EXPLANATIONS.items():
            assert explanation.vulnerability_name != ""
            assert explanation.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            assert explanation.description != ""
            assert explanation.why_dangerous != ""
            assert explanation.how_to_exploit != ""
            assert explanation.how_to_fix != ""
            assert explanation.example_vulnerable != ""
            assert explanation.example_secure != ""
            assert isinstance(explanation.references, list)
            assert len(explanation.references) > 0

    def test_all_explanations_have_cwe(self):
        """Test all explanations have CWE IDs."""
        explainer = AIExplainer()

        for vuln_type, explanation in explainer.EXPLANATIONS.items():
            assert explanation.cwe_id is not None
            assert "CWE-" in explanation.cwe_id

    def test_simplify_text(self):
        """Test text simplification for beginners."""
        explainer = AIExplainer()

        text = "parameterization prevents exploitation through sanitization and arbitrary compromise"
        simplified = explainer._simplify_text(text)

        # Check that terms were replaced
        assert "parameterization" not in simplified or "using placeholders" in simplified
        assert "exploitation" not in simplified or "attack" in simplified
        assert "sanitization" not in simplified or "cleaning" in simplified
        assert "arbitrary" not in simplified or "any" in simplified
        assert "compromise" not in simplified or "take over" in simplified

    def test_convenience_function(self):
        """Test convenience function."""
        explanation = explain("SQL_INJECTION")

        assert explanation is not None
        assert isinstance(explanation, SecurityExplanation)
        assert explanation.vulnerability_name == "SQL Injection"

    def test_convenience_function_with_level(self):
        """Test convenience function with educational level."""
        explanation = explain("COMMAND_INJECTION", "beginner")

        assert explanation is not None
        assert explanation.difficulty_level == "beginner"

    def test_all_vulnerabilities_covered(self):
        """Test that common vulnerabilities are covered."""
        explainer = AIExplainer()

        expected_vulnerabilities = [
            "SQL_INJECTION",
            "COMMAND_INJECTION",
            "CODE_INJECTION",
            "HARDCODED_SECRET",
            "UNSAFE_DESERIALIZATION",
            "XSS",
            "PATH_TRAVERSAL",
        ]

        for vuln in expected_vulnerabilities:
            explanation = explainer.explain_vulnerability(vuln)
            assert explanation is not None, f"Missing explanation for {vuln}"


class TestSecurityExplanation:
    """Tests for SecurityExplanation dataclass."""

    def test_security_explanation_creation(self):
        """Test creating SecurityExplanation."""
        explanation = SecurityExplanation(
            vulnerability_name="Test Vulnerability",
            severity="HIGH",
            description="Test description",
            why_dangerous="Test danger",
            how_to_exploit="Test exploit",
            how_to_fix="Test fix",
            example_vulnerable="bad_code",
            example_secure="good_code",
            references=["http://example.com"],
        )

        assert explanation.vulnerability_name == "Test Vulnerability"
        assert explanation.severity == "HIGH"
        assert explanation.difficulty_level == "intermediate"  # Default


class TestFixRationale:
    """Tests for FixRationale dataclass."""

    def test_fix_rationale_creation(self):
        """Test creating FixRationale."""
        rationale = FixRationale(
            original_code="bad_code",
            fixed_code="good_code",
            fix_type="automated",
            why_this_fix="Test reason",
            alternatives=["alt1", "alt2"],
            trade_offs="Test tradeoffs",
            security_impact="High",
            performance_impact="Low",
        )

        assert rationale.original_code == "bad_code"
        assert rationale.fixed_code == "good_code"
        assert len(rationale.alternatives) == 2
