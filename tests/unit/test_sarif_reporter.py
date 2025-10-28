"""
Tests for SARIF reporter module.
"""

import json


from pyguard.lib.sarif_reporter import SARIFReporter


class TestSARIFReporter:
    """Test SARIF reporter functionality."""

    def test_initialization(self):
        """Test SARIF reporter initialization."""
        reporter = SARIFReporter()
        assert reporter is not None
        assert reporter.SARIF_VERSION == "2.1.0"
        assert "sarif-schema-2.1.0.json" in reporter.SARIF_SCHEMA

    def test_severity_mapping(self):
        """Test severity mapping from PyGuard to SARIF."""
        reporter = SARIFReporter()

        assert reporter._map_severity("HIGH") == "error"
        assert reporter._map_severity("CRITICAL") == "error"
        assert reporter._map_severity("MEDIUM") == "warning"
        assert reporter._map_severity("LOW") == "note"
        assert reporter._map_severity("INFO") == "note"
        assert reporter._map_severity("UNKNOWN") == "warning"

    def test_generate_empty_report(self):
        """Test generating report with no issues."""
        reporter = SARIFReporter()
        report = reporter.generate_report(issues=[], tool_name="PyGuard", tool_version="0.3.0")

        assert report["version"] == "2.1.0"
        assert "$schema" in report
        assert "runs" in report
        assert len(report["runs"]) == 1
        assert report["runs"][0]["tool"]["driver"]["name"] == "PyGuard"
        assert report["runs"][0]["tool"]["driver"]["version"] == "0.3.0"
        assert len(report["runs"][0]["results"]) == 0

    def test_generate_report_with_single_issue(self):
        """Test generating report with a single security issue."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "Potential SQL injection vulnerability",
                "file": "test.py",
                "line": 10,
                "column": 5,
                "cwe_id": "CWE-89",
                "owasp_id": "A03:2021",
                "fix_suggestion": "Use parameterized queries",
            }
        ]

        report = reporter.generate_report(issues, tool_name="PyGuard", tool_version="0.3.0")

        # Check basic structure
        assert report["version"] == "2.1.0"
        assert len(report["runs"][0]["results"]) == 1

        # Check result details
        result = report["runs"][0]["results"][0]
        assert result["ruleId"] == "PY/CWE-89"
        assert result["level"] == "error"
        assert result["message"]["text"] == "Potential SQL injection vulnerability"

        # Check location
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "test.py"
        assert location["region"]["startLine"] == 10
        assert location["region"]["startColumn"] == 5

        # Check properties
        assert result["properties"]["cwe"] == "CWE-89"
        assert result["properties"]["owasp"] == "A03:2021"

        # Check fix suggestion
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Use parameterized queries"

    def test_generate_report_with_multiple_issues(self):
        """Test generating report with multiple issues."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "SQL injection vulnerability",
                "file": "app.py",
                "line": 10,
                "column": 1,
                "cwe_id": "CWE-89",
            },
            {
                "severity": "MEDIUM",
                "category": "XSS",
                "message": "Cross-site scripting vulnerability",
                "file": "views.py",
                "line": 25,
                "column": 1,
                "cwe_id": "CWE-79",
            },
            {
                "severity": "LOW",
                "category": "Hardcoded Password",
                "message": "Password stored in code",
                "file": "config.py",
                "line": 5,
                "column": 1,
                "cwe_id": "CWE-798",
            },
        ]

        report = reporter.generate_report(issues, tool_name="PyGuard", tool_version="0.3.0")

        # Check results count
        assert len(report["runs"][0]["results"]) == 3

        # Check severity levels
        levels = [result["level"] for result in report["runs"][0]["results"]]
        assert "error" in levels
        assert "warning" in levels
        assert "note" in levels

    def test_extract_rules(self):
        """Test rule extraction from issues."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "SQL injection",
                "cwe_id": "CWE-89",
                "file": "test.py",
                "line": 1,
            },
            {
                "severity": "HIGH",
                "category": "SQL Injection",
                "message": "Another SQL injection",
                "cwe_id": "CWE-89",
                "file": "test2.py",
                "line": 1,
            },
            {
                "severity": "MEDIUM",
                "category": "XSS",
                "message": "XSS vulnerability",
                "cwe_id": "CWE-79",
                "file": "test3.py",
                "line": 1,
            },
        ]

        report = reporter.generate_report(issues)
        rules = report["runs"][0]["tool"]["driver"]["rules"]

        # Should have 2 unique rules (CWE-89 and CWE-79)
        assert len(rules) == 2
        rule_ids = [rule["id"] for rule in rules]
        assert "PY/CWE-89" in rule_ids
        assert "PY/CWE-79" in rule_ids

    def test_rule_without_cwe(self):
        """Test rule generation for issues without CWE ID."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "MEDIUM",
                "category": "Code Quality Issue",
                "message": "Code quality problem",
                "file": "test.py",
                "line": 1,
            }
        ]

        report = reporter.generate_report(issues)
        result = report["runs"][0]["results"][0]

        # Should use category-based rule ID
        assert result["ruleId"] == "PY/CODE-QUALITY-ISSUE"

    def test_tags_generation(self):
        """Test tag generation for different issue types."""
        reporter = SARIFReporter()

        # SQL injection
        issue_sql = {
            "severity": "HIGH",
            "category": "SQL Injection",
            "cwe_id": "CWE-89",
            "message": "SQL injection",
        }
        tags_sql = reporter._get_tags(issue_sql)
        assert "security" in tags_sql
        assert "sql" in tags_sql
        assert "injection" in tags_sql
        assert "high" in tags_sql
        assert "cwe-89" in tags_sql

        # XSS
        issue_xss = {"severity": "MEDIUM", "category": "Cross-Site Scripting", "message": "XSS"}
        tags_xss = reporter._get_tags(issue_xss)
        assert "security" in tags_xss
        assert "xss" in tags_xss

        # Authentication
        issue_auth = {
            "severity": "HIGH",
            "category": "Weak Password",
            "message": "Weak password",
        }
        tags_auth = reporter._get_tags(issue_auth)
        assert "security" in tags_auth
        assert "authentication" in tags_auth

        # Cryptography
        issue_crypto = {
            "severity": "HIGH",
            "category": "Weak Crypto",
            "message": "Weak cryptography",
        }
        tags_crypto = reporter._get_tags(issue_crypto)
        assert "security" in tags_crypto
        assert "cryptography" in tags_crypto

    def test_security_severity_scores(self):
        """Test security severity score mapping."""
        reporter = SARIFReporter()

        assert reporter._get_security_severity("CRITICAL") == "9.0"
        assert reporter._get_security_severity("HIGH") == "7.0"
        assert reporter._get_security_severity("MEDIUM") == "5.0"
        assert reporter._get_security_severity("LOW") == "3.0"
        assert reporter._get_security_severity("INFO") == "1.0"
        assert reporter._get_security_severity("UNKNOWN") == "5.0"

    def test_markdown_help_formatting(self):
        """Test markdown help text formatting."""
        reporter = SARIFReporter()
        issue = {
            "category": "SQL Injection",
            "message": "Potential SQL injection vulnerability",
            "cwe_id": "CWE-89",
            "owasp_id": "A03:2021",
            "fix_suggestion": "Use parameterized queries instead of string concatenation",
        }

        markdown = reporter._format_help_markdown(issue)

        assert "## SQL Injection" in markdown
        assert "Potential SQL injection vulnerability" in markdown
        assert "CWE-89" in markdown
        assert "https://cwe.mitre.org/data/definitions/89.html" in markdown
        assert "A03:2021" in markdown
        assert "Use parameterized queries" in markdown

    def test_save_report(self, tmp_path):
        """Test saving SARIF report to file."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "HIGH",
                "category": "Test Issue",
                "message": "Test message",
                "file": "test.py",
                "line": 1,
            }
        ]

        report = reporter.generate_report(issues)
        output_path = tmp_path / "test-report.sarif"

        result = reporter.save_report(report, output_path)

        assert result is True
        assert output_path.exists()

        # Verify file content is valid JSON
        with open(output_path, "r", encoding="utf-8") as f:
            loaded_report = json.load(f)
            assert loaded_report["version"] == "2.1.0"

    def test_save_report_handles_exceptions(self, tmp_path, monkeypatch):
        """Test save_report handles exceptions gracefully."""
        reporter = SARIFReporter()
        issues = [{"severity": "HIGH", "category": "Test", "message": "Test", "file": "test.py", "line": 1}]
        report = reporter.generate_report(issues)
        
        # Mock open to raise an exception
        def mock_open(*args, **kwargs):
            raise IOError("Disk full")
        
        monkeypatch.setattr("builtins.open", mock_open)
        
        output_path = tmp_path / "test-report.sarif"
        result = reporter.save_report(report, output_path)
        
        # Should return False on exception
        assert result is False

    def test_validate_report(self):
        """Test SARIF report validation."""
        reporter = SARIFReporter()

        # Valid report
        valid_report = reporter.generate_report(
            issues=[
                {
                    "severity": "HIGH",
                    "category": "Test",
                    "message": "Test",
                    "file": "test.py",
                    "line": 1,
                }
            ]
        )
        assert reporter.validate_report(valid_report) is True

        # Invalid reports
        invalid_report_1 = {"version": "2.1.0"}  # Missing required fields
        assert reporter.validate_report(invalid_report_1) is False

        invalid_report_2 = {"$schema": "test", "version": "2.1.0", "runs": []}  # Empty runs
        assert reporter.validate_report(invalid_report_2) is False

    def test_repository_uri_integration(self):
        """Test repository URI in SARIF report."""
        reporter = SARIFReporter()
        repo_uri = "https://github.com/user/repo"

        report = reporter.generate_report(
            issues=[],
            tool_name="PyGuard",
            tool_version="0.3.0",
            repository_uri=repo_uri,
        )

        assert "versionControlProvenance" in report["runs"][0]
        assert report["runs"][0]["versionControlProvenance"][0]["repositoryUri"] == repo_uri

    def test_code_snippet_in_location(self):
        """Test code snippet inclusion in SARIF location."""
        reporter = SARIFReporter()
        issues = [
            {
                "severity": "HIGH",
                "category": "Test Issue",
                "message": "Test",
                "file": "test.py",
                "line": 10,
                "column": 5,
                "code_snippet": "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
            }
        ]

        report = reporter.generate_report(issues)
        result = report["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]

        assert "snippet" in location["region"]
        assert (
            location["region"]["snippet"]["text"]
            == "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)"
        )

    def test_invocations_timestamp(self):
        """Test that invocations include timestamp."""
        reporter = SARIFReporter()
        report = reporter.generate_report(issues=[])

        invocations = report["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert "endTimeUtc" in invocations[0]
        assert invocations[0]["endTimeUtc"].endswith("Z")

    def test_tool_properties(self):
        """Test tool properties in SARIF report."""
        reporter = SARIFReporter()
        report = reporter.generate_report(issues=[], tool_name="PyGuard", tool_version="0.3.0")

        driver = report["runs"][0]["tool"]["driver"]
        assert driver["name"] == "PyGuard"
        assert driver["version"] == "0.3.0"
        assert driver["semanticVersion"] == "0.3.0"
        assert "informationUri" in driver
        assert "github.com/cboyd0319/PyGuard" in driver["informationUri"]
        assert "properties" in driver
        assert "description" in driver["properties"]
        assert "tags" in driver["properties"]
        assert "security" in driver["properties"]["tags"]

    def test_github_code_scanning_compatibility(self):
        """Test GitHub Code Scanning specific features."""
        reporter = SARIFReporter()
        report = reporter.generate_report(
            issues=[
                {
                    "severity": "HIGH",
                    "category": "SQL Injection",
                    "message": "SQL injection vulnerability",
                    "file": "app.py",
                    "line": 10,
                    "column": 5,
                    "cwe_id": "CWE-89",
                    "owasp_id": "A03:2021",
                }
            ]
        )

        run = report["runs"][0]

        # Check columnKind for GitHub compatibility
        assert run["columnKind"] == "utf16CodeUnits"

        # Check automation details
        assert "automationDetails" in run
        assert "id" in run["automationDetails"]
        assert "guid" in run["automationDetails"]

        # Check tool organization and download URI
        driver = run["tool"]["driver"]
        assert "organization" in driver
        assert driver["organization"] == "PyGuard"
        assert "downloadUri" in driver
        assert "releases" in driver["downloadUri"]

        # Check enhanced tags
        assert "sarif" in driver["properties"]["tags"]
        assert "owasp" in driver["properties"]["tags"]
        assert "cwe" in driver["properties"]["tags"]

    def test_working_directory_in_invocations(self):
        """Test working directory is included in invocations."""
        reporter = SARIFReporter()
        report = reporter.generate_report(issues=[])

        invocations = report["runs"][0]["invocations"]
        assert "workingDirectory" in invocations[0]
        assert "uri" in invocations[0]["workingDirectory"]
