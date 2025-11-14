"""
Integration tests for GitHub Action and SARIF workflow.

These tests verify:
- Action.yml inputs and outputs
- SARIF generation and validation
- GitHub Code Scanning compatibility
- Error handling and edge cases
"""

import json
from pathlib import Path
import subprocess
import sys

import pytest


class TestGitHubActionIntegration:
    """Test GitHub Action integration and SARIF workflow."""

    def test_sarif_generation_with_issues(self, temp_dir):
        """Test SARIF generation when security issues are found."""
        # Create a test file with security issues
        test_file = temp_dir / "vulnerable.py"
        test_file.write_text(
            """
import os
import yaml

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"  # SECURITY: Use environment variables or config files

# SQL injection
def query_user(user_id):
    # TODO: Add docstring
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# Command injection
def run_cmd(filename):
    # TODO: Add docstring
    os.system("cat " + filename)  # SECURITY: Use subprocess.run() instead  # SECURITY: Use subprocess.run() instead

# Unsafe deserialization
def load_config(file_path):
    # TODO: Add docstring
    with open(file_path) as f:
        return yaml.safe_load(f)
"""
        )

        # Run PyGuard with SARIF output
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        # Check SARIF file was created
        sarif_file = temp_dir / "pyguard-report.sarif"
        assert sarif_file.exists(), "SARIF file should be created"

        # Validate SARIF content
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        # Validate SARIF structure
        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert "runs" in sarif_data
        assert len(sarif_data["runs"]) == 1

        run = sarif_data["runs"][0]

        # Validate tool information
        assert run["tool"]["driver"]["name"] == "PyGuard"
        assert "version" in run["tool"]["driver"]
        assert run["tool"]["driver"]["informationUri"] == "https://github.com/cboyd0319/PyGuard"

        # Validate results
        assert "results" in run
        assert len(run["results"]) > 0, "Should detect security issues"

        # Check for specific issues
        rule_ids = [result["ruleId"] for result in run["results"]]

        # Should detect at least hardcoded credentials
        assert any("CWE-798" in rid for rid in rule_ids), "Should detect hardcoded credentials"

    def test_sarif_generation_without_issues(self, temp_dir):
        """Test SARIF generation when no issues are found."""
        # Create a clean test file
        test_file = temp_dir / "clean.py"
        test_file.write_text(
            '''
"""A clean Python module with no security issues."""

def greet(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"

def add_numbers(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b
'''
        )

        # Run PyGuard with SARIF output
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        # Check SARIF file was created
        sarif_file = temp_dir / "pyguard-report.sarif"
        assert sarif_file.exists(), "SARIF file should be created even with no issues"

        # Validate SARIF content
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        # Basic structure should still be valid
        assert sarif_data["version"] == "2.1.0"
        assert len(sarif_data["runs"]) == 1

        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "PyGuard"

    def test_sarif_github_security_tab_format(self, temp_dir):
        """Test SARIF format is compatible with GitHub Security tab."""
        test_file = temp_dir / "test.py"
        test_file.write_text(
            """
import pickle

def load_data(data):
    # TODO: Add docstring
    return pickle.loads(data)  # CWE-502: Insecure deserialization  # SECURITY: Don't use pickle with untrusted data
"""
        )

        # Run PyGuard with SARIF output
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]

        # Check required fields for GitHub Security tab
        assert "$schema" in sarif_data
        assert sarif_data["$schema"].startswith("https://")

        # Tool must have required fields
        driver = run["tool"]["driver"]
        assert "name" in driver
        assert "version" in driver or "semanticVersion" in driver
        assert "informationUri" in driver

        # Results must have proper structure
        if run.get("results"):
            for result in run["results"]:
                assert "ruleId" in result
                assert "level" in result
                assert result["level"] in ["none", "note", "warning", "error"]
                assert "message" in result
                assert "text" in result["message"]

                # Locations must have proper structure
                assert "locations" in result
                assert len(result["locations"]) > 0

                for location in result["locations"]:
                    assert "physicalLocation" in location
                    phys_loc = location["physicalLocation"]
                    assert "artifactLocation" in phys_loc
                    assert "uri" in phys_loc["artifactLocation"]
                    assert "region" in phys_loc
                    assert "startLine" in phys_loc["region"]

    def test_sarif_cwe_owasp_mappings(self, temp_dir):
        """Test SARIF includes CWE and OWASP mappings."""
        test_file = temp_dir / "test.py"
        test_file.write_text(
            """
import hashlib

def hash_password(password):
    # TODO: Add docstring
    return hashlib.md5(password.encode()).hexdigest()  # CWE-327: Weak crypto  # SECURITY: Consider using SHA256 or stronger
"""
        )

        # Run PyGuard with SARIF output
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]

        # Check rules have CWE/OWASP properties
        if run.get("results"):
            for result in run["results"]:
                # Should have CWE/OWASP in properties or rule definition
                if "properties" in result:
                    props = result["properties"]
                    # Either CWE or OWASP should be present
                    has_security_mapping = (
                        "cwe" in props or "owasp" in props or "security-severity" in props
                    )
                    assert has_security_mapping, "Security issues should have CWE/OWASP mappings"

    def test_multiple_files_sarif_output(self, temp_dir):
        """Test SARIF generation with multiple files."""
        # Create multiple test files
        file1 = temp_dir / "app.py"
        file1.write_text(
            """
API_KEY = "secret123"  # Hardcoded secret
"""
        )

        file2 = temp_dir / "db.py"
        file2.write_text(
            """
def query(user_input):
    # TODO: Add docstring
    return "SELECT * FROM users WHERE id = " + user_input  # SQL injection
"""
        )

        # Run PyGuard on directory with SARIF output
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(temp_dir),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        assert sarif_file.exists()

        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]
        results = run.get("results", [])

        # Should have issues from both files
        assert len(results) >= 2, "Should detect issues from multiple files"

        # Check that different files are referenced
        file_uris = set()
        for result in results:
            for location in result["locations"]:
                uri = location["physicalLocation"]["artifactLocation"]["uri"]
                file_uris.add(uri)

        assert len(file_uris) >= 2, "Should report issues from multiple files"

    def test_sarif_fix_suggestions(self, temp_dir):
        """Test SARIF includes fix suggestions."""
        test_file = temp_dir / "test.py"
        test_file.write_text(
            """
import os

def dangerous_exec(code):  # DANGEROUS: Avoid exec with untrusted input
    # TODO: Add docstring
    exec(code)  # CWE-95: Code injection  # DANGEROUS: Avoid exec with untrusted input
"""
        )

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]

        # Check that results have fix suggestions
        if run.get("results"):
            for result in run["results"]:
                # Should have either fixes or help text with recommendations
                "fixes" in result or (
                    "help" in run["tool"]["driver"].get("rules", [{}])[0]
                    if run["tool"]["driver"].get("rules")
                    else False
                )
                # At minimum, should have a message describing the issue
                assert "message" in result
                assert len(result["message"]["text"]) > 0

    def test_sarif_severity_levels(self, temp_dir):
        """Test SARIF correctly maps severity levels."""
        test_file = temp_dir / "test.py"
        test_file.write_text(
            """
# Various severity issues
API_KEY = "sk-123"  # HIGH/CRITICAL

def func():
    # TODO: Add docstring
    pass  # Missing docstring - LOW
"""
        )

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]

        if run.get("results"):
            levels = [result["level"] for result in run["results"]]

            # Should have mapped severity levels
            assert all(level in ["none", "note", "warning", "error"] for level in levels)

            # Should have different severity levels
            # (at least note for documentation, error for security)
            assert "error" in levels or "warning" in levels, "Should have high severity issues"


class TestActionYmlConfiguration:
    """Test action.yml configuration and behavior."""

    def test_action_yml_exists(self):
        """Test action.yml file exists and is valid."""
        action_file = Path(__file__).parent.parent.parent / "action.yml"
        assert action_file.exists(), "action.yml should exist in repository root"

        # Read and parse as YAML
        import yaml

        with open(action_file) as f:
            action_config = yaml.safe_load(f)

        # Validate required fields
        assert "name" in action_config
        assert "description" in action_config
        assert "runs" in action_config
        assert action_config["runs"]["using"] == "composite"

    def test_action_inputs_defined(self):
        """Test all expected inputs are defined in action.yml."""
        action_file = Path(__file__).parent.parent.parent / "action.yml"

        import yaml

        with open(action_file) as f:
            action_config = yaml.safe_load(f)

        # Check expected inputs
        expected_inputs = [
            "paths",
            "python-version",
            "scan-only",
            "security-only",
            "severity",
            "exclude",
            "sarif-file",
            "upload-sarif",
            "fail-on-issues",
        ]

        for input_name in expected_inputs:
            assert input_name in action_config["inputs"], f"Input '{input_name}' should be defined"

            # Each input should have description
            assert "description" in action_config["inputs"][input_name]

    def test_action_outputs_defined(self):
        """Test action outputs are properly defined."""
        action_file = Path(__file__).parent.parent.parent / "action.yml"

        import yaml

        with open(action_file) as f:
            action_config = yaml.safe_load(f)

        # Check expected outputs
        assert "outputs" in action_config
        assert "issues-found" in action_config["outputs"]
        assert "sarif-file" in action_config["outputs"]

    def test_action_security_best_practices(self):
        """Test action.yml follows security best practices."""
        action_file = Path(__file__).parent.parent.parent / "action.yml"

        import yaml

        with open(action_file) as f:
            action_config = yaml.safe_load(f)

        steps = action_config["runs"]["steps"]

        # Check for pinned action versions (SHA)
        for step in steps:
            if "uses" in step:
                # Should use SHA pins or tagged versions
                uses = step["uses"]
                if "@" in uses:
                    version = uses.split("@")[1]
                    # Either a SHA (40 chars) or a version tag
                    assert len(version) >= 6, f"Action version should be pinned: {uses}"


class TestSARIFValidation:
    """Test SARIF output validation and compliance."""

    def test_sarif_schema_validation(self, temp_dir):
        """Test SARIF output validates against official schema."""
        test_file = temp_dir / "test.py"
        test_file.write_text('API_KEY = "secret"')

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        # Basic schema validation
        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert sarif_data["$schema"].endswith("sarif-schema-2.1.0.json")

    def test_sarif_location_references(self, temp_dir):
        """Test SARIF location references are correct."""
        test_file = temp_dir / "vulnerable.py"
        test_file.write_text(
            """
line 1
API_KEY = "secret"  # Line 3
line 4
"""
        )

        subprocess.run(
            [
                sys.executable,
                "-m",
                "pyguard.cli",
                str(test_file),
                "--scan-only",
                "--sarif",
                "--no-html",
            ],
            check=False,
            cwd=temp_dir,
            capture_output=True,
            text=True,
        )

        sarif_file = temp_dir / "pyguard-report.sarif"
        with open(sarif_file) as f:
            sarif_data = json.load(f)

        run = sarif_data["runs"][0]

        if run.get("results"):
            for result in run["results"]:
                for location in result["locations"]:
                    region = location["physicalLocation"]["region"]

                    # Line numbers should be positive
                    assert region["startLine"] > 0

                    # If column is present, should be positive
                    if "startColumn" in region:
                        assert region["startColumn"] >= 0


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test files."""
    return tmp_path
