"""
SARIF (Static Analysis Results Interchange Format) Reporter for PyGuard.

Generates SARIF 2.1.0 compliant reports for GitHub Code Scanning integration.
Supports security vulnerabilities with CWE/OWASP mappings and severity levels.

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub Integration: https://docs.github.com/en/code-security/code-scanning
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyguard.lib.core import PyGuardLogger


@dataclass
class SARIFRule:
    """Represents a SARIF rule/check definition."""

    id: str
    name: str
    short_description: str
    full_description: str
    help_text: str
    default_level: str
    properties: Optional[Dict[str, Any]] = None


class SARIFReporter:
    """
    SARIF 2.1.0 compliant reporter for PyGuard analysis results.

    Generates SARIF reports compatible with GitHub Code Scanning and other
    SARIF-aware tools. Maps PyGuard security issues to SARIF format with
    proper severity levels, CWE/OWASP IDs, and fix suggestions.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
        "master/Schemata/sarif-schema-2.1.0.json"
    )

    # Severity mapping from PyGuard to SARIF levels
    SEVERITY_MAP = {
        "HIGH": "error",
        "CRITICAL": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    def __init__(self):
        """Initialize SARIF reporter."""
        self.logger = PyGuardLogger()

    def generate_report(
        self,
        issues: List[Dict[str, Any]],
        tool_name: str = "PyGuard",
        tool_version: str = "0.3.0",
        repository_uri: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate SARIF 2.1.0 compliant report.

        Args:
            issues: List of PyGuard issues to convert to SARIF format
            tool_name: Name of the analysis tool (default: PyGuard)
            tool_version: Version of the tool
            repository_uri: Optional URI of the repository being analyzed

        Returns:
            SARIF report as dictionary
        """
        # Group issues by rule ID to create rule definitions
        rules = self._extract_rules(issues)

        # Convert issues to SARIF results
        results = self._convert_issues_to_results(issues)

        # Build SARIF report structure
        run: Dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/cboyd0319/PyGuard",
                    "semanticVersion": tool_version,
                    "rules": rules,
                    "properties": {
                        "description": (
                            "Python security and code quality analysis tool with "
                            "ML-powered detection and auto-fix capabilities"
                        ),
                        "tags": [
                            "security",
                            "code-quality",
                            "python",
                            "static-analysis",
                        ],
                    },
                }
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                }
            ],
        }

        # Add repository information if provided
        if repository_uri:
            run["versionControlProvenance"] = [
                {"repositoryUri": repository_uri}
            ]

        sarif_report = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [run],
        }

        return sarif_report

    def _extract_rules(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract unique rules from issues.

        Args:
            issues: List of PyGuard issues

        Returns:
            List of SARIF rule definitions
        """
        rules_dict = {}

        for issue in issues:
            rule_id = self._get_rule_id(issue)
            if rule_id not in rules_dict:
                rules_dict[rule_id] = self._create_rule_definition(issue)

        return list(rules_dict.values())

    def _create_rule_definition(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create SARIF rule definition from an issue.

        Args:
            issue: PyGuard issue dictionary

        Returns:
            SARIF rule definition
        """
        rule_id = self._get_rule_id(issue)
        category = issue.get("category", "Unknown")
        severity = issue.get("severity", "LOW")
        cwe_id = issue.get("cwe_id", "")
        owasp_id = issue.get("owasp_id", "")

        # Build help text with fix suggestion if available
        help_text = issue.get("message", "")
        if issue.get("fix_suggestion"):
            help_text += f"\n\nFix: {issue['fix_suggestion']}"

        rule = {
            "id": rule_id,
            "name": category.replace(" ", ""),
            "shortDescription": {"text": category},
            "fullDescription": {"text": help_text},
            "help": {
                "text": help_text,
                "markdown": self._format_help_markdown(issue),
            },
            "defaultConfiguration": {"level": self._map_severity(severity)},
            "properties": {
                "tags": self._get_tags(issue),
                "precision": "high",
            },
        }

        # Add CWE/OWASP IDs if available
        if cwe_id:
            rule["properties"]["security-severity"] = self._get_security_severity(severity)
            rule["properties"]["cwe"] = cwe_id

        if owasp_id:
            rule["properties"]["owasp"] = owasp_id

        return rule

    def _convert_issues_to_results(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert PyGuard issues to SARIF results.

        Args:
            issues: List of PyGuard issues

        Returns:
            List of SARIF result objects
        """
        results = []

        for issue in issues:
            result = {
                "ruleId": self._get_rule_id(issue),
                "level": self._map_severity(issue.get("severity", "LOW")),
                "message": {"text": issue.get("message", "Security issue detected")},
                "locations": [self._create_location(issue)],
            }

            # Add fix suggestion as fix object if available
            if issue.get("fix_suggestion"):
                result["fixes"] = [
                    {
                        "description": {"text": issue["fix_suggestion"]},
                        "artifactChanges": [
                            {
                                "artifactLocation": {
                                    "uri": issue.get("file", "unknown"),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": issue.get("line", 1),
                                            "startColumn": max(1, issue.get("column", 1)),
                                        },
                                        "insertedContent": {
                                            "text": issue.get("fix_suggestion", "")
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]

            # Add properties for additional metadata
            properties = {}
            if issue.get("cwe_id"):
                properties["cwe"] = issue["cwe_id"]
            if issue.get("owasp_id"):
                properties["owasp"] = issue["owasp_id"]

            if properties:
                result["properties"] = properties

            results.append(result)

        return results

    def _create_location(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create SARIF location object from issue.

        Args:
            issue: PyGuard issue dictionary

        Returns:
            SARIF location object
        """
        file_path = issue.get("file", "unknown")
        line = issue.get("line", 1)
        column = max(1, issue.get("column", 1))  # Ensure column is >= 1 for SARIF compliance

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": line,
                    "startColumn": column,
                },
            }
        }

        # Add snippet if available
        if issue.get("code_snippet"):
            location["physicalLocation"]["region"]["snippet"] = {
                "text": issue["code_snippet"]
            }

        return location

    def _get_rule_id(self, issue: Dict[str, Any]) -> str:
        """
        Generate rule ID from issue category and CWE.

        Args:
            issue: PyGuard issue dictionary

        Returns:
            Rule ID string
        """
        category = issue.get("category", "Unknown")
        cwe_id = issue.get("cwe_id", "")

        # Use CWE ID if available, otherwise use category
        if cwe_id and cwe_id.startswith("CWE-"):
            return f"PY/{cwe_id}"
        else:
            # Create ID from category (e.g., "SQL Injection" -> "PY/SQL-INJECTION")
            rule_id = category.upper().replace(" ", "-")
            return f"PY/{rule_id}"

    def _map_severity(self, severity: str) -> str:
        """
        Map PyGuard severity to SARIF level.

        Args:
            severity: PyGuard severity (HIGH, MEDIUM, LOW, etc.)

        Returns:
            SARIF level (error, warning, note, none)
        """
        return self.SEVERITY_MAP.get(severity.upper(), "warning")

    def _get_security_severity(self, severity: str) -> str:
        """
        Get numeric security severity for SARIF.

        Args:
            severity: PyGuard severity

        Returns:
            Numeric severity score (0.0-10.0)
        """
        severity_scores = {
            "CRITICAL": "9.0",
            "HIGH": "7.0",
            "MEDIUM": "5.0",
            "LOW": "3.0",
            "INFO": "1.0",
        }
        return severity_scores.get(severity.upper(), "5.0")

    def _get_tags(self, issue: Dict[str, Any]) -> List[str]:
        """
        Generate tags for SARIF rule.

        Args:
            issue: PyGuard issue dictionary

        Returns:
            List of tags
        """
        tags = ["security"]

        # Add category-based tags
        category = issue.get("category", "").lower()
        if "injection" in category:
            tags.append("injection")
        if "xss" in category or "cross-site" in category:
            tags.append("xss")
        if "sql" in category:
            tags.append("sql")
        if "auth" in category or "password" in category:
            tags.append("authentication")
        if "crypto" in category or "hash" in category:
            tags.append("cryptography")

        # Add severity tag
        tags.append(issue.get("severity", "MEDIUM").lower())

        # Add CWE/OWASP tags if available
        if issue.get("cwe_id"):
            tags.append(issue["cwe_id"].lower())
        if issue.get("owasp_id"):
            tags.append("owasp")

        return tags

    def _format_help_markdown(self, issue: Dict[str, Any]) -> str:
        """
        Format help text as markdown.

        Args:
            issue: PyGuard issue dictionary

        Returns:
            Markdown formatted help text
        """
        markdown = f"## {issue.get('category', 'Security Issue')}\n\n"
        markdown += f"{issue.get('message', '')}\n\n"

        # Add CWE/OWASP references
        if issue.get("cwe_id"):
            cwe_num = issue["cwe_id"].replace("CWE-", "")
            markdown += f"**CWE Reference:** [{issue['cwe_id']}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)\n\n"

        if issue.get("owasp_id"):
            markdown += f"**OWASP Reference:** {issue['owasp_id']}\n\n"

        # Add fix suggestion
        if issue.get("fix_suggestion"):
            markdown += f"### Recommended Fix\n\n{issue['fix_suggestion']}\n"

        return markdown

    def save_report(self, report: Dict[str, Any], output_path: Path) -> bool:
        """
        Save SARIF report to file.

        Args:
            report: SARIF report dictionary
            output_path: Path to output file

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            self.logger.log(
                "INFO",
                f"SARIF report saved to {output_path}",
                category="SARIF Reporter",
                file_path=str(output_path),
                details={"num_issues": len(report["runs"][0]["results"])},
            )
            return True
        except Exception as e:
            self.logger.log(
                "ERROR",
                f"Failed to save SARIF report: {e}",
                category="SARIF Reporter",
                file_path=str(output_path),
                details={"error": str(e)},
            )
            return False

    def validate_report(self, report: Dict[str, Any]) -> bool:
        """
        Perform basic validation of SARIF report structure.

        Args:
            report: SARIF report dictionary

        Returns:
            True if valid, False otherwise
        """
        try:
            # Check required top-level fields
            assert "$schema" in report, "Missing $schema field"
            assert "version" in report, "Missing version field"
            assert "runs" in report, "Missing runs field"
            assert isinstance(report["runs"], list), "runs must be a list"
            assert len(report["runs"]) > 0, "runs must not be empty"

            # Check run structure
            run = report["runs"][0]
            assert "tool" in run, "Missing tool field in run"
            assert "results" in run, "Missing results field in run"

            # Check tool structure
            tool = run["tool"]
            assert "driver" in tool, "Missing driver field in tool"
            driver = tool["driver"]
            assert "name" in driver, "Missing name in driver"
            assert "version" in driver, "Missing version in driver"

            return True
        except AssertionError as e:
            self.logger.log(
                "ERROR",
                f"SARIF validation failed: {e}",
                category="SARIF Reporter",
                details={"error": str(e)},
            )
            return False
