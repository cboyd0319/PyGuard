"""
Fast secret scanning using ripgrep with comprehensive patterns.

Detects hardcoded credentials, API keys, tokens, and other sensitive data.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class SecretFinding:
    """Represents a detected secret in code."""

    file_path: str
    line_number: int
    secret_type: str
    match: str
    severity: str = 'CRITICAL'


class SecretScanner:
    """
    Fast secret scanning using ripgrep with comprehensive patterns.
    """

    SECRET_PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'aws_secret_access_key\s*=\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
        'Generic API Key': r'api[_-]?key\s*[=:]\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
        'Password (hardcoded)': r'password\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',
        'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
        'GitHub OAuth': r'gho_[a-zA-Z0-9]{36}',
        'Slack Token': r'xox[baprs]-[a-zA-Z0-9-]+',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'PyPI Token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}',
        'Azure Key': r'DefaultEndpointsProtocol=https;AccountName=.+;AccountKey=[A-Za-z0-9+/=]{88}',
        'Google API Key': r'AIza[0-9A-Za-z_\-]{35}',
        'Google OAuth': r'ya29\.[0-9A-Za-z_\-]+',
        'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'Database URL (PostgreSQL)': r'postgres://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+',
        'Database URL (MySQL)': r'mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+',
        'MongoDB URI': r'mongodb(\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+',
        'Redis URL': r'redis://:[^@\s]+@[a-zA-Z0-9.-]+',
    }

    @staticmethod
    def scan_secrets(path: str, export_sarif: bool = False) -> List[SecretFinding]:
        """
        Scan for hardcoded secrets using ripgrep.

        Args:
            path: Directory or file to scan
            export_sarif: Export findings to SARIF format

        Returns:
            List of secret findings
        """
        findings = []

        for secret_type, pattern in SecretScanner.SECRET_PATTERNS.items():
            try:
                result = subprocess.run(
                    [
                        'rg',
                        '--type',
                        'py',
                        '--line-number',
                        '--no-heading',
                        '--color',
                        'never',
                        '--max-count',
                        '1000',
                        pattern,
                        path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                for line in result.stdout.strip().split('\n'):
                    if line:
                        # Format: file.py:42:password = "secret123"
                        match = re.match(r'^(.+):(\d+):(.+)$', line)
                        if match:
                            findings.append(
                                SecretFinding(
                                    file_path=match.group(1),
                                    line_number=int(match.group(2)),
                                    secret_type=secret_type,
                                    match=SecretScanner._redact_secret(match.group(3)),
                                )
                            )

            except subprocess.TimeoutExpired:
                print(f"Warning: Timeout scanning for {secret_type}")
                continue
            except FileNotFoundError:
                # ripgrep not available
                return []

        if export_sarif:
            SecretScanner._export_to_sarif(findings, 'pyguard-secrets.sarif')

        return findings

    @staticmethod
    def _redact_secret(text: str) -> str:
        """
        Redact actual secret values in output for security.
        """
        # Redact values in quotes
        text = re.sub(r'([\'"])[^\'"]{8,}([\'"])', r'\1***REDACTED***\2', text)
        # Redact keys/tokens
        text = re.sub(r'[A-Za-z0-9_\-/+=]{20,}', '***REDACTED***', text)
        return text

    @staticmethod
    def _export_to_sarif(findings: List[SecretFinding], output_path: str):
        """Export findings to SARIF format for GitHub Code Scanning."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PyGuard Secret Scanner",
                            "version": "0.3.0",
                            "informationUri": "https://github.com/cboyd0319/PyGuard",
                        }
                    },
                    "results": [],
                }
            ],
        }

        for finding in findings:
            sarif['runs'][0]['results'].append(
                {
                    "ruleId": f"secret-{finding.secret_type.lower().replace(' ', '-')}",
                    "level": "error",
                    "message": {"text": f"Hardcoded {finding.secret_type} detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file_path},
                                "region": {"startLine": finding.line_number},
                            }
                        }
                    ],
                }
            )

        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)

        print(f"SARIF report exported to {output_path}")
