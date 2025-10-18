"""
Unit tests for Secret Scanner module.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from pyguard.lib.secret_scanner import SecretFinding, SecretScanner


class TestSecretFinding:
    """Test SecretFinding dataclass."""

    def test_secret_finding_creation(self):
        """Test creating a SecretFinding instance."""
        finding = SecretFinding(
            file_path='test.py',
            line_number=42,
            secret_type='API Key',
            match='api_key = "***REDACTED***"',
        )

        assert finding.file_path == 'test.py'
        assert finding.line_number == 42
        assert finding.secret_type == 'API Key'
        assert finding.match == 'api_key = "***REDACTED***"'
        assert finding.severity == 'CRITICAL'


class TestSecretScanner:
    """Test SecretScanner functionality."""

    def test_secret_patterns_defined(self):
        """Test that secret patterns are defined."""
        assert len(SecretScanner.SECRET_PATTERNS) > 0
        assert 'AWS Access Key' in SecretScanner.SECRET_PATTERNS
        assert 'GitHub Token' in SecretScanner.SECRET_PATTERNS
        assert 'Generic API Key' in SecretScanner.SECRET_PATTERNS

    def test_scan_secrets_with_findings(self):
        """Test scanning for secrets when secrets are found."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='test.py:10:password = "secret123"\n', returncode=0
            )

            findings = SecretScanner.scan_secrets('/test/path')

            assert len(findings) > 0
            # Verify the finding structure
            for finding in findings:
                assert isinstance(finding, SecretFinding)

    def test_scan_secrets_no_findings(self):
        """Test scanning for secrets when no secrets are found."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='', returncode=0)

            findings = SecretScanner.scan_secrets('/test/path')

            # Should have empty results for all patterns
            assert isinstance(findings, list)

    def test_scan_secrets_ripgrep_not_found(self):
        """Test handling when ripgrep is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            findings = SecretScanner.scan_secrets('/test/path')

            assert findings == []

    def test_scan_secrets_timeout(self):
        """Test handling timeout during secret scan."""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('rg', 60)):
            findings = SecretScanner.scan_secrets('/test/path')

            # Should return partial results or empty list
            assert isinstance(findings, list)

    def test_redact_secret_with_quoted_values(self):
        """Test redacting secrets in quoted strings."""
        text = 'password = "mySecretPassword123"'
        redacted = SecretScanner._redact_secret(text)

        assert '***REDACTED***' in redacted
        assert 'mySecretPassword123' not in redacted

    def test_redact_secret_with_tokens(self):
        """Test redacting long tokens."""
        text = 'token = AKIA1234567890ABCDEF'
        redacted = SecretScanner._redact_secret(text)

        assert '***REDACTED***' in redacted
        assert 'AKIA1234567890ABCDEF' not in redacted

    def test_export_to_sarif(self):
        """Test SARIF export functionality."""
        findings = [
            SecretFinding(
                file_path='test.py',
                line_number=10,
                secret_type='API Key',
                match='api_key = "***REDACTED***"',
            ),
            SecretFinding(
                file_path='config.py',
                line_number=5,
                secret_type='Password (hardcoded)',
                match='password = "***REDACTED***"',
            ),
        ]

        m = mock_open()
        with patch('builtins.open', m):
            SecretScanner._export_to_sarif(findings, 'test.sarif')

        # Verify the file was opened for writing
        m.assert_called_once_with('test.sarif', 'w')

        # Get the written content
        handle = m()
        written_content = ''.join(call.args[0] for call in handle.write.call_args_list)
        sarif_data = json.loads(written_content)

        # Verify SARIF structure
        assert sarif_data['version'] == '2.1.0'
        assert len(sarif_data['runs']) == 1
        assert sarif_data['runs'][0]['tool']['driver']['name'] == 'PyGuard Secret Scanner'
        assert len(sarif_data['runs'][0]['results']) == 2

    def test_scan_secrets_with_sarif_export(self):
        """Test scanning with SARIF export enabled."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='test.py:10:password = "secret"\n', returncode=0
            )

            m = mock_open()
            with patch('builtins.open', m):
                findings = SecretScanner.scan_secrets('/test/path', export_sarif=True)

            # Verify SARIF file was created
            assert m.called

    def test_finding_parsing(self):
        """Test parsing of ripgrep output into findings."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='src/config.py:15:api_key = "sk_test_1234567890"\n', returncode=0
            )

            findings = SecretScanner.scan_secrets('/test/path')

            # Should parse the output correctly
            for finding in findings:
                if finding.file_path == 'src/config.py':
                    assert finding.line_number == 15
                    assert '***REDACTED***' in finding.match
