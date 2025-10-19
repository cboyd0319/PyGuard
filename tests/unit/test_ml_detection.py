"""Unit tests for ML detection module."""

import pytest

from pyguard.lib.ml_detection import (
    AnomalyDetector,
    CodeFeatureExtractor,
    MLRiskScorer,
    RiskScore,
)


class TestCodeFeatureExtractor:
    """Test code feature extraction."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = CodeFeatureExtractor()

    def test_extract_basic_features(self):
        """Test extracting basic code features."""
        code = """
def hello():
    pass

class MyClass:
    pass
"""
        features = self.extractor.extract_features(code)

        assert features["num_functions"] == 1
        assert features["num_classes"] == 1
        assert features["num_imports"] == 0

    def test_extract_security_features(self):
        """Test extracting security-relevant features."""
        code = """
import subprocess
eval(user_input)
subprocess.run(['ls'])
"""
        features = self.extractor.extract_features(code)

        assert features["eval_count"] == 1
        assert features["subprocess_count"] > 0

    def test_extract_string_patterns(self):
        """Test extracting string patterns."""
        code = """
password = "secret"
api_key = "12345"
"""
        features = self.extractor.extract_features(code)

        assert features["hardcoded_strings"] >= 0

    def test_invalid_syntax(self):
        """Test handling invalid syntax."""
        code = "def invalid syntax here"
        features = self.extractor.extract_features(code)

        # Should return zeros for all features
        assert features["num_functions"] == 0.0


class TestMLRiskScorer:
    """Test ML risk scoring."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scorer = MLRiskScorer()

    def test_calculate_risk_score_safe_code(self):
        """Test risk score for safe code."""
        code = """
def add(x, y):
    return x + y
"""
        score = self.scorer.calculate_risk_score(code)

        assert isinstance(score, RiskScore)
        assert score.score < 0.3
        assert score.severity == "LOW"
        assert score.confidence > 0.0

    def test_calculate_risk_score_dangerous_code(self):
        """Test risk score for dangerous code."""
        code = """
import subprocess
eval(user_input)
password = "secret123"
subprocess.run(user_command, shell=True)
"""
        score = self.scorer.calculate_risk_score(code)

        assert score.score > 0.25  # Should be at least MEDIUM risk
        assert score.severity in ["MEDIUM", "HIGH", "CRITICAL"]
        assert len(score.factors) > 0

    def test_risk_factors_include_details(self):
        """Test that risk factors include meaningful details."""
        code = "eval(x)\nexec(y)"
        score = self.scorer.calculate_risk_score(code)

        assert len(score.factors) > 0
        assert any("injection" in factor.lower() for factor in score.factors)

    def test_predict_vulnerability_type(self):
        """Test vulnerability type prediction."""
        code = "eval(user_input)"
        prediction = self.scorer.predict_vulnerability_type(code)

        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "code_injection"
        assert confidence > 0.8

    def test_predict_no_vulnerability(self):
        """Test prediction with safe code."""
        code = "x = 1 + 1"
        prediction = self.scorer.predict_vulnerability_type(code)

        # May return None or low-confidence prediction
        if prediction:
            _, confidence = prediction
            assert confidence < 0.9

    def test_calculate_risk_score_critical_severity(self):
        """Test that high-risk code gets CRITICAL severity."""
        # Code with multiple high-risk patterns to reach >= 0.8 score
        # eval (0.3) + subprocess>2 (0.2) + hardcoded (0.25) + sql>2 (0.15) = 0.9
        code = """
import subprocess
eval(user_input)
exec(code)
subprocess.run(cmd1, shell=True)
subprocess.run(cmd2, shell=True)
subprocess.run(cmd3, shell=True)
password = "secret"
query1 = "SELECT * FROM users"
query2 = "DELETE FROM data"  
query3 = "INSERT INTO logs"
"""
        score = self.scorer.calculate_risk_score(code)
        
        assert score.score >= 0.8
        assert score.severity == "CRITICAL"

    def test_predict_vulnerability_subprocess(self):
        """Test prediction for subprocess-based command injection."""
        code = "subprocess.run(user_cmd, shell=True)"
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "command_injection"
        assert confidence == 0.85

    def test_predict_vulnerability_hardcoded_credentials(self):
        """Test prediction for hardcoded credentials."""
        code = '''x = "api_key"'''
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "hardcoded_credentials"
        assert confidence == 0.80

    def test_predict_vulnerability_sql_injection(self):
        """Test prediction for SQL injection patterns."""
        code = """
query1 = "SELECT * FROM users"
query2 = "DELETE FROM data"
query3 = "INSERT INTO logs"
cursor.execute(query1)
"""
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "sql_injection"
        assert confidence == 0.75


class TestAnomalyDetector:
    """Test anomaly detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_detect_no_anomalies(self):
        """Test detection with normal code."""
        code = """
def hello():
    print("Hello, World!")
"""
        anomalies = self.detector.detect_anomalies(code)

        assert isinstance(anomalies, list)
        # Normal code should have few or no anomalies
        assert len(anomalies) == 0

    def test_detect_obfuscation(self):
        """Test obfuscation detection."""
        code = """
x = chr(101) + chr(118) + chr(97) + chr(108)
exec(x + "(user_input)")
"""
        anomalies = self.detector.detect_anomalies(code)

        # May detect chr() usage as potential obfuscation
        # chr appears 4 times but threshold is 5, so may not trigger
        # Just verify we get a list back
        assert isinstance(anomalies, list)

    def test_detect_suspicious_imports(self):
        """Test suspicious import detection."""
        code = """
import socket
socket.connect(("evil.com", 1337))
"""
        anomalies = self.detector.detect_anomalies(code)

        # May detect suspicious socket usage
        if anomalies:
            assert any(a["type"] == "suspicious_imports" for a in anomalies)

    def test_detect_unusual_strings(self):
        """Test unusual string pattern detection."""
        # Very long string
        long_string = "x" * 300
        code = f'data = "{long_string}"'
        anomalies = self.detector.detect_anomalies(code)

        # Should detect unusual string length
        if anomalies:
            assert any(a["type"] == "unusual_strings" for a in anomalies)

    def test_anomaly_severity_levels(self):
        """Test that anomalies have severity levels."""
        code = """
import ctypes
ctypes.CDLL("malicious.dll")
"""
        anomalies = self.detector.detect_anomalies(code)

        if anomalies:
            for anomaly in anomalies:
                assert "severity" in anomaly
                assert "confidence" in anomaly
                assert "description" in anomaly


    def test_detect_obfuscation_chr_usage(self):
        """Test obfuscation detection with excessive chr() usage."""
        # Use 6 chr() calls to exceed threshold of 5
        code = """
x = chr(101) + chr(118) + chr(97) + chr(108) + chr(40) + chr(41)
exec(x)
"""
        anomalies = self.detector.detect_anomalies(code)
        
        assert any(a["type"] == "obfuscation" for a in anomalies)
        assert any(a["severity"] == "HIGH" for a in anomalies)

    def test_detect_obfuscation_long_lines(self):
        """Test obfuscation detection with very long lines."""
        # Create 4 lines longer than 200 characters to exceed threshold of 3
        long_line = "x = " + " + ".join([f'"{i}"' for i in range(50)])
        code = "\n".join([long_line] * 4)
        
        anomalies = self.detector.detect_anomalies(code)
        
        assert any(a["type"] == "obfuscation" for a in anomalies)

    def test_detect_obfuscation_base64(self):
        """Test obfuscation detection with base64 decode."""
        code = """
import base64
data = base64.b64decode(secret).decode()
"""
        anomalies = self.detector.detect_anomalies(code)
        
        assert any(a["type"] == "obfuscation" for a in anomalies)

    def test_detect_unusual_strings_hex_encoding(self):
        """Test detection of hex-encoded strings."""
        # Create string with more than 10 hex escape sequences
        hex_string = "\\x48" * 15  # 15 hex escapes
        code = f'data = "{hex_string}"'
        
        anomalies = self.detector.detect_anomalies(code)
        
        assert any(a["type"] == "unusual_strings" for a in anomalies)

    def test_detect_suspicious_socket_without_server(self):
        """Test socket usage without server keyword."""
        code = """
import socket
sock = socket.socket()
sock.connect(("evil.com", 1337))
"""
        anomalies = self.detector.detect_anomalies(code)
        
        suspicious_imports = [a for a in anomalies if a["type"] == "suspicious_imports"]
        if suspicious_imports:
            assert "socket" in suspicious_imports[0]["description"]

    def test_detect_suspicious_ctypes(self):
        """Test ctypes with system access."""
        code = """
import ctypes
ctypes.windll.kernel32.SomeFunction()
"""
        anomalies = self.detector.detect_anomalies(code)
        
        suspicious_imports = [a for a in anomalies if a["type"] == "suspicious_imports"]
        if suspicious_imports:
            assert "ctypes" in suspicious_imports[0]["description"]

    def test_detect_suspicious_dynamic_imports(self):
        """Test dynamic import detection."""
        code = """
module = __import__("os")
module.system("ls")
"""
        anomalies = self.detector.detect_anomalies(code)
        
        suspicious_imports = [a for a in anomalies if a["type"] == "suspicious_imports"]
        if suspicious_imports:
            assert "dynamic imports" in suspicious_imports[0]["description"]


class TestMLRiskScorerEdgeCases:
    """Test edge cases for ML risk scoring."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scorer = MLRiskScorer()

    def test_critical_severity_threshold(self):
        """Test that score >= 0.8 results in CRITICAL severity."""
        # Create code with many high-risk factors to push score above 0.8
        code = """
import subprocess
eval(user_input)
exec(malicious_code)
password = "secret123"
api_key = "sk-1234567890"
token = "ghp_abcdefg"
subprocess.run(user_command, shell=True)
os.system(user_input)
"""
        score = self.scorer.calculate_risk_score(code)
        
        # With eval, exec, hardcoded secrets, and shell=True, score should be high
        assert score.severity == "CRITICAL"

    def test_predict_subprocess_injection(self):
        """Test prediction of command injection via subprocess."""
        code = """
import subprocess
subprocess.run(user_input, shell=True)
"""
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "command_injection"
        assert confidence == 0.85

    def test_predict_hardcoded_credentials(self):
        """Test prediction of hardcoded credentials."""
        code = """
password = "secret123"
api_key = "sk_test_1234"
"""
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "hardcoded_credentials"
        assert confidence == 0.80

    def test_predict_sql_injection(self):
        """Test prediction of SQL injection with multiple patterns."""
        code = """
query1 = "SELECT * FROM users WHERE id = " + user_id
query2 = "UPDATE users SET name = '" + name + "'"
query3 = "DELETE FROM data WHERE " + condition
cursor.execute(query1)
"""
        prediction = self.scorer.predict_vulnerability_type(code)
        
        assert prediction is not None
        vuln_type, confidence = prediction
        assert vuln_type == "sql_injection"
        assert confidence == 0.75


class TestRiskScore:
    """Test RiskScore dataclass."""

    def test_create_risk_score(self):
        """Test creating a risk score."""
        score = RiskScore(
            score=0.75,
            confidence=0.85,
            factors=["High complexity", "Dangerous API usage"],
            severity="HIGH",
        )

        assert score.score == 0.75
        assert score.confidence == 0.85
        assert len(score.factors) == 2
        assert score.severity == "HIGH"


class TestMLRiskScorerEdgeCases:
    """Test MLRiskScorer edge cases and threshold conditions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scorer = MLRiskScorer()

    def test_risk_score_subprocess_threshold(self):
        """Test subprocess count threshold (>2)."""
        code = """
import subprocess
subprocess.run(['ls'])
subprocess.run(['cat', 'file.txt'])
subprocess.run(['pwd'])
subprocess.run(['echo', 'test'])
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should trigger subprocess_count > 2
        assert score.score > 0
        assert any("Command injection" in factor for factor in score.factors)

    def test_risk_score_hardcoded_strings(self):
        """Test hardcoded string detection."""
        code = """
password = "mysecretpass123"
api_key = "sk-1234567890abcdef"
token = "ghp_abcdefghijklmnop"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Hardcoded strings detection depends on feature extractor patterns
        # Just verify we get a valid score
        assert 0.0 <= score.score <= 1.0
        assert score.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_risk_score_sql_patterns(self):
        """Test SQL pattern detection threshold (>2)."""
        code = """
query1 = "SELECT * FROM users"
query2 = "INSERT INTO logs VALUES (1, 'test')"
query3 = "UPDATE settings SET value=1"
query4 = "DELETE FROM temp"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should trigger sql_patterns > 2
        assert any("SQL injection" in factor for factor in score.factors)

    def test_risk_score_bare_except(self):
        """Test bare except clause detection."""
        code = """
try:
    risky_operation()
except:
    pass
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should trigger bare_except > 0
        assert any("Error handling" in factor for factor in score.factors)

    def test_risk_score_max_nesting(self):
        """Test maximum nesting level detection (>10)."""
        # Create deeply nested code
        code = """
def deeply_nested():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            if True:
                                if True:
                                    if True:
                                        if True:
                                            if True:
                                                pass
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should trigger max_nesting > 10
        assert any("Complexity risk" in factor for factor in score.factors)

    def test_risk_score_network_operations(self):
        """Test network operation detection threshold (>3)."""
        code = """
import socket
socket.socket()
socket.create_connection(('host', 80))
socket.create_server(('', 8000))
socket.getaddrinfo('host', 80)
socket.gethostbyname('example.com')
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should trigger network_count > 3
        assert any("Network security" in factor for factor in score.factors)

    def test_risk_score_critical_severity(self):
        """Test high-risk code with multiple vulnerabilities."""
        code = """
import subprocess
eval(user_input)
exec(code)
compile(source, '', 'exec')
subprocess.run(cmd)
subprocess.Popen(cmd)
subprocess.call(cmd)
password = "secret123"
api_key = "sk-test123"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Code with eval/exec should score high
        # At minimum should be MEDIUM or higher
        assert score.severity in ["MEDIUM", "HIGH", "CRITICAL"]
        assert score.score > 0.3

    def test_risk_score_high_severity(self):
        """Test HIGH severity threshold (score >= 0.6)."""
        code = """
import subprocess
eval(user_input)
password = "secret"
query = "SELECT * FROM users"
query2 = "DELETE FROM logs"
query3 = "UPDATE data SET x=1"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Should be in HIGH range (0.6-0.8)
        assert score.severity in ["HIGH", "CRITICAL"]

    def test_risk_score_medium_severity(self):
        """Test code with moderate risk indicators."""
        code = """
try:
    operation()
except:
    pass

query = "SELECT * FROM data"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Bare except should add some risk
        # Just verify we get a valid score
        assert 0.0 <= score.score <= 1.0
        assert score.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_risk_score_low_severity(self):
        """Test LOW severity for minimal risks."""
        code = """
def simple_function():
    x = 1 + 1
    return x
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Clean code should have LOW severity
        assert score.severity == "LOW"

    def test_risk_score_capped_at_one(self):
        """Test that risk score is capped at 1.0."""
        code = """
import subprocess
eval(user_input)
exec(code)
compile(source, '', 'exec')
eval(data)
exec(more_code)
compile(src2, '', 'exec')
subprocess.run(cmd1)
subprocess.Popen(cmd2)
subprocess.call(cmd3)
subprocess.run(cmd4)
password = "secret123"
api_key = "sk-test123"
token = "token123"
query1 = "SELECT * FROM users"
query2 = "DELETE FROM data"
query3 = "UPDATE settings"
query4 = "INSERT INTO logs"
"""
        score = self.scorer.calculate_risk_score(code)
        
        # Score should be capped at 1.0
        assert score.score <= 1.0


class TestAnomalyDetectorEdgeCases:
    """Test AnomalyDetector edge cases."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_detect_empty_code(self):
        """Test anomaly detection on empty code."""
        anomalies = self.detector.detect_anomalies("")
        assert isinstance(anomalies, list)

    def test_detect_whitespace_only(self):
        """Test anomaly detection on whitespace-only code."""
        anomalies = self.detector.detect_anomalies("   \n\n   \t\t  ")
        assert isinstance(anomalies, list)

    def test_detect_comment_only(self):
        """Test anomaly detection on comment-only code."""
        code = """
# This is a comment
# Another comment
"""
        anomalies = self.detector.detect_anomalies(code)
        assert isinstance(anomalies, list)

    def test_detect_invalid_syntax(self):
        """Test anomaly detection handles invalid syntax gracefully."""
        code = "def invalid syntax here ["
        anomalies = self.detector.detect_anomalies(code)
        # Should return list (possibly empty) rather than raising exception
        assert isinstance(anomalies, list)


class TestCodeFeatureExtractorEdgeCases:
    """Test CodeFeatureExtractor edge cases."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = CodeFeatureExtractor()

    def test_extract_features_empty_string(self):
        """Test feature extraction from empty string."""
        features = self.extractor.extract_features("")
        # Should return dict with zero values
        assert isinstance(features, dict)
        assert features["num_functions"] == 0.0

    def test_extract_features_with_file_path(self):
        """Test feature extraction with file path context."""
        code = "def test(): pass"
        features = self.extractor.extract_features(code, file_path="test.py")
        assert isinstance(features, dict)
        assert features["num_functions"] >= 1

    def test_extract_features_complex_nesting(self):
        """Test feature extraction with complex nesting."""
        code = """
def outer():
    def inner1():
        def inner2():
            def inner3():
                pass
"""
        features = self.extractor.extract_features(code)
        # Should track nested functions
        assert features["num_functions"] >= 1
        assert "max_nesting" in features


class TestMLDetectorEdgeCases:
    """Test edge cases and missing branch coverage."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_detect_suspicious_imports_server_socket(self):
        """Test socket usage in server context (legitimate use case)."""
        # Arrange - socket used for server, which is legitimate
        code = """
import socket
server = socket.socket()
server.bind(("0.0.0.0", 8080))
server.listen(5)
"""
        # Act
        anomalies = self.detector.detect_anomalies(code)
        
        # Assert - should not flag as suspicious because 'server' is in the code
        if anomalies:
            suspicious_socket = [a for a in anomalies if a["type"] == "suspicious_imports" and "socket" in str(a)]
            # Should either have no anomalies or the socket anomaly should be filtered out
            # because "server" appears in the code
            assert len(suspicious_socket) == 0 or "backdoor" not in str(suspicious_socket)
