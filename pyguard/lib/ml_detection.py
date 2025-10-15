"""
Machine Learning Enhanced Detection for PyGuard.

Uses lightweight ML techniques for:
- Pattern recognition in code vulnerabilities
- Anomaly detection in code patterns
- Risk scoring based on historical data
- Predictive analysis for potential issues

NOTE: Uses scikit-learn-style patterns without requiring heavy ML dependencies.
All models are rule-based and deterministic for transparency and explainability.

References:
- NIST AI Risk Management | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf | High | AI risk framework
- OWASP ML Security | https://owasp.org/www-project-machine-learning-security/ | Medium | ML security guidance
"""

import ast
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pyguard.lib.core import PyGuardLogger


@dataclass
class MLFeature:
    """Represents a feature extracted from code for ML analysis."""

    name: str
    value: float
    importance: float


@dataclass
class RiskScore:
    """Risk score for a code pattern."""

    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    factors: List[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


class CodeFeatureExtractor:
    """
    Extract features from code for ML-based analysis.

    Features include:
    - Code complexity metrics
    - Pattern frequencies
    - API usage patterns
    - Historical vulnerability indicators
    """

    def __init__(self):
        """Initialize feature extractor."""
        self.logger = PyGuardLogger()

    def extract_features(self, code: str, file_path: str = "") -> Dict[str, float]:
        """
        Extract numerical features from code.

        Args:
            code: Source code to analyze
            file_path: Optional file path for context

        Returns:
            Dictionary of feature names to values
        """
        features: Dict[str, float] = {}

        try:
            tree = ast.parse(code)

            # Complexity features
            features["num_functions"] = float(
                len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)])
            )
            features["num_classes"] = float(
                len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])
            )
            features["num_imports"] = float(
                len([n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))])
            )

            # Depth and nesting
            features["max_nesting"] = float(self._calculate_max_nesting(tree))

            # API usage patterns (security-relevant)
            features["eval_count"] = float(
                len(
                    [
                        n
                        for n in ast.walk(tree)
                        if isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Name)
                        and n.func.id in ["eval", "exec", "compile"]
                    ]
                )
            )

            features["subprocess_count"] = float(
                code.count("subprocess.") + code.count("os.system")
            )
            features["network_count"] = float(code.count("socket.") + code.count("requests."))
            features["file_ops_count"] = float(code.count("open(") + code.count("file("))

            # String patterns
            features["hardcoded_strings"] = float(
                len(re.findall(r'["\'](?:password|api_key|secret|token)["\']', code.lower()))
            )
            features["sql_patterns"] = float(
                len(re.findall(r"(?:SELECT|INSERT|UPDATE|DELETE)", code))
            )

            # Exception handling
            features["bare_except"] = float(code.count("except:"))
            features["try_except_ratio"] = code.count("try:") / max(1.0, features["num_functions"])

        except SyntaxError:
            # Return zeros for invalid syntax
            return {
                key: 0.0
                for key in [
                    "num_functions",
                    "num_classes",
                    "num_imports",
                    "max_nesting",
                    "eval_count",
                    "subprocess_count",
                    "network_count",
                    "file_ops_count",
                    "hardcoded_strings",
                    "sql_patterns",
                    "bare_except",
                    "try_except_ratio",
                ]
            }

        return features

    def _calculate_max_nesting(self, tree: ast.AST) -> int:
        """Calculate maximum nesting level in AST."""

        class DepthVisitor(ast.NodeVisitor):
            def __init__(self):
                self.depth = 0
                self.max_depth = 0

            def visit(self, node):
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1

        visitor = DepthVisitor()
        visitor.visit(tree)
        return visitor.max_depth


class MLRiskScorer:
    """
    ML-based risk scoring for code patterns.

    Uses rule-based heuristics combined with feature analysis to provide
    transparent, explainable risk scores.
    """

    def __init__(self):
        """Initialize ML risk scorer."""
        self.logger = PyGuardLogger()
        self.extractor = CodeFeatureExtractor()

    def calculate_risk_score(
        self, code: str, file_path: str = "", existing_issues: Optional[List] = None
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for code.

        Args:
            code: Source code to analyze
            file_path: Optional file path
            existing_issues: List of already detected issues

        Returns:
            RiskScore with overall assessment
        """
        features = self.extractor.extract_features(code, file_path)
        factors = []
        score = 0.0

        # Evaluate each feature
        if features.get("eval_count", 0) > 0:
            score += 0.3
            factors.append(f"Code injection risk: {int(features['eval_count'])} eval/exec calls")

        if features.get("subprocess_count", 0) > 2:
            score += 0.2
            factors.append(
                f"Command injection risk: {int(features['subprocess_count'])} subprocess calls"
            )

        if features.get("hardcoded_strings", 0) > 0:
            score += 0.25
            factors.append(
                f"Credential exposure risk: {int(features['hardcoded_strings'])} hardcoded secrets"
            )

        if features.get("sql_patterns", 0) > 2:
            score += 0.15
            factors.append(
                f"SQL injection risk: {int(features['sql_patterns'])} SQL patterns detected"
            )

        if features.get("bare_except", 0) > 0:
            score += 0.1
            factors.append(
                f"Error handling issue: {int(features['bare_except'])} bare except clauses"
            )

        if features.get("max_nesting", 0) > 10:
            score += 0.1
            factors.append(f"Complexity risk: nesting level {int(features['max_nesting'])}")

        # Network operations increase risk
        if features.get("network_count", 0) > 3:
            score += 0.1
            factors.append(f"Network security: {int(features['network_count'])} network operations")

        # Cap score at 1.0
        score = min(1.0, score)

        # Determine severity
        if score >= 0.8:
            severity = "CRITICAL"
        elif score >= 0.6:
            severity = "HIGH"
        elif score >= 0.3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Confidence based on number of factors
        confidence = min(1.0, 0.5 + (len(factors) * 0.1))

        return RiskScore(score=score, confidence=confidence, factors=factors, severity=severity)

    def predict_vulnerability_type(self, code_snippet: str) -> Optional[Tuple[str, float]]:
        """
        Predict most likely vulnerability type.

        Args:
            code_snippet: Code to analyze

        Returns:
            Tuple of (vulnerability_type, confidence) or None
        """
        features = self.extractor.extract_features(code_snippet)

        # Simple decision tree based on features
        predictions = []

        if features.get("eval_count", 0) > 0:
            predictions.append(("code_injection", 0.95))

        if features.get("subprocess_count", 0) > 0:
            predictions.append(("command_injection", 0.85))

        if features.get("hardcoded_strings", 0) > 0:
            predictions.append(("hardcoded_credentials", 0.80))

        if features.get("sql_patterns", 0) > 2:
            predictions.append(("sql_injection", 0.75))

        # Return highest confidence prediction
        if predictions:
            return max(predictions, key=lambda x: x[1])

        return None


class AnomalyDetector:
    """
    Detect anomalous code patterns that may indicate security issues.

    Uses statistical analysis and pattern recognition to identify:
    - Unusual API usage
    - Uncommon coding patterns
    - Potential obfuscation
    """

    def __init__(self):
        """Initialize anomaly detector."""
        self.logger = PyGuardLogger()

    def detect_anomalies(self, code: str) -> List[Dict[str, Any]]:
        """
        Detect anomalous patterns in code.

        Args:
            code: Source code to analyze

        Returns:
            List of detected anomalies with descriptions
        """
        anomalies = []

        # Obfuscation indicators
        if self._check_obfuscation(code):
            anomalies.append(
                {
                    "type": "obfuscation",
                    "severity": "HIGH",
                    "description": "Potential code obfuscation detected",
                    "confidence": 0.7,
                }
            )

        # Unusual string patterns
        if self._check_unusual_strings(code):
            anomalies.append(
                {
                    "type": "unusual_strings",
                    "severity": "MEDIUM",
                    "description": "Unusual string patterns detected",
                    "confidence": 0.6,
                }
            )

        # Suspicious imports
        suspicious_imports = self._check_suspicious_imports(code)
        if suspicious_imports:
            anomalies.append(
                {
                    "type": "suspicious_imports",
                    "severity": "MEDIUM",
                    "description": f"Suspicious imports: {', '.join(suspicious_imports)}",
                    "confidence": 0.8,
                }
            )

        return anomalies

    def _check_obfuscation(self, code: str) -> bool:
        """Check for code obfuscation indicators."""
        # Long single-line statements
        lines = code.split("\n")
        long_lines = [line for line in lines if len(line) > 200]
        if len(long_lines) > 3:
            return True

        # Excessive use of chr() or ord()
        if code.count("chr(") > 5 or code.count("ord(") > 5:
            return True

        # Base64 patterns
        if "base64.b64decode" in code and ".decode()" in code:
            return True

        return False

    def _check_unusual_strings(self, code: str) -> bool:
        """Check for unusual string patterns."""
        # Very long strings (potential data exfiltration)
        string_pattern = r'["\']([^"\']{200,})["\']'
        if re.search(string_pattern, code):
            return True

        # Hex encoded strings
        hex_pattern = r"\\x[0-9a-fA-F]{2}"
        if len(re.findall(hex_pattern, code)) > 10:
            return True

        return False

    def _check_suspicious_imports(self, code: str) -> List[str]:
        """Check for suspicious import statements."""
        suspicious = []

        # Network-related imports that could indicate malware
        if "socket" in code and ("connect" in code or "bind" in code):
            if "server" not in code.lower():
                suspicious.append("socket (potential backdoor)")

        # System modification
        if "ctypes" in code and ("windll" in code or "CDLL" in code):
            suspicious.append("ctypes (direct system access)")

        # Code execution
        if "__import__" in code or "importlib.import_module" in code:
            suspicious.append("dynamic imports (code injection risk)")

        return suspicious
