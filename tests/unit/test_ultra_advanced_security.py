"""
Tests for ultra-advanced security detections in PyGuard.

Tests world-class security detection capabilities including:
- GraphQL injection
- Server-Side Template Injection (SSTI)
- JWT security vulnerabilities
- API rate limiting
- Container escape vulnerabilities
- Prototype pollution
- Cache poisoning
- Business logic flaws
"""

import pytest

from pyguard.lib.ultra_advanced_security import (
    APIRateLimitDetector,
    BusinessLogicDetector,
    CachePoisoningDetector,
    ContainerEscapeDetector,
    GraphQLInjectionDetector,
    JWTSecurityDetector,
    PrototypePollutionDetector,
    SSTIDetector,
)


class TestGraphQLInjectionDetector:
    """Test GraphQL injection detection."""

    def test_detect_query_concatenation(self):
        """Should detect string concatenation in GraphQL queries."""
        detector = GraphQLInjectionDetector()
        code = """
query = "{ user(id: " + user_id + ") { name } }"
result = graphql.execute(query)
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any("concatenation" in issue.message.lower() for issue in issues)
        assert all(issue.severity in ["HIGH", "CRITICAL"] for issue in issues)

    def test_detect_fstring_query(self):
        """Should detect f-string formatting in GraphQL queries."""
        detector = GraphQLInjectionDetector()
        code = """
query = f"{{ user(id: {user_id}) {{ name }} }}"
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any(issue.cwe_id == "CWE-943" for issue in issues)

    def test_detect_format_method(self):
        """Should detect .format() in GraphQL queries."""
        detector = GraphQLInjectionDetector()
        code = """
query = "{ user(id: {}) { name } }".format(user_id)
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0

    def test_safe_query_no_issue(self):
        """Should not flag parameterized GraphQL queries."""
        detector = GraphQLInjectionDetector()
        code = """
query = "{ user(id: $userId) { name } }"
result = graphql.execute(query, variables={"userId": user_id})
"""
        issues = detector.scan_code(code)
        assert len(issues) == 0


class TestSSTIDetector:
    """Test Server-Side Template Injection detection."""

    def test_detect_render_template_string(self):
        """Should detect render_template_string with user input."""
        detector = SSTIDetector(
            [
                "from flask import render_template_string",
                "html = render_template_string(user_template)",
            ]
        )
        import ast

        tree = ast.parse("\n".join(detector.source_lines))
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any(issue.severity == "CRITICAL" for issue in detector.issues)
        assert any("template injection" in issue.category.lower() for issue in detector.issues)

    def test_detect_template_concatenation(self):
        """Should detect Template() with string concatenation."""
        detector = SSTIDetector(
            ["from jinja2 import Template", 'template = Template("Hello " + user_input)']
        )
        import ast

        tree = ast.parse("\n".join(detector.source_lines))
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any(issue.cwe_id == "CWE-94" for issue in detector.issues)

    def test_safe_template_no_issue(self):
        """Should not flag safe template usage."""
        detector = SSTIDetector(
            [
                "from flask import render_template",
                'html = render_template("template.html", data=user_data)',
            ]
        )
        import ast

        tree = ast.parse("\n".join(detector.source_lines))
        detector.visit(tree)

        assert len(detector.issues) == 0


class TestJWTSecurityDetector:
    """Test JWT security vulnerability detection."""

    def test_detect_none_algorithm(self):
        """Should detect JWT with 'none' algorithm."""
        detector = JWTSecurityDetector()
        code = """
token = jwt.encode(payload, key, algorithm="none")
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any(issue.severity == "CRITICAL" for issue in issues)
        assert any("none" in issue.message.lower() for issue in issues)

    def test_detect_disabled_verification(self):
        """Should detect disabled JWT signature verification."""
        detector = JWTSecurityDetector()
        code = """
payload = jwt.decode(token, verify=False)
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any(issue.severity == "CRITICAL" for issue in issues)

    def test_detect_weak_key(self):
        """Should detect weak JWT signing keys."""
        detector = JWTSecurityDetector()
        code = """
token = jwt.encode(payload, key="short", algorithm="HS256")
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any("key" in issue.message.lower() for issue in issues)

    def test_safe_jwt_no_issue(self):
        """Should not flag secure JWT usage."""
        detector = JWTSecurityDetector()
        code = """
token = jwt.encode(payload, private_key, algorithm="RS256")
payload = jwt.decode(token, public_key, algorithms=["RS256"])
"""
        issues = detector.scan_code(code)
        assert len(issues) == 0


class TestAPIRateLimitDetector:
    """Test API rate limiting detection."""

    def test_detect_missing_rate_limit(self):
        """Should detect API endpoints without rate limiting."""
        code = """
import app

@app.route('/api/data')
def get_data():
    return jsonify(data)
"""
        detector = APIRateLimitDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any("rate limiting" in issue.message.lower() for issue in detector.issues)
        assert any(issue.cwe_id == "CWE-770" for issue in detector.issues)

    def test_rate_limited_endpoint_no_issue(self):
        """Should not flag endpoints with rate limiting."""
        code = """
@app.route('/api/data')
@limiter.limit("100/hour")
def get_data():
    return jsonify(data)
"""
        detector = APIRateLimitDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) == 0


class TestContainerEscapeDetector:
    """Test container escape vulnerability detection."""

    def test_detect_privileged_mode(self):
        """Should detect privileged container mode."""
        detector = ContainerEscapeDetector()
        docker_compose = """
version: '3'
services:
  app:
    image: myapp
    privileged: true
"""
        issues = detector.scan_file("docker-compose.yml", docker_compose)
        assert len(issues) > 0
        assert any("privileged" in issue.message.lower() for issue in issues)
        assert any(issue.severity == "HIGH" for issue in issues)

    def test_detect_root_user(self):
        """Should detect container running as root."""
        detector = ContainerEscapeDetector()
        dockerfile = """
FROM python:3.9
USER root
COPY . /app
"""
        issues = detector.scan_file("Dockerfile", dockerfile)
        assert len(issues) > 0
        assert any("root" in issue.message.lower() for issue in issues)

    def test_detect_docker_socket_mount(self):
        """Should detect Docker socket mounting."""
        detector = ContainerEscapeDetector()
        docker_compose = """
version: '3'
services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        issues = detector.scan_file("docker-compose.yml", docker_compose)
        assert len(issues) > 0
        assert any("docker.sock" in issue.code_snippet.lower() for issue in issues)

    def test_safe_container_no_issue(self):
        """Should not flag secure container configuration."""
        detector = ContainerEscapeDetector()
        dockerfile = """
FROM python:3.9
RUN useradd -m appuser
USER appuser
COPY --chown=appuser:appuser . /app
"""
        issues = detector.scan_file("Dockerfile", dockerfile)
        # Should have no critical issues (may have warnings about other things)
        assert not any("root" in issue.message.lower() for issue in issues)


class TestPrototypePollutionDetector:
    """Test prototype pollution detection."""

    def test_detect_dangerous_setattr(self):
        """Should detect setattr with user-controlled attribute names."""
        code = """
def update_object(obj, attr_name, value):
    setattr(obj, attr_name, value)
"""
        detector = PrototypePollutionDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any("setattr" in issue.message.lower() for issue in detector.issues)
        assert any(issue.cwe_id == "CWE-1321" for issue in detector.issues)

    def test_detect_dict_manipulation(self):
        """Should detect __dict__ manipulation with external data."""
        code = """
obj.__dict__ = external_data['attrs']
"""
        detector = PrototypePollutionDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any("__dict__" in issue.message for issue in detector.issues)

    def test_safe_attribute_access_no_issue(self):
        """Should not flag safe attribute access."""
        code = """
class User:
    def __init__(self, name):
        self.name = name
        self.email = None
"""
        detector = PrototypePollutionDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) == 0


class TestCachePoisoningDetector:
    """Test cache poisoning detection."""

    def test_detect_request_in_cache_key(self):
        """Should detect request data in cache keys."""
        detector = CachePoisoningDetector()
        code = """
@cache.memoize()
def get_data(request):
    cache_key = "data_" + request.args.get('id')
    return cache.get(cache_key)
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any("cache" in issue.category.lower() for issue in issues)

    def test_detect_cache_set_with_user_data(self):
        """Should detect cache.set with user-controlled keys."""
        detector = CachePoisoningDetector()
        code = """
cache.set(request.args['key'], value)
"""
        issues = detector.scan_code(code)
        assert len(issues) > 0
        assert any(issue.cwe_id == "CWE-444" for issue in issues)

    def test_safe_cache_no_issue(self):
        """Should not flag safe cache usage."""
        detector = CachePoisoningDetector()
        code = """
import hashlib
key_hash = hashlib.sha256(user_input.encode()).hexdigest()
cache.set(f"user_{key_hash}", value)
"""
        issues = detector.scan_code(code)
        # Should have minimal or no issues for hashed keys
        assert len([i for i in issues if "concatenating" in i.message.lower()]) == 0


class TestBusinessLogicDetector:
    """Test business logic vulnerability detection."""

    def test_detect_missing_balance_check(self):
        """Should detect financial functions without balance validation."""
        code = """
def transfer_money(from_account, to_account, amount):
    from_account.balance -= amount
    to_account.balance += amount
    db.commit()
"""
        detector = BusinessLogicDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any("balance" in issue.message.lower() for issue in detector.issues)
        assert any(issue.cwe_id == "CWE-840" for issue in detector.issues)

    def test_detect_missing_rollback(self):
        """Should detect financial functions without rollback handling."""
        code = """
def process_payment(user, amount):
    user.balance -= amount
    charge_card(user.card, amount)
    db.commit()
"""
        detector = BusinessLogicDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        assert len(detector.issues) > 0
        assert any("rollback" in issue.message.lower() for issue in detector.issues)

    def test_safe_financial_function_no_issue(self):
        """Should not flag properly implemented financial functions."""
        code = """
def transfer_money(from_account, to_account, amount):
    if from_account.balance < amount:
        raise InsufficientFunds()
    try:
        from_account.balance -= amount
        to_account.balance += amount
        db.commit()
    except Exception:
        db.rollback()
        raise
"""
        detector = BusinessLogicDetector(code.split("\n"))
        import ast

        tree = ast.parse(code)
        detector.visit(tree)

        # Should have no issues or only minor ones
        critical_issues = [i for i in detector.issues if i.severity in ["CRITICAL", "HIGH"]]
        assert len(critical_issues) == 0


class TestIntegration:
    """Integration tests for all ultra-advanced detectors."""

    def test_all_detectors_initialized(self):
        """Test that all detectors can be initialized."""
        detectors = [
            GraphQLInjectionDetector(),
            JWTSecurityDetector(),
            ContainerEscapeDetector(),
            CachePoisoningDetector(),
        ]
        assert all(d is not None for d in detectors)

    def test_ast_detectors_initialized(self):
        """Test that all AST-based detectors can be initialized."""
        code = "# test code"
        lines = code.split("\n")

        ast_detectors = [
            SSTIDetector(lines),
            APIRateLimitDetector(lines),
            PrototypePollutionDetector(lines),
            BusinessLogicDetector(lines),
        ]
        assert all(d is not None for d in ast_detectors)

    def test_multiple_issues_detected(self):
        """Test that multiple issues can be detected in same code."""
        code = """
# Multiple vulnerabilities
token = jwt.encode(payload, key="weak", algorithm="none")
query = "{ user(id: " + user_id + ") }"
cache.set(request.args['key'], data)
"""
        jwt_detector = JWTSecurityDetector()
        graphql_detector = GraphQLInjectionDetector()
        cache_detector = CachePoisoningDetector()

        jwt_issues = jwt_detector.scan_code(code)
        graphql_issues = graphql_detector.scan_code(code)
        cache_issues = cache_detector.scan_code(code)

        total_issues = len(jwt_issues) + len(graphql_issues) + len(cache_issues)
        assert total_issues >= 3  # Should find at least 3 different issues
