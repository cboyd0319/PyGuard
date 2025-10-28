"""
Tests for ultra-advanced security auto-fixes in PyGuard.

Tests intelligent auto-fix capabilities for:
- GraphQL injection
- JWT security issues
- SSTI vulnerabilities
- API rate limiting
- Weak cryptography
- Container security
- SQL injection (enhanced)
- XSS vulnerabilities
"""

from pyguard.lib.ultra_advanced_fixes import UltraAdvancedSecurityFixer


class TestGraphQLInjectionFixes:
    """Test GraphQL injection auto-fixes."""

    def test_fix_query_concatenation(self):
        """Should fix string concatenation in GraphQL queries."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
query = "{ user(id: " + user_id + ") { name } }"
result = graphql.execute(query)
"""
        fixed, modified = fixer.fix_graphql_injection(code)
        assert modified
        assert "SECURITY" in fixed or "FIXED" in fixed
        assert "parameterized" in fixed.lower() or "variables" in fixed.lower()

    def test_fix_fstring_query(self):
        """Should add warning for f-string GraphQL queries."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'query = f"{{ user(id: {user_id}) {{ name }} }}"'
        fixed, modified = fixer.fix_graphql_injection(code)
        assert modified
        assert "SECURITY" in fixed

    def test_safe_query_unchanged(self):
        """Should not modify safe GraphQL queries."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
query = "{ user(id: $userId) { name } }"
result = graphql.execute(query, variables={"userId": user_id})
"""
        _fixed, modified = fixer.fix_graphql_injection(code)
        assert not modified


class TestJWTSecurityFixes:
    """Test JWT security auto-fixes."""

    def test_fix_none_algorithm(self):
        """Should fix JWT 'none' algorithm."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'token = jwt.encode(payload, key, algorithm="none")'
        fixed, modified = fixer.fix_jwt_security(code)
        assert modified
        assert "RS256" in fixed
        assert "none" not in fixed or 'from "none"' in fixed
        assert "FIXED" in fixed

    def test_fix_disabled_verification(self):
        """Should fix disabled JWT verification."""
        fixer = UltraAdvancedSecurityFixer()
        code = "payload = jwt.decode(token, verify=False)"
        fixed, modified = fixer.fix_jwt_security(code)
        assert modified
        assert "verify=True" in fixed
        assert "FIXED" in fixed

    def test_add_weak_key_warning(self):
        """Should add warning for weak JWT keys."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'token = jwt.encode(payload, key="short")'
        fixed, modified = fixer.fix_jwt_security(code)
        assert modified
        assert "SECURITY" in fixed
        assert "32 characters" in fixed or "RS256" in fixed


class TestSSTIFixes:
    """Test Server-Side Template Injection auto-fixes."""

    def test_fix_render_template_string(self):
        """Should fix render_template_string usage."""
        fixer = UltraAdvancedSecurityFixer()
        code = "html = render_template_string(user_template)"
        fixed, modified = fixer.fix_ssti_vulnerabilities(code)
        assert modified
        assert "render_template" in fixed
        assert "FIXED" in fixed or "SECURITY" in fixed

    def test_fix_template_concatenation(self):
        """Should add warning for template concatenation."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'template = Template("Hello " + user_input)'
        fixed, modified = fixer.fix_ssti_vulnerabilities(code)
        assert modified
        assert "SECURITY" in fixed
        assert "Template injection" in fixed

    def test_safe_template_unchanged(self):
        """Should not modify safe template usage."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'html = render_template("template.html", data=user_data)'
        _fixed, modified = fixer.fix_ssti_vulnerabilities(code)
        assert not modified


class TestAPIRateLimitingFixes:
    """Test API rate limiting auto-fixes."""

    def test_add_rate_limiter(self):
        """Should add rate limiter to API endpoints."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
@app.route('/api/data')
def get_data():
    return jsonify(data)
"""
        fixed, modified = fixer.fix_api_rate_limiting(code)
        assert modified
        assert "@limiter.limit" in fixed
        assert "Rate limiting" in fixed or "ADDED" in fixed

    def test_add_limiter_import(self):
        """Should add flask_limiter import if needed."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
@app.route('/api/data')
def get_data():
    return jsonify(data)
"""
        fixed, modified = fixer.fix_api_rate_limiting(code)
        assert modified
        assert "flask_limiter" in fixed

    def test_dont_duplicate_limiter(self):
        """Should not add rate limiter if already present."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
from flask_limiter import Limiter

@app.route('/api/data')
@limiter.limit("100/hour")
def get_data():
    return jsonify(data)
"""
        _fixed, _modified = fixer.fix_api_rate_limiting(code)
        # Should not modify if limiter is already there
        assert 'limiter.limit("100/hour")' in code


class TestWeakCryptographyFixes:
    """Test weak cryptography auto-fixes."""

    def test_fix_md5(self):
        """Should fix MD5 to SHA256."""
        fixer = UltraAdvancedSecurityFixer()
        code = "hash = hashlib.md5(data).hexdigest()"
        fixed, modified = fixer.fix_weak_cryptography(code)
        assert modified
        assert "sha256" in fixed
        assert "md5" not in fixed or "from MD5" in fixed
        assert "FIXED" in fixed

    def test_fix_sha1(self):
        """Should fix SHA1 to SHA256."""
        fixer = UltraAdvancedSecurityFixer()
        code = "hash = hashlib.sha1(data).hexdigest()"
        fixed, modified = fixer.fix_weak_cryptography(code)
        assert modified
        assert "sha256" in fixed
        assert "FIXED" in fixed

    def test_fix_des(self):
        """Should fix DES to AES."""
        fixer = UltraAdvancedSecurityFixer()
        code = "from Crypto.Cipher import DES"
        fixed, modified = fixer.fix_weak_cryptography(code)
        assert modified
        assert "AES" in fixed
        assert "FIXED" in fixed

    def test_safe_crypto_unchanged(self):
        """Should not modify secure cryptography."""
        fixer = UltraAdvancedSecurityFixer()
        code = "hash = hashlib.sha256(data).hexdigest()"
        _fixed, modified = fixer.fix_weak_cryptography(code)
        assert not modified


class TestContainerSecurityFixes:
    """Test container security auto-fixes."""

    def test_fix_dockerfile_root_user(self):
        """Should fix USER root in Dockerfile."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
FROM python:3.9
USER root
COPY . /app
"""
        fixed, modified = fixer.fix_container_security(code, "Dockerfile")
        assert modified
        assert "USER nonroot" in fixed
        assert "FIXED" in fixed

    def test_fix_privileged_mode(self):
        """Should fix privileged mode in docker-compose."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
version: '3'
services:
  app:
    privileged: true
"""
        fixed, modified = fixer.fix_container_security(code, "docker-compose.yml")
        assert modified
        assert "privileged: false" in fixed
        assert "FIXED" in fixed

    def test_add_security_opt(self):
        """Should add security_opt to docker-compose services."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
version: '3'
services:
  app:
    image: myapp
"""
        fixed, modified = fixer.fix_container_security(code, "docker-compose.yml")
        assert modified
        assert "security_opt:" in fixed
        assert "no-new-privileges" in fixed

    def test_non_container_file_unchanged(self):
        """Should not modify non-container files."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'USER = "admin"'
        _fixed, modified = fixer.fix_container_security(code, "app.py")
        assert not modified


class TestSQLInjectionEnhancedFixes:
    """Test enhanced SQL injection auto-fixes."""

    def test_fix_format_sql(self):
        """Should add warning for SQL with .format()."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'query = "SELECT * FROM users WHERE id = {}".format(user_id)'
        fixed, modified = fixer.fix_sql_injection_enhanced(code)
        assert modified
        assert "SECURITY" in fixed
        assert "SQL Injection" in fixed
        assert "parameterized" in fixed.lower()

    def test_fix_fstring_sql(self):
        """Should add warning for SQL with f-strings."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        fixed, modified = fixer.fix_sql_injection_enhanced(code)
        assert modified
        assert "SECURITY" in fixed
        assert "SQL Injection" in fixed

    def test_safe_sql_unchanged(self):
        """Should not modify parameterized queries."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        _fixed, modified = fixer.fix_sql_injection_enhanced(code)
        assert not modified


class TestXSSFixes:
    """Test XSS vulnerability auto-fixes."""

    def test_add_innerHTML_warning(self):
        """Should add warning for innerHTML usage."""
        fixer = UltraAdvancedSecurityFixer()
        code = "element.innerHTML = user_input"
        fixed, modified = fixer.fix_xss_vulnerabilities(code)
        assert modified
        assert "SECURITY" in fixed
        assert "XSS" in fixed

    def test_fix_jinja_autoescape(self):
        """Should add autoescape=True to Jinja2."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'env = Environment(loader=FileSystemLoader("templates"))'
        fixed, modified = fixer.fix_xss_vulnerabilities(code)
        assert modified
        assert "autoescape=True" in fixed
        assert "FIXED" in fixed or "ADDED" in fixed

    def test_safe_template_unchanged(self):
        """Should not modify templates with autoescape."""
        fixer = UltraAdvancedSecurityFixer()
        code = 'env = Environment(loader=FileSystemLoader("templates"), autoescape=True)'
        _fixed, modified = fixer.fix_xss_vulnerabilities(code)
        assert not modified


class TestIntegration:
    """Integration tests for ultra-advanced fixes."""

    def test_multiple_fixes_in_same_file(self):
        """Should apply multiple fixes to same file."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
# Multiple vulnerabilities
token = jwt.encode(payload, key="weak", algorithm="none")
hash = hashlib.md5(data).hexdigest()
query = f"SELECT * FROM users WHERE id = {user_id}"
"""
        content = code
        content, _ = fixer.fix_jwt_security(content)
        content, _ = fixer.fix_weak_cryptography(content)
        content, _ = fixer.fix_sql_injection_enhanced(content)

        assert "RS256" in content
        assert "sha256" in content
        assert "SECURITY" in content

    def test_fixer_tracks_applied_fixes(self):
        """Should track all fixes applied."""
        fixer = UltraAdvancedSecurityFixer()
        code = """
token = jwt.encode(payload, algorithm="none")
hash = hashlib.md5(data).hexdigest()
"""
        fixer.fix_jwt_security(code)
        fixer.fix_weak_cryptography(code)

        assert len(fixer.fixes_applied) >= 2
        assert any("JWT" in fix for fix in fixer.fixes_applied)
        assert any("MD5" in fix or "Crypto" in fix for fix in fixer.fixes_applied)
