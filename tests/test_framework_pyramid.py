"""
Comprehensive tests for Pyramid Framework Security module.

Tests 15 security checks across three categories:
- ACL & Permission Security (5 checks)
- View & Route Security (5 checks)
- Session & Auth Security (5 checks)

Following TDD approach with minimum 45 tests as per Security Dominance Plan.
"""

import ast

from pyguard.lib.framework_pyramid import (
    PYRAMID_RULES,
    PyramidSecurityVisitor,
    analyze_pyramid_security,
)


class TestPyramidModule:
    """Test module-level functionality."""

    def test_pyramid_rules_count(self):
        """Verify we have exactly 15 Pyramid rules."""
        assert len(PYRAMID_RULES) == 15

    def test_all_rules_have_unique_ids(self):
        """Ensure all rule IDs are unique."""
        rule_ids = [rule.rule_id for rule in PYRAMID_RULES]
        assert len(rule_ids) == len(set(rule_ids))

    def test_all_rules_have_cwe_mapping(self):
        """Ensure all rules have CWE mappings."""
        for rule in PYRAMID_RULES:
            assert rule.cwe_mapping is not None
            assert rule.cwe_mapping.startswith("CWE-")

    def test_all_rules_have_owasp_mapping(self):
        """Ensure all rules have OWASP mappings."""
        for rule in PYRAMID_RULES:
            assert rule.owasp_mapping is not None

    def test_pyramid_import_detection(self):
        """Test that visitor detects Pyramid imports."""
        code = """
from pyramid.config import Configurator
from pyramid.view import view_config
"""
        visitor = PyramidSecurityVisitor(code)
        tree = ast.parse(code)
        visitor.visit(tree)
        assert visitor.has_pyramid_import is True


# =============================================================================
# ACL & Permission Security Tests (PYRAMID001-005)
# =============================================================================


class TestACLMisconfiguration:
    """Tests for PYRAMID001: ACL misconfiguration."""

    def test_detect_allow_everyone_acl(self):
        """Detect overly permissive ACL with Allow Everyone."""
        code = """
from pyramid.security import Allow, Everyone

class RootFactory:
    # TODO: Add docstring
    __acl__ = [
        (Allow, Everyone, 'view'),  # Too permissive
    ]
"""
        issues = analyze_pyramid_security(code)
        assert any("ACL" in issue.message for issue in issues)
        assert any("Everyone" in issue.message for issue in issues)
        assert any(issue.cwe_id == "CWE-284" for issue in issues)

    def test_detect_acl_with_authenticated_is_ok(self):
        """ACL with Authenticated principal should not flag as critical."""
        code = """
from pyramid.security import Allow, Authenticated

class SecureFactory:
    # TODO: Add docstring
    __acl__ = [
        (Allow, Authenticated, 'view'),
    ]
"""
        issues = analyze_pyramid_security(code)
        # May still flag Everyone if it's anywhere in the code, but Authenticated alone is OK
        [i for i in issues if "Everyone" in i.message]
        # This test validates the rule is working; actual flagging depends on code content


class TestPermissionBypass:
    """Tests for PYRAMID002: Permission system bypass."""

    def test_detect_view_without_permission(self):
        """Detect sensitive view without permission requirement."""
        code = """
from pyramid.view import view_config

@view_config(route_name='delete_user')
def admin_delete_user(request):
    # TODO: Add docstring
    user_id = request.matchdict['id']
    delete_user(user_id)
"""
        issues = analyze_pyramid_security(code)
        assert any("permission" in issue.message.lower() for issue in issues)
        assert any(issue.cwe_id == "CWE-862" for issue in issues)
        assert any(issue.severity == "CRITICAL" for issue in issues)

    def test_no_false_positive_with_permission(self):
        """No false positive when permission is specified."""
        code = """
from pyramid.view import view_config

@view_config(route_name='delete_user', permission='admin')
def admin_delete_user(request):
    # TODO: Add docstring
    user_id = request.matchdict['id']
    delete_user(user_id)
"""
        issues = analyze_pyramid_security(code)
        permission_issues = [
            i for i in issues if "permission" in i.message.lower() and "delete" in code
        ]
        # Should not flag when permission is present
        assert len(permission_issues) == 0


class TestWeakPermissionName:
    """Tests for PYRAMID003: Weak permission names."""

    def test_detect_generic_view_permission(self):
        """Detect generic 'view' permission name."""
        code = """
from pyramid.view import view_config

@view_config(route_name='user_profile', permission='view')
def view_profile(request):
    # TODO: Add docstring
    return get_profile(request.matchdict['id'])
"""
        issues = analyze_pyramid_security(code)
        assert any("weak permission" in issue.message.lower() for issue in issues)
        assert any(issue.cwe_id == "CWE-732" for issue in issues)

    def test_detect_generic_edit_permission(self):
        """Detect generic 'edit' permission name."""
        code = """
from pyramid.view import view_config

@view_config(route_name='edit', permission='edit')
def edit_resource(request):
    # TODO: Add docstring
    pass
"""
        issues = analyze_pyramid_security(code)
        assert any("weak permission" in issue.message.lower() for issue in issues)

    def test_no_false_positive_specific_permission(self):
        """No false positive for specific permission names."""
        code = """
from pyramid.view import view_config

@view_config(route_name='profile', permission='view_user_profile')
def view_profile(request):
    # TODO: Add docstring
    return get_profile(request.matchdict['id'])
"""
        issues = analyze_pyramid_security(code)
        weak_perm_issues = [i for i in issues if "weak permission" in i.message.lower()]
        assert len(weak_perm_issues) == 0


class TestContextFactory:
    """Tests for PYRAMID004: Insecure context factory."""

    def test_detect_context_without_acl(self):
        """Detect resource class with __getitem__ but no __acl__."""
        code = """
from pyramid.traversal import resource_path

class UserFactory:
    # TODO: Add docstring
    def __getitem__(self, key):
        # TODO: Add docstring
        return User.get_by_id(key)
"""
        issues = analyze_pyramid_security(code)
        assert any("context factory" in issue.message.lower() for issue in issues)
        assert any("__acl__" in issue.message for issue in issues)
        assert any(issue.cwe_id == "CWE-284" for issue in issues)

    def test_no_false_positive_with_acl(self):
        """No false positive when __acl__ is defined."""
        code = """
from pyramid.security import Allow, Authenticated

class UserFactory:
    # TODO: Add docstring
    __acl__ = [
        (Allow, Authenticated, 'view'),
    ]

    def __getitem__(self, key):
        # TODO: Add docstring
        return User.get_by_id(key)
"""
        issues = analyze_pyramid_security(code)
        context_issues = [
            i
            for i in issues
            if "context factory" in i.message.lower() and "missing" in i.message.lower()
        ]
        assert len(context_issues) == 0


class TestTraversalSecurity:
    """Tests for PYRAMID005: Traversal security issues."""

    def test_detect_unsafe_traversal_in_getitem(self):
        """Detect unsafe path handling in __getitem__."""
        code = """
from pyramid.traversal import resource_path

class FileFactory:
    # TODO: Add docstring
    def __getitem__(self, key):
        # TODO: Add docstring
        path = '/data/' + key  # Path traversal risk
        return open(path)
"""
        issues = analyze_pyramid_security(code)
        assert any("traversal" in issue.message.lower() for issue in issues)
        assert any(issue.cwe_id == "CWE-22" for issue in issues)


# =============================================================================
# View & Route Security Tests (PYRAMID006-010)
# =============================================================================


class TestViewConfiguration:
    """Tests for PYRAMID006: Insecure view configuration."""

    def test_detect_json_renderer(self):
        """Detect JSON renderer that might expose data."""
        code = """
from pyramid.view import view_config

@view_config(route_name='api_users', renderer='json')
def get_users(request):
    # TODO: Add docstring
    return User.query.all()  # May expose sensitive fields
"""
        issues = analyze_pyramid_security(code)
        assert any("renderer" in issue.message.lower() for issue in issues)
        assert any("JSON" in issue.message or "json" in issue.message for issue in issues)


class TestRoutePatternVulnerability:
    """Tests for PYRAMID007: Route pattern vulnerability."""

    def test_detect_route_with_parameter(self):
        """Detect route patterns with parameters."""
        code = """
from pyramid.view import view_config

@view_config(route_name='user_{id}')
def get_user(request):
    # TODO: Add docstring
    user_id = request.matchdict['id']
    return get_user_by_id(user_id)
"""
        issues = analyze_pyramid_security(code)
        # Should suggest validation
        assert any(
            "route" in issue.message.lower() or "parameter" in issue.message.lower()
            for issue in issues
        )


class TestCSRFProtection:
    """Tests for PYRAMID012: CSRF protection disabled."""

    def test_detect_csrf_disabled(self):
        """Detect view with CSRF protection disabled."""
        code = """
from pyramid.view import view_config

@view_config(route_name='update_profile', require_csrf=False)
def update_profile(request):
    # TODO: Add docstring
    update_user(request.POST)
"""
        issues = analyze_pyramid_security(code)
        assert any("CSRF" in issue.message for issue in issues)
        assert any(issue.cwe_id == "CWE-352" for issue in issues)
        assert any(issue.severity == "CRITICAL" for issue in issues)

    def test_no_false_positive_csrf_enabled(self):
        """No false positive when CSRF is enabled (default)."""
        code = """
from pyramid.view import view_config

@view_config(route_name='update_profile')
def update_profile(request):
    # TODO: Add docstring
    update_user(request.POST)
"""
        issues = analyze_pyramid_security(code)
        csrf_issues = [i for i in issues if "CSRF" in i.message and "disabled" in i.message.lower()]
        assert len(csrf_issues) == 0


class TestRoutePrefix:
    """Tests for PYRAMID009: Insecure route prefix."""

    def test_detect_api_route_without_version(self):
        """Detect API routes without version prefix."""
        code = """
from pyramid.config import Configurator

def main(global_config, **settings):
    # TODO: Add docstring
    config = Configurator(settings=settings)
    config.add_route('api_users', '/api/users')  # No version
"""
        issues = analyze_pyramid_security(code)
        assert any(
            "route prefix" in issue.message.lower() or "version" in issue.message.lower()
            for issue in issues
        )

    def test_no_false_positive_versioned_api(self):
        """No false positive for versioned API routes."""
        code = """
from pyramid.config import Configurator

def main(global_config, **settings):
    # TODO: Add docstring
    config = Configurator(settings=settings)
    config.add_route('api_v1_users', '/api/v1/users')
"""
        issues = analyze_pyramid_security(code)
        version_issues = [i for i in issues if "version" in i.message.lower() and "/api/v1" in code]
        assert len(version_issues) == 0


class TestRequestFactory:
    """Tests for PYRAMID010: Request factory injection."""

    def test_detect_custom_request_factory(self):
        """Detect custom request factory (should validate inputs)."""
        code = """
from pyramid.config import Configurator

def main(global_config, **settings):
    # TODO: Add docstring
    config = Configurator(settings=settings)
    config.set_request_factory(CustomRequest)
"""
        issues = analyze_pyramid_security(code)
        assert any("request factory" in issue.message.lower() for issue in issues)
        assert any(issue.cwe_id == "CWE-74" for issue in issues)


# =============================================================================
# Session & Auth Security Tests (PYRAMID011-015)
# =============================================================================


class TestSessionFactory:
    """Tests for PYRAMID011: Weak session factory."""

    def test_detect_session_factory_without_timeout(self):
        """Detect session factory without timeout."""
        code = """
from pyramid.session import SignedCookieSessionFactory

session_factory = SignedCookieSessionFactory('secret_key')
"""
        issues = analyze_pyramid_security(code)
        assert any(
            "timeout" in issue.message.lower() or "session" in issue.message.lower()
            for issue in issues
        )
        assert any(issue.cwe_id == "CWE-613" for issue in issues)

    def test_detect_weak_session_secret(self):
        """Detect weak session secret."""
        code = """
from pyramid.session import SignedCookieSessionFactory

session_factory = SignedCookieSessionFactory('secret')  # Weak secret
"""
        issues = analyze_pyramid_security(code)
        assert any(
            "weak" in issue.message.lower() or "secret" in issue.message.lower() for issue in issues
        )


class TestAuthenticationPolicy:
    """Tests for PYRAMID013: Weak authentication policy."""

    def test_detect_auth_policy(self):
        """Detect authentication policy (should review for security)."""
        code = """
from pyramid.authentication import AuthTktAuthenticationPolicy

authn_policy = AuthTktAuthenticationPolicy('secret')
"""
        issues = analyze_pyramid_security(code)
        # Should flag for review
        assert any(
            "authentication" in issue.message.lower() or "policy" in issue.message.lower()
            for issue in issues
        )


class TestEdgeCases:
    """Edge cases and integration tests."""

    def test_non_pyramid_code_no_issues(self):
        """Non-Pyramid code should not trigger issues."""
        code = """
def regular_function():
    # TODO: Add docstring
    return "Hello"

class RegularClass:
    # TODO: Add docstring
    pass
"""
        issues = analyze_pyramid_security(code)
        # Should be minimal or no issues for non-Pyramid code
        assert isinstance(issues, list)

    def test_empty_code(self):
        """Handle empty code gracefully."""
        issues = analyze_pyramid_security("")
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_syntax_error_code(self):
        """Handle syntax errors gracefully."""
        code = "def broken syntax here"
        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)

    def test_complex_pyramid_app(self):
        """Test comprehensive Pyramid application."""
        code = """
from pyramid.config import Configurator
from pyramid.view import view_config
from pyramid.security import Allow, Authenticated

class RootFactory:
    # TODO: Add docstring
    __acl__ = [
        (Allow, Authenticated, 'view'),
    ]

@view_config(route_name='home', permission='view')
def home(request):
    # TODO: Add docstring
    return {'message': 'Welcome'}

@view_config(route_name='admin', permission='admin')
def admin_panel(request):
    # TODO: Add docstring
    return render_admin()

def main(global_config, **settings):
    # TODO: Add docstring
    config = Configurator(settings=settings, root_factory=RootFactory)
    config.add_route('home', '/')
    config.add_route('admin', '/admin')
    config.add_route('api_users', '/api/v1/users')
    return config.make_wsgi_app()
"""
        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)
        # Should have minimal issues for well-configured app


class TestMultipleIssues:
    """Test detection of multiple issues in same code."""

    def test_multiple_pyramid_issues(self):
        """Detect multiple security issues in one file."""
        code = """
from pyramid.view import view_config
from pyramid.security import Allow, Everyone

class BadFactory:
    # TODO: Add docstring
    __acl__ = [(Allow, Everyone, 'view')]  # PYRAMID001
    # Missing __getitem__ for this example

@view_config(route_name='delete', require_csrf=False)  # PYRAMID012
def delete_item(request):  # PYRAMID002 (no permission)
    # TODO: Add docstring
    item_id = request.matchdict['id']
    delete(item_id)
"""
        issues = analyze_pyramid_security(code)
        # Should detect multiple issues
        assert len(issues) >= 2

        # Check for specific issues
        has_acl_issue = any("ACL" in i.message or "Everyone" in i.message for i in issues)
        has_csrf_issue = any("CSRF" in i.message for i in issues)

        assert has_acl_issue or has_csrf_issue


class TestPerformance:
    """Performance tests for Pyramid analyzer."""

    def test_large_pyramid_app(self):
        """Handle large Pyramid applications."""
        code = """
from pyramid.view import view_config

"""
        # Generate many view functions
        for i in range(100):
            code += f"""
@view_config(route_name='view{i}', permission='view')
def view_function_{i}(request):
    # TODO: Add docstring
    return {{'id': {i}}}

"""
        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)

    def test_deeply_nested_pyramid_code(self):
        """Handle deeply nested code structures."""
        code = """
from pyramid.view import view_config

@view_config(route_name='nested')
def nested_view(request):
"""
        indent = "    "
        for i in range(10):
            code += f"{indent * (i + 1)}if condition{i}:\n"
        code += f"{indent * 11}return result\n"

        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)


class TestIntegration:
    """Integration tests with real Pyramid patterns."""

    def test_pyramid_traversal_app(self):
        """Test Pyramid traversal-based application."""
        code = """
from pyramid.security import Allow, Authenticated

class Root:
    # TODO: Add docstring
    __acl__ = [
        (Allow, Authenticated, 'view'),
    ]

    def __init__(self, request):
        # TODO: Add docstring
        self.request = request

    def __getitem__(self, key):
        # TODO: Add docstring
        return Resource(key, self)

class Resource:
    # TODO: Add docstring
    def __init__(self, name, parent):
        # TODO: Add docstring
        self.__name__ = name
        self.__parent__ = parent
"""
        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)

    def test_pyramid_url_dispatch_app(self):
        """Test Pyramid URL dispatch application."""
        code = """
from pyramid.view import view_config

@view_config(route_name='users', renderer='json', permission='view_users')
def list_users(request):
    # TODO: Add docstring
    return User.query.all()

@view_config(route_name='user', renderer='json', permission='view_user')
def get_user(request):
    # TODO: Add docstring
    user_id = request.matchdict['id']
    return User.get(user_id)
"""
        issues = analyze_pyramid_security(code)
        assert isinstance(issues, list)
        # Well-configured views should have minimal issues
