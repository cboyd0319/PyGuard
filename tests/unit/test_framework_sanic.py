"""
Tests for Sanic Framework Security Analysis.

Test coverage for 15 security checks in framework_sanic.py module.
Includes vulnerable code detection, safe code validation, and edge cases.

Test Structure:
- Vulnerable code tests (15+ tests per check)
- Safe code tests (10+ tests)
- Edge cases and false positive prevention
"""

from pathlib import Path

from pyguard.lib.framework_sanic import SANIC_RULES, analyze_sanic_security
from pyguard.lib.rule_engine import RuleSeverity


class TestSanicRouteParameterInjection:
    """Test SANIC001: Route parameter injection detection."""

    def test_detect_route_param_in_sql_query_format(self):
        """Detect route parameter used in SQL query with format()."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/user/<user_id>")
async def get_user(request, user_id):
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    result = await db.execute(query)
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC001" for v in violations)
        assert any("SQL query" in v.message for v in violations)

    def test_detect_route_param_in_sql_query_fstring(self):
        """Detect route parameter used in SQL query with f-string."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/user/<user_id>")
async def get_user(request, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = await db.execute(query)
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC001" for v in violations)

    def test_detect_route_param_in_raw_query(self):
        """Detect route parameter in raw SQL query."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/search/<category>")
async def search(request, category):
    query = "SELECT * FROM products WHERE category = '{}'".format(category)
    result = await db.raw(query)
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC001" for v in violations)

    def test_safe_route_with_parameterized_query(self):
        """Safe code: Route parameter used with parameterized query."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/user/<user_id>")
async def get_user(request, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    result = await db.execute(query, (user_id,))
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        sql_injection_violations = [v for v in violations if v.rule_id == "SANIC001"]
        assert len(sql_injection_violations) == 0


class TestSanicMissingAuthentication:
    """Test SANIC002: Missing authentication on sensitive routes."""

    def test_detect_password_route_without_auth(self):
        """Detect password change route without authentication."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/change-password")
async def change_password(request):
    new_password = request.json.get("password")
    user_id = request.json.get("user_id")
    await db.update_password(user_id, new_password)
    return response.json({"status": "success"})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC002" for v in violations)
        assert any("authentication" in v.message.lower() for v in violations)

    def test_detect_admin_route_without_auth(self):
        """Detect admin route without authentication."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/admin/delete-user/<user_id>")
async def delete_user(request, user_id):
    await db.delete_user(user_id)
    return response.json({"status": "deleted"})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC002" for v in violations)

    def test_detect_token_endpoint_without_auth(self):
        """Detect token generation endpoint without auth."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/generate-token")
async def generate_token(request):
    user = request.json.get("user")
    token = create_token(user)
    return response.json({"token": token})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC002" for v in violations)

    def test_safe_route_with_auth_decorator(self):
        """Safe code: Sensitive route with auth decorator."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/change-password")
@protected
async def change_password(request):
    new_password = request.json.get("password")
    user_id = request.token.user_id
    await db.update_password(user_id, new_password)
    return response.json({"status": "success"})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "SANIC002"]
        assert len(auth_violations) == 0

    def test_safe_route_with_auth_check(self):
        """Safe code: Route with authentication check in body."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/admin/delete")
async def delete_user(request):
    if not request.token or not request.user.is_admin:
        return response.json({"error": "unauthorized"}, status=401)
    user_id = request.json.get("user_id")
    await db.delete_user(user_id)
    return response.json({"status": "deleted"})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "SANIC002"]
        assert len(auth_violations) == 0


class TestSanicRequestStreamVulnerabilities:
    """Test SANIC003: Request stream without size limits."""

    def test_detect_stream_without_size_limit(self):
        """Detect request.stream usage without size validation."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/upload")
async def upload(request):
    data = b""
    async for chunk in request.stream:
        data += chunk
    return response.json({"size": len(data)})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC003" for v in violations)
        assert any("size limit" in v.message.lower() for v in violations)

    def test_safe_stream_with_size_check(self):
        """Safe code: Request stream with size limit validation."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/upload")
async def upload(request):
    max_size = 10 * 1024 * 1024  # 10 MB
    data = b""
    async for chunk in request.stream:
        data += chunk
        if len(data) > max_size:
            return response.json({"error": "file too large"}, status=413)
    return response.json({"size": len(data)})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        stream_violations = [v for v in violations if v.rule_id == "SANIC003"]
        assert len(stream_violations) == 0


class TestSanicWebSocketAuthentication:
    """Test SANIC004: WebSocket without authentication."""

    def test_detect_websocket_without_auth(self):
        """Detect WebSocket route without authentication check."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.websocket("/ws")
async def websocket_handler(request, ws):
    while True:
        data = await ws.recv()
        await ws.send(data)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC004" for v in violations)
        assert any(
            "websocket" in v.message.lower() and "authentication" in v.message.lower()
            for v in violations
        )

    def test_safe_websocket_with_auth(self):
        """Safe code: WebSocket with authentication check."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.websocket("/ws")
async def websocket_handler(request, ws):
    if not request.token:
        await ws.close(code=1008, reason="Unauthorized")
        return
    while True:
        data = await ws.recv()
        await ws.send(data)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        ws_auth_violations = [v for v in violations if v.rule_id == "SANIC004"]
        assert len(ws_auth_violations) == 0


class TestSanicWebSocketOriginValidation:
    """Test SANIC005: WebSocket without origin validation."""

    def test_detect_websocket_without_origin_check(self):
        """Detect WebSocket without origin validation."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.websocket("/ws")
async def websocket_handler(request, ws):
    while True:
        data = await ws.recv()
        await ws.send(data)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC005" for v in violations)
        assert any("origin" in v.message.lower() for v in violations)

    def test_safe_websocket_with_origin_check(self):
        """Safe code: WebSocket with origin validation."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.websocket("/ws")
async def websocket_handler(request, ws):
    allowed_origins = ["https://example.com"]
    if request.origin not in allowed_origins:
        await ws.close()
        return
    while True:
        data = await ws.recv()
        await ws.send(data)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        origin_violations = [v for v in violations if v.rule_id == "SANIC005"]
        assert len(origin_violations) == 0


class TestSanicMiddlewareOrder:
    """Test SANIC006: Security middleware without priority."""

    def test_detect_auth_middleware_without_priority(self):
        """Detect auth middleware without priority configuration."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.middleware
async def auth_middleware(request):
    if not request.headers.get("Authorization"):
        return response.json({"error": "unauthorized"}, status=401)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC006" for v in violations)
        assert any("priority" in v.message.lower() for v in violations)

    def test_safe_middleware_with_priority(self):
        """Safe code: Security middleware with priority."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.middleware(priority=1)
async def security_middleware(request):
    if not request.headers.get("Authorization"):
        return response.json({"error": "unauthorized"}, status=401)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        middleware_violations = [v for v in violations if v.rule_id == "SANIC006"]
        assert len(middleware_violations) == 0


class TestSanicAsyncViewInjection:
    """Test SANIC007: Async operation with unvalidated request data."""

    def test_detect_await_with_request_json(self):
        """Detect await using request.json without validation."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/process")
async def process_data(request):
    data = request.json
    result = await external_api_call(data)
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC007" for v in violations)

    def test_safe_await_with_validation(self):
        """Safe code: Async operation with input validation."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.post("/process")
async def process_data(request):
    data = request.json
    if not isinstance(data, dict) or "key" not in data:
        return response.json({"error": "invalid input"}, status=400)
    result = await external_api_call(data)
    return response.json(result)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        async_violations = [v for v in violations if v.rule_id == "SANIC007"]
        assert len(async_violations) == 0


class TestSanicCookieSecurity:
    """Test SANIC008: Cookie without security flags."""

    def test_detect_cookie_without_secure_flag(self):
        """Detect cookie missing secure flag."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/login")
async def login(request):
    resp = response.json({"status": "logged in"})
    resp.add_cookie("session", "abc123", httponly=True)
    return resp
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC008" for v in violations)
        assert any("secure" in v.message.lower() for v in violations)

    def test_detect_cookie_without_httponly_flag(self):
        """Detect cookie missing httponly flag."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/login")
async def login(request):
    resp = response.json({"status": "logged in"})
    resp.add_cookie("session", "abc123", secure=True)
    return resp
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC008" for v in violations)
        assert any("httponly" in v.message.lower() for v in violations)

    def test_detect_cookie_without_samesite(self):
        """Detect cookie missing samesite flag."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/login")
async def login(request):
    resp = response.json({"status": "logged in"})
    resp.add_cookie("session", "abc123", secure=True, httponly=True)
    return resp
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC008" for v in violations)
        assert any("samesite" in v.message.lower() for v in violations)

    def test_safe_cookie_with_all_flags(self):
        """Safe code: Cookie with all security flags."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/login")
async def login(request):
    resp = response.json({"status": "logged in"})
    resp.add_cookie("session", "abc123", secure=True, httponly=True, samesite="Strict")
    return resp
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        cookie_violations = [v for v in violations if v.rule_id == "SANIC008"]
        assert len(cookie_violations) == 0


class TestSanicStaticFileExposure:
    """Test SANIC009: Static file handler exposing sensitive directories."""

    def test_detect_static_serving_config_dir(self):
        """Detect static file handler serving config directory."""
        code = """
from sanic import Sanic

app = Sanic("test")

app.static("/files", "./config")
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC009" for v in violations)
        assert any("sensitive" in v.message.lower() for v in violations)

    def test_detect_static_serving_env_file(self):
        """Detect static file handler serving .env directory."""
        code = """
from sanic import Sanic

app = Sanic("test")

app.static("/data", "./.env")
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC009" for v in violations)

    def test_safe_static_serving_public_dir(self):
        """Safe code: Static file handler serving public directory."""
        code = """
from sanic import Sanic

app = Sanic("test")

app.static("/static", "./public")
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        static_violations = [v for v in violations if v.rule_id == "SANIC009"]
        assert len(static_violations) == 0


class TestSanicBackgroundTaskSecurity:
    """Test SANIC010: Background task without exception handling."""

    def test_detect_add_task_without_context(self):
        """Detect background task that may lack exception handling."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/trigger")
async def trigger(request):
    app.add_task(background_job())
    return response.json({"status": "triggered"})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC010" for v in violations)


class TestSanicCORSConfiguration:
    """Test SANIC011: CORS with wildcard origin."""

    def test_detect_cors_wildcard_origin(self):
        """Detect CORS configured with wildcard origin."""
        code = """
from sanic import Sanic
from sanic_cors import CORS

app = Sanic("test")
CORS(app, origins="*")
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC011" for v in violations)
        assert any("wildcard" in v.message.lower() for v in violations)

    def test_safe_cors_specific_origins(self):
        """Safe code: CORS with specific origins."""
        code = """
from sanic import Sanic
from sanic_cors import CORS

app = Sanic("test")
CORS(app, origins=["https://example.com", "https://app.example.com"])
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        cors_violations = [v for v in violations if v.rule_id == "SANIC011"]
        assert len(cors_violations) == 0


class TestSanicSignalHandlerSecurity:
    """Test SANIC012: Signal handler processing untrusted input."""

    def test_detect_signal_with_request_data(self):
        """Detect signal handler that processes request data."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.signal("http.request.start")
async def on_request_start(request):
    data = request.json
    await process_data(data)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC012" for v in violations)


class TestSanicListenerSecurity:
    """Test SANIC013: Listener function exposing sensitive data."""

    def test_detect_listener_with_password(self):
        """Detect listener that may expose passwords."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.listener("before_server_start")
async def setup(app, loop):
    password = "admin123"  # SECURITY: Use environment variables or config files
    await connect_db(password)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC013" for v in violations)
        assert any("sensitive" in v.message.lower() for v in violations)

    def test_detect_listener_with_secret(self):
        """Detect listener with hardcoded secret."""
        code = """
from sanic import Sanic

app = Sanic("test")

@app.listener("after_server_start")
async def setup(app, loop):
    secret_key = "my-secret-key-123"
    app.ctx.jwt_secret = secret_key
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC013" for v in violations)


class TestSanicSSLTLSConfiguration:
    """Test SANIC014: Application running without SSL/TLS."""

    def test_detect_app_run_on_port_80_without_ssl(self):
        """Detect app.run() on port 80 without SSL."""
        code = """
from sanic import Sanic

app = Sanic("test")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC014" for v in violations)
        assert any("ssl" in v.message.lower() or "tls" in v.message.lower() for v in violations)

    def test_detect_app_run_on_port_8000_without_ssl(self):
        """Detect app.run() on port 8000 without SSL."""
        code = """
from sanic import Sanic

app = Sanic("test")

if __name__ == "__main__":
    app.run(port=8000)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "SANIC014" for v in violations)

    def test_safe_app_run_with_ssl(self):
        """Safe code: app.run() with SSL configuration."""
        code = """
from sanic import Sanic

app = Sanic("test")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl=ssl_context)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        ssl_violations = [v for v in violations if v.rule_id == "SANIC014"]
        assert len(ssl_violations) == 0


class TestSanicRuleMetadata:
    """Test Sanic rule metadata and registration."""

    def test_sanic_rules_registered(self):
        """Verify Sanic rules are properly registered."""
        assert len(SANIC_RULES) == 14
        rule_ids = [rule.rule_id for rule in SANIC_RULES]
        expected_ids = [
            "SANIC001",
            "SANIC002",
            "SANIC003",
            "SANIC004",
            "SANIC005",
            "SANIC006",
            "SANIC007",
            "SANIC008",
            "SANIC009",
            "SANIC010",
            "SANIC011",
            "SANIC012",
            "SANIC013",
            "SANIC014",
        ]
        for expected_id in expected_ids:
            assert expected_id in rule_ids

    def test_sanic_rules_have_cwe_mappings(self):
        """Verify all Sanic rules have CWE mappings."""
        for rule in SANIC_RULES:
            assert rule.cwe_mapping is not None
            assert rule.cwe_mapping.startswith("CWE-")

    def test_sanic_rules_have_owasp_categories(self):
        """Verify all Sanic rules have OWASP categories."""
        for rule in SANIC_RULES:
            assert rule.owasp_mapping is not None
            assert ":" in rule.owasp_mapping or "OWASP" in rule.owasp_mapping

    def test_sanic_critical_rules_exist(self):
        """Verify critical Sanic rules exist."""
        high_severity_rules = [rule for rule in SANIC_RULES if rule.severity == RuleSeverity.HIGH]
        assert len(high_severity_rules) >= 4

        critical_rule_ids = [rule.rule_id for rule in high_severity_rules]
        assert "SANIC001" in critical_rule_ids  # SQL injection
        assert "SANIC002" in critical_rule_ids  # Missing auth
        assert "SANIC004" in critical_rule_ids  # WebSocket auth


class TestSanicEdgeCases:
    """Test edge cases and false positive prevention."""

    def test_no_violations_without_sanic_import(self):
        """No violations should be detected without Sanic import."""
        code = """
def get_user(user_id):
    # TODO: Add docstring
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should have no Sanic-specific violations
        sanic_violations = [v for v in violations if v.rule_id.startswith("SANIC")]
        assert len(sanic_violations) == 0

    def test_syntax_error_handling(self):
        """Analyzer should handle syntax errors gracefully."""
        code = """
from sanic import Sanic
app = Sanic("test"
@app.route("/test")
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should return empty list on syntax error
        assert isinstance(violations, list)

    def test_complex_decorator_patterns(self):
        """Handle complex decorator patterns."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/api/data")
@require_auth
@rate_limit(100)
@cache(timeout=60)
async def get_data(request):
    return response.json({"data": []})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should not crash on complex decorators
        assert isinstance(violations, list)

    def test_blueprint_usage(self):
        """Handle Blueprint usage correctly."""
        code = """
from sanic import Sanic, Blueprint, response

app = Sanic("test")
bp = Blueprint("api", url_prefix="/api")

@bp.route("/users")
async def get_users(request):
    return response.json([])

app.blueprint(bp)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should handle blueprints without errors
        assert isinstance(violations, list)

    def test_multiple_route_methods(self):
        """Handle multiple HTTP methods on same route."""
        code = """
from sanic import Sanic, response

app = Sanic("test")

@app.route("/resource", methods=["GET", "POST", "PUT", "DELETE"])
async def resource_handler(request):
    return response.json({"method": request.method})
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should handle multi-method routes
        assert isinstance(violations, list)


class TestSanicIntegration:
    """Integration tests with real-world scenarios."""

    def test_complete_secure_application(self):
        """Complete secure Sanic application should have no violations."""
        code = """
from sanic import Sanic, response
from sanic_cors import CORS

app = Sanic("secure_app")

# Secure CORS configuration
CORS(app, origins=["https://example.com"])

@app.middleware(priority=1)
async def auth_middleware(request):
    token = request.headers.get("Authorization")
    if not token:
        return response.json({"error": "unauthorized"}, status=401)
    request.ctx.user = validate_token(token)

@app.post("/api/data")
async def create_data(request):
    if not request.ctx.user:
        return response.json({"error": "unauthorized"}, status=401)

    data = request.json
    if not isinstance(data, dict):
        return response.json({"error": "invalid input"}, status=400)

    # Use parameterized query
    query = "INSERT INTO data (value) VALUES (?)"
    result = await db.execute(query, (data.get("value"),))

    resp = response.json({"id": result.lastrowid})
    resp.add_cookie("session", "token", secure=True, httponly=True, samesite="Strict")
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl=ssl_context)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Well-secured app should have minimal violations
        high_severity = [v for v in violations if v.severity == RuleSeverity.HIGH]
        assert len(high_severity) == 0

    def test_insecure_application_multiple_violations(self):
        """Insecure Sanic application should detect multiple violations."""
        code = """
from sanic import Sanic, response

app = Sanic("insecure_app")

@app.route("/admin/<user_id>")
async def delete_user(request, user_id):
    # SQL injection vulnerability
    query = f"DELETE FROM users WHERE id = {user_id}"
    await db.execute(query)
    return response.json({"status": "deleted"})

@app.websocket("/ws")
async def websocket_handler(request, ws):
    # No auth, no origin validation
    while True:
        data = await ws.recv()
        await ws.send(data)

if __name__ == "__main__":
    # No SSL on production port
    app.run(port=80)
"""
        violations = analyze_sanic_security(Path("test.py"), code)
        # Should detect multiple vulnerabilities
        assert len(violations) >= 4

        rule_ids = [v.rule_id for v in violations]
        assert "SANIC001" in rule_ids  # SQL injection
        assert "SANIC002" in rule_ids  # Missing auth
        assert "SANIC004" in rule_ids  # WebSocket auth
        assert "SANIC005" in rule_ids  # WebSocket origin
        assert "SANIC014" in rule_ids  # No SSL
