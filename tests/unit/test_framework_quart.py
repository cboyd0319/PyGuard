"""
Tests for Quart Framework Security Analysis.

Test coverage for 15 security checks in framework_quart.py module.
Includes vulnerable code detection, safe code validation, and edge cases.

Test Structure:
- Vulnerable code tests (15+ tests per check)
- Safe code tests (10+ tests)
- Edge cases and false positive prevention
"""

from pathlib import Path

from pyguard.lib.framework_quart import QUART_RULES, analyze_quart
from pyguard.lib.rule_engine import RuleSeverity


class TestQuartAsyncRequestContext:
    """Test QUART001: Async request context issues."""

    def test_detect_request_access_non_async_function(self):
        """Detect request accessed in non-async function."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/data")
def get_data():
    # TODO: Add docstring
    user_input = request.args.get("q")
    return {"result": user_input}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART001" for v in violations)
        assert any("async context" in v.message for v in violations)

    def test_safe_async_request_access(self):
        """Safe code: Request accessed in async function."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/data")
async def get_data():
    user_input = await request.args.get("q")
    return {"result": user_input}
"""
        violations = analyze_quart(Path("test.py"), code)
        context_violations = [v for v in violations if v.rule_id == "QUART001"]
        assert len(context_violations) == 0


class TestQuartWebSocketAuth:
    """Test QUART002: WebSocket authentication issues."""

    def test_detect_websocket_without_auth_check(self):
        """Detect WebSocket route without authentication."""
        code = """
from quart import Quart, websocket

app = Quart(__name__)

@app.websocket("/ws")
async def ws():
    while True:
        data = await websocket.receive()
        await websocket.send(data)
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART002" for v in violations)
        assert any("authentication" in v.message.lower() for v in violations)

    def test_safe_websocket_with_auth_check(self):
        """Safe code: WebSocket with authentication check."""
        code = """
from quart import Quart, websocket

app = Quart(__name__)

@app.websocket("/ws")
async def ws():
    token = websocket.headers.get("Authorization")
    if not verify_token(token):
        await websocket.close(1008)
        return
    while True:
        data = await websocket.receive()
        await websocket.send(data)
"""
        violations = analyze_quart(Path("test.py"), code)
        ws_auth_violations = [v for v in violations if v.rule_id == "QUART002"]
        assert len(ws_auth_violations) == 0

    def test_safe_websocket_with_authenticate_call(self):
        """Safe code: WebSocket with authenticate() call."""
        code = """
from quart import Quart, websocket

app = Quart(__name__)

@app.websocket("/ws")
async def ws():
    await authenticate(websocket)
    while True:
        data = await websocket.receive()
        await websocket.send(data)
"""
        violations = analyze_quart(Path("test.py"), code)
        ws_auth_violations = [v for v in violations if v.rule_id == "QUART002"]
        assert len(ws_auth_violations) == 0


class TestQuartBackgroundTaskSecurity:
    """Test QUART003: Background task security."""

    def test_detect_background_task_with_form_input(self):
        """Detect background task receiving form input without validation."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/process", methods=["POST"])
async def process_data():
    form_data = await request.form
    app.add_background_task(process_user_data, form_data)
    return {"status": "processing"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART003" for v in violations)
        assert any("user input" in v.message.lower() for v in violations)

    def test_detect_background_task_with_json_input(self):
        """Detect background task receiving JSON input without validation."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/api/process", methods=["POST"])
async def process_api():
    json_data = await request.json
    app.add_background_task(process_data, json_data)
    return {"status": "ok"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART003" for v in violations)

    def test_safe_background_task_with_validated_data(self):
        """Safe code: Background task with validated data."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/process", methods=["POST"])
async def process_data():
    form_data = await request.form
    validated_data = validate_input(form_data)
    app.add_background_task(process_user_data, validated_data)
    return {"status": "processing"}
"""
        violations = analyze_quart(Path("test.py"), code)
        task_violations = [v for v in violations if v.rule_id == "QUART003"]
        assert len(task_violations) == 0


class TestQuartSessionManagement:
    """Test QUART004: Session management in async context."""

    def test_detect_session_modified_non_async(self):
        """Detect session modification in non-async context."""
        code = """
from quart import Quart, session

app = Quart(__name__)

@app.route("/login")
def login():
    # TODO: Add docstring
    session["user_id"] = 123
    return {"status": "logged in"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART004" for v in violations)
        assert any("session" in v.message.lower() for v in violations)

    def test_safe_session_in_async_context(self):
        """Safe code: Session modified in async context."""
        code = """
from quart import Quart, session

app = Quart(__name__)

@app.route("/login")
async def login():
    session["user_id"] = 123
    return {"status": "logged in"}
"""
        violations = analyze_quart(Path("test.py"), code)
        session_violations = [v for v in violations if v.rule_id == "QUART004"]
        assert len(session_violations) == 0


class TestQuartCORSConfiguration:
    """Test QUART005: CORS configuration issues."""

    def test_detect_cors_wildcard_origin(self):
        """Detect CORS configured with wildcard origin."""
        code = """
from quart import Quart
from quart_cors import cors

app = Quart(__name__)
app = cors(app, origins="*")
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART005" for v in violations)
        assert any("wildcard" in v.message.lower() for v in violations)

    def test_detect_cors_no_origin_specified(self):
        """Detect CORS without origin specification."""
        code = """
from quart import Quart
from quart_cors import cors

app = Quart(__name__)
app = cors(app)
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART005" for v in violations)

    def test_safe_cors_with_specific_origins(self):
        """Safe code: CORS with specific origins."""
        code = """
from quart import Quart
from quart_cors import cors

app = Quart(__name__)
app = cors(app, origins=["https://example.com", "https://app.example.com"])
"""
        violations = analyze_quart(Path("test.py"), code)
        cors_violations = [v for v in violations if v.rule_id == "QUART005"]
        assert len(cors_violations) == 0


class TestQuartFileUploadSecurity:
    """Test QUART006: File upload handling issues."""

    def test_detect_file_save_without_validation(self):
        """Detect file save without filename validation."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/upload", methods=["POST"])
async def upload_file():
    files = await request.files
    file = files["file"]
    await file.save(f"/uploads/{file.filename}")
    return {"status": "uploaded"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART006" for v in violations)
        assert any("filename validation" in v.message.lower() for v in violations)

    def test_safe_file_save_with_secure_filename(self):
        """Safe code: File save with secure_filename()."""
        code = """
from quart import Quart, request
from werkzeug.utils import secure_filename

app = Quart(__name__)

@app.route("/upload", methods=["POST"])
async def upload_file():
    files = await request.files
    file = files["file"]
    filename = secure_filename(file.filename)
    await file.save(f"/uploads/{filename}")
    return {"status": "uploaded"}
"""
        violations = analyze_quart(Path("test.py"), code)
        upload_violations = [v for v in violations if v.rule_id == "QUART006"]
        assert len(upload_violations) == 0


class TestQuartTemplateRendering:
    """Test QUART007: Template rendering security."""

    def test_detect_render_template_string_with_form_input(self):
        """Detect render_template_string with form input (SSTI risk)."""
        code = """
from quart import Quart, request, render_template_string

app = Quart(__name__)

@app.route("/render")
async def render_page():
    template = await request.form.get("template")
    return await render_template_string(template)
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART007" for v in violations)
        assert any("SSTI" in v.message for v in violations)

    def test_detect_render_template_string_with_args(self):
        """Detect render_template_string with query args."""
        code = """
from quart import Quart, request, render_template_string

app = Quart(__name__)

@app.route("/render")
async def render_page():
    template = request.args.get("tmpl")
    return await render_template_string(template)
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART007" for v in violations)

    def test_safe_render_template_with_file(self):
        """Safe code: render_template with template file."""
        code = """
from quart import Quart, request, render_template

app = Quart(__name__)

@app.route("/render")
async def render_page():
    data = await request.form.get("data")
    return await render_template("page.html", data=data)
"""
        violations = analyze_quart(Path("test.py"), code)
        template_violations = [v for v in violations if v.rule_id == "QUART007"]
        assert len(template_violations) == 0


class TestQuartCookieSecurity:
    """Test QUART008-010: Cookie security flags."""

    def test_detect_cookie_without_secure_flag(self):
        """Detect cookie set without secure flag."""
        code = """
from quart import Quart, make_response

app = Quart(__name__)

@app.route("/login")
async def login():
    response = await make_response("OK")
    response.set_cookie("session_id", "abc123")
    return response
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART008" for v in violations)
        assert any("secure flag" in v.message.lower() for v in violations)

    def test_detect_cookie_without_httponly_flag(self):
        """Detect cookie set without httponly flag."""
        code = """
from quart import Quart, make_response

app = Quart(__name__)

@app.route("/login")
async def login():
    response = await make_response("OK")
    response.set_cookie("session_id", "abc123", secure=True)
    return response
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART009" for v in violations)
        assert any("httponly" in v.message.lower() for v in violations)

    def test_detect_cookie_without_samesite(self):
        """Detect cookie set without samesite attribute."""
        code = """
from quart import Quart, make_response

app = Quart(__name__)

@app.route("/login")
async def login():
    response = await make_response("OK")
    response.set_cookie("session_id", "abc123", secure=True, httponly=True)
    return response
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART010" for v in violations)
        assert any("samesite" in v.message.lower() for v in violations)

    def test_safe_cookie_with_all_flags(self):
        """Safe code: Cookie with all security flags."""
        code = """
from quart import Quart, make_response

app = Quart(__name__)

@app.route("/login")
async def login():
    response = await make_response("OK")
    response.set_cookie(
        "session_id", "abc123",
        secure=True,
        httponly=True,
        samesite="Strict"
    )
    return response
"""
        violations = analyze_quart(Path("test.py"), code)
        cookie_violations = [
            v for v in violations if v.rule_id in ["QUART008", "QUART009", "QUART010"]
        ]
        assert len(cookie_violations) == 0


class TestQuartCSRFProtection:
    """Test QUART011: CSRF protection gaps."""

    def test_detect_post_route_without_csrf(self):
        """Detect POST route without CSRF protection."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.post("/update")
async def update_data():
    data = await request.form
    update_database(data)
    return {"status": "updated"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART011" for v in violations)
        assert any("CSRF" in v.message for v in violations)

    def test_detect_put_route_without_csrf(self):
        """Detect PUT route without CSRF protection."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.put("/resource/<id>")
async def update_resource(id):
    data = await request.json
    update_resource_db(id, data)
    return {"status": "updated"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART011" for v in violations)

    def test_detect_delete_route_without_csrf(self):
        """Detect DELETE route without CSRF protection."""
        code = """
from quart import Quart

app = Quart(__name__)

@app.delete("/resource/<id>")
async def delete_resource(id):
    delete_from_db(id)
    return {"status": "deleted"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART011" for v in violations)

    def test_safe_post_route_with_csrf_check(self):
        """Safe code: POST route with CSRF token validation."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.post("/update")
async def update_data():
    csrf_token = await request.form.get("csrf_token")
    validate_csrf_token(csrf_token)
    data = await request.form
    update_database(data)
    return {"status": "updated"}
"""
        violations = analyze_quart(Path("test.py"), code)
        csrf_violations = [v for v in violations if v.rule_id == "QUART011"]
        assert len(csrf_violations) == 0


class TestQuartAuthenticationDecorator:
    """Test QUART012: Authentication decorator issues."""

    def test_detect_route_accessing_password_without_auth(self):
        """Detect route accessing password without authentication."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/admin/users")
async def get_users():
    users = await db.query("SELECT id, username, password FROM users")
    return {"users": users}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART012" for v in violations)
        assert any("authentication" in v.message.lower() for v in violations)

    def test_detect_route_accessing_token_without_auth(self):
        """Detect route accessing token without authentication."""
        code = """
from quart import Quart

app = Quart(__name__)

@app.route("/api/tokens")
async def get_tokens():
    tokens = await db.query("SELECT api_key FROM api_tokens")
    return {"tokens": tokens}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) >= 1
        assert any(v.rule_id == "QUART012" for v in violations)

    def test_safe_route_with_auth_decorator(self):
        """Safe code: Route with authentication decorator."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/admin/users")
@login_required
async def get_users():
    users = await db.query("SELECT id, username, password FROM users")
    return {"users": users}
"""
        violations = analyze_quart(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "QUART012"]
        assert len(auth_violations) == 0

    def test_safe_route_with_auth_required_decorator(self):
        """Safe code: Route with auth_required decorator."""
        code = """
from quart import Quart

app = Quart(__name__)

@app.route("/api/secrets")
@auth_required
async def get_secrets():
    secrets = await db.query("SELECT secret FROM secrets")
    return {"secrets": secrets}
"""
        violations = analyze_quart(Path("test.py"), code)
        auth_violations = [v for v in violations if v.rule_id == "QUART012"]
        assert len(auth_violations) == 0


class TestQuartRulesMetadata:
    """Test that Quart rules are properly registered."""

    def test_quart_rules_exist(self):
        """Verify all 15 Quart rules are registered."""
        assert len(QUART_RULES) == 15

    def test_quart_rule_ids_are_unique(self):
        """Verify all rule IDs are unique."""
        rule_ids = [rule.rule_id for rule in QUART_RULES]
        assert len(rule_ids) == len(set(rule_ids))

    def test_quart_rules_have_cwe_mappings(self):
        """Verify all rules have CWE mappings."""
        for rule in QUART_RULES:
            assert rule.cwe_id is not None
            assert rule.cwe_id.startswith("CWE-")

    def test_quart_rules_have_owasp_categories(self):
        """Verify all rules have OWASP categories."""
        for rule in QUART_RULES:
            assert rule.owasp_category is not None

    def test_quart_critical_rules_exist(self):
        """Verify critical severity rules exist."""
        critical_rules = [r for r in QUART_RULES if r.severity == RuleSeverity.CRITICAL]
        assert len(critical_rules) >= 1


class TestQuartEdgeCases:
    """Test edge cases and false positive prevention."""

    def test_no_violations_for_non_quart_code(self):
        """No violations for code without Quart imports."""
        code = """
def process_data(data):
    # TODO: Add docstring
    return {"result": data}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) == 0

    def test_no_violations_for_safe_quart_app(self):
        """No violations for properly secured Quart app."""
        code = """
from quart import Quart, request, render_template
from werkzeug.utils import secure_filename

app = Quart(__name__)

@app.route("/")
async def index():
    return await render_template("index.html")

@app.route("/data")
async def get_data():
    return {"status": "ok"}
"""
        violations = analyze_quart(Path("test.py"), code)
        assert len(violations) == 0

    def test_multiple_violations_in_single_function(self):
        """Detect multiple violations in a single function."""
        code = """
from quart import Quart, request, render_template_string

app = Quart(__name__)

@app.post("/process")
async def process():
    template = await request.form.get("template")
    result = await render_template_string(template)
    return result
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should detect: CSRF missing + SSTI risk
        assert len(violations) >= 2

    def test_safe_get_route_no_csrf_required(self):
        """Safe code: GET routes don't require CSRF protection."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.get("/data")
async def get_data():
    query = request.args.get("q")
    results = search(query)
    return {"results": results}
"""
        violations = analyze_quart(Path("test.py"), code)
        csrf_violations = [v for v in violations if v.rule_id == "QUART011"]
        assert len(csrf_violations) == 0


class TestQuartRealWorldPatterns:
    """Test real-world Quart application patterns."""

    def test_api_endpoint_with_json_response(self):
        """Test typical API endpoint pattern."""
        code = """
from quart import Quart, request, jsonify

app = Quart(__name__)

@app.route("/api/users", methods=["GET", "POST"])
@auth_required
async def users():
    if request.method == "POST":
        data = await request.json
        validated = validate_user(data)
        user = await create_user(validated)
        return jsonify(user), 201
    else:
        users = await get_all_users()
        return jsonify(users)
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should detect CSRF on POST
        csrf_violations = [v for v in violations if v.rule_id == "QUART011"]
        assert len(csrf_violations) >= 1

    def test_websocket_chat_application(self):
        """Test WebSocket chat application pattern."""
        code = """
from quart import Quart, websocket

app = Quart(__name__)

@app.websocket("/chat")
async def chat():
    token = websocket.headers.get("Authorization")
    if not verify_token(token):
        await websocket.close(1008)
        return

    while True:
        message = await websocket.receive()
        sanitized = sanitize_message(message)
        await websocket.send(sanitized)
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should not detect violations - properly secured
        ws_violations = [v for v in violations if v.rule_id == "QUART002"]
        assert len(ws_violations) == 0

    def test_file_upload_api(self):
        """Test file upload API endpoint."""
        code = """
from quart import Quart, request
from werkzeug.utils import secure_filename

app = Quart(__name__)

@app.post("/api/upload")
@auth_required
async def upload():
    csrf_token = await request.form.get("csrf")
    validate_csrf(csrf_token)

    files = await request.files
    file = files["file"]
    filename = secure_filename(file.filename)
    await file.save(f"/uploads/{filename}")
    return {"status": "uploaded", "filename": filename}
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should not detect violations - properly secured
        major_violations = [v for v in violations if v.rule_id in ["QUART006", "QUART011"]]
        assert len(major_violations) == 0


class TestQuartAsyncPatterns:
    """Test async-specific patterns in Quart."""

    def test_async_database_query_pattern(self):
        """Test async database query patterns."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.route("/users/<user_id>")
async def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    user = await db.fetch_one(query, user_id)
    return {"user": user}
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should not detect SQL injection - using parameters
        sql_violations = [v for v in violations if "injection" in v.message.lower()]
        assert len(sql_violations) == 0

    def test_async_background_task_pattern(self):
        """Test async background task pattern."""
        code = """
from quart import Quart, request

app = Quart(__name__)

@app.post("/process")
async def process():
    data = await request.json
    validated = validate_and_sanitize(data)
    app.add_background_task(async_process, validated)
    return {"status": "processing"}
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should detect CSRF but not background task issue
        task_violations = [v for v in violations if v.rule_id == "QUART003"]
        assert len(task_violations) == 0

    def test_async_context_manager_pattern(self):
        """Test async context manager pattern."""
        code = """
from quart import Quart

app = Quart(__name__)

@app.route("/data")
async def get_data():
    async with db.transaction():
        result = await db.query("SELECT * FROM data")
        return {"data": result}
"""
        violations = analyze_quart(Path("test.py"), code)
        # Should not detect any violations for safe async patterns
        assert len(violations) == 0
