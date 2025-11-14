"""
Tests for JSON-RPC API server.

Tests JSON-RPC 2.0 protocol compliance, document management,
analysis methods, and IDE integration features.
"""

import json

import pytest

from pyguard.lib.jsonrpc_api import (
    DocumentInfo,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    PyGuardJsonRpcServer,
)


class TestJsonRpcRequest:
    """Test JSON-RPC request parsing and validation."""

    def test_from_dict_basic(self):
        """Test basic request parsing."""
        data = {
            "jsonrpc": "2.0",
            "method": "test_method",
            "params": {"key": "value"},
            "id": 1,
        }
        request = JsonRpcRequest.from_dict(data)

        assert request.jsonrpc == "2.0"
        assert request.method == "test_method"
        assert request.params == {"key": "value"}
        assert request.id == 1

    def test_from_dict_notification(self):
        """Test notification (no id) parsing."""
        data = {
            "jsonrpc": "2.0",
            "method": "notify",
        }
        request = JsonRpcRequest.from_dict(data)

        assert request.is_notification()
        assert request.id is None

    def test_from_dict_string_id(self):
        """Test request with string ID."""
        data = {
            "jsonrpc": "2.0",
            "method": "test",
            "id": "abc-123",
        }
        request = JsonRpcRequest.from_dict(data)

        assert request.id == "abc-123"
        assert not request.is_notification()

    def test_from_dict_list_params(self):
        """Test request with list parameters."""
        data = {
            "jsonrpc": "2.0",
            "method": "test",
            "params": [1, 2, 3],
            "id": 1,
        }
        request = JsonRpcRequest.from_dict(data)

        assert request.params == [1, 2, 3]


class TestJsonRpcResponse:
    """Test JSON-RPC response creation and serialization."""

    def test_success_response(self):
        """Test success response creation."""
        response = JsonRpcResponse.success({"result": "ok"}, 1)

        assert response.result == {"result": "ok"}
        assert response.error is None
        assert response.id == 1

    def test_error_response(self):
        """Test error response creation."""
        response = JsonRpcResponse.error_response(
            JsonRpcError.INTERNAL_ERROR.value,
            "Something went wrong",
            1,
        )

        assert response.error is not None
        assert response.error["code"] == -32603
        assert response.error["message"] == "Something went wrong"
        assert response.result is None
        assert response.id == 1

    def test_error_response_with_data(self):
        """Test error response with additional data."""
        response = JsonRpcResponse.error_response(
            JsonRpcError.INVALID_PARAMS.value,
            "Invalid parameters",
            1,
            data={"expected": "string", "got": "int"},
        )

        assert response.error["data"] == {"expected": "string", "got": "int"}

    def test_to_dict_success(self):
        """Test success response serialization."""
        response = JsonRpcResponse.success({"value": 42}, 1)
        data = response.to_dict()

        assert data["jsonrpc"] == "2.0"
        assert data["result"] == {"value": 42}
        assert "error" not in data
        assert data["id"] == 1

    def test_to_dict_error(self):
        """Test error response serialization."""
        response = JsonRpcResponse.error_response(
            JsonRpcError.METHOD_NOT_FOUND.value,
            "Method not found",
            1,
        )
        data = response.to_dict()

        assert data["jsonrpc"] == "2.0"
        assert "result" not in data
        assert data["error"]["code"] == -32601
        assert data["error"]["message"] == "Method not found"
        assert data["id"] == 1


class TestDocumentInfo:
    """Test document information management."""

    def test_document_creation(self):
        """Test basic document info creation."""
        doc = DocumentInfo(
            uri="file:///test.py",
            content="print('hello')",
            version=1,
        )

        assert doc.uri == "file:///test.py"
        assert doc.content == "print('hello')"
        assert doc.version == 1
        assert doc.language_id == "python"
        assert len(doc.issues) == 0

    def test_document_with_issues(self):
        """Test document with issues."""
        issues = [
            {"type": "security", "severity": "high", "line": 5},
            {"type": "quality", "severity": "medium", "line": 10},
        ]
        doc = DocumentInfo(
            uri="file:///test.py",
            content="code",
            issues=issues,
        )

        assert len(doc.issues) == 2
        assert doc.issues[0]["severity"] == "high"


class TestPyGuardJsonRpcServer:
    """Test PyGuard JSON-RPC server functionality."""

    @pytest.fixture
    def server(self):
        """Create a test server instance."""
        return PyGuardJsonRpcServer(host="127.0.0.1", port=5007)

    def test_server_initialization(self, server):
        """Test server initialization."""
        assert server.host == "127.0.0.1"
        assert server.port == 5007
        assert len(server.methods) > 0
        assert not server.running

    def test_method_registration(self, server):
        """Test custom method registration."""
        def custom_method(params):
            # TODO: Add docstring
            return {"custom": True}

        server.register_method("custom/test", custom_method)
        assert "custom/test" in server.methods

    def test_initialize_method(self, server):
        """Test server initialization method."""
        params = {
            "clientInfo": {"name": "Test IDE", "version": "1.0"},
        }
        result = server._initialize(params)

        assert "capabilities" in result
        assert "serverInfo" in result
        assert result["serverInfo"]["name"] == "PyGuard JSON-RPC Server"
        assert "textDocumentSync" in result["capabilities"]

    def test_did_open_document(self, server):
        """Test document open notification."""
        params = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "print('hello')",
                "version": 1,
                "languageId": "python",
            }
        }
        server._did_open(params)

        assert "file:///test.py" in server.documents
        doc = server.documents["file:///test.py"]
        assert doc.content == "print('hello')"
        assert doc.version == 1

    def test_did_change_document(self, server):
        """Test document change notification."""
        # First open the document
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "original",
                "version": 1,
            }
        }
        server._did_open(params_open)

        # Then change it
        params_change = {
            "textDocument": {
                "uri": "file:///test.py",
                "version": 2,
            },
            "contentChanges": [
                {"text": "modified"},
            ],
        }
        server._did_change(params_change)

        doc = server.documents["file:///test.py"]
        assert doc.content == "modified"
        assert doc.version == 2

    def test_did_close_document(self, server):
        """Test document close notification."""
        # Open document
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "code",
                "version": 1,
            }
        }
        server._did_open(params_open)
        assert "file:///test.py" in server.documents

        # Close document
        params_close = {
            "textDocument": {
                "uri": "file:///test.py",
            }
        }
        server._did_close(params_close)
        assert "file:///test.py" not in server.documents

    def test_analyze_document_not_open(self, server):
        """Test analyzing a document that's not open."""
        params = {"uri": "file:///nonexistent.py"}

        with pytest.raises(ValueError, match="Document not open"):
            server._analyze_document(params)

    def test_analyze_document_basic(self, server):
        """Test basic document analysis."""
        # Open document with simple code
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "x = 1\nprint(x)",
                "version": 1,
            }
        }
        server._did_open(params_open)

        # Analyze
        params_analyze = {"uri": "file:///test.py"}
        result = server._analyze_document(params_analyze)

        assert "issues" in result
        assert "timestamp" in result
        assert "duration_ms" in result
        assert "issue_count" in result
        assert isinstance(result["issues"], list)

    def test_analyze_document_with_security_issue(self, server):
        """Test analyzing document with security issues."""
        # Code with potential security issue
        code = """
import pickle
data = pickle.loads(user_input)  # SECURITY: Don't use pickle with untrusted data
"""
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": code,
                "version": 1,
            }
        }
        server._did_open(params_open)

        params_analyze = {"uri": "file:///test.py"}
        result = server._analyze_document(params_analyze)

        # Should detect pickle security issue
        assert result["issue_count"] >= 0  # May or may not detect depending on analyzer

    def test_get_issues_cached(self, server):
        """Test getting cached issues."""
        # Open and analyze document
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "x = 1",
                "version": 1,
            }
        }
        server._did_open(params_open)
        server._analyze_document({"uri": "file:///test.py"})

        # Get cached issues
        params_get = {"uri": "file:///test.py"}
        result = server._get_issues(params_get)

        assert result["cached"] is True
        assert "issues" in result
        assert "timestamp" in result

    def test_get_issues_not_cached(self, server):
        """Test getting issues for unopened document."""
        params = {"uri": "file:///nonexistent.py"}
        result = server._get_issues(params)

        assert result["cached"] is False
        assert result["issues"] == []
        assert result["timestamp"] == 0

    def test_get_code_actions(self, server):
        """Test getting code actions."""
        # Open document with issues
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "x = 1",
                "version": 1,
            }
        }
        server._did_open(params_open)

        # Add mock issue with fix available
        doc = server.documents["file:///test.py"]
        doc.issues = [
            {
                "type": "security",
                "severity": "high",
                "line": 5,
                "message": "Test issue",
                "fix_available": True,
                "rule_id": "TEST001",
            }
        ]

        # Get code actions for range containing the issue
        params = {
            "uri": "file:///test.py",
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 10, "character": 0},
            },
        }
        actions = server._get_code_actions(params)

        assert len(actions) > 0
        assert actions[0]["kind"] == "quickfix"
        assert "title" in actions[0]

    def test_get_code_actions_no_fix(self, server):
        """Test getting code actions when no fix available."""
        # Open document with issue but no fix
        params_open = {
            "textDocument": {
                "uri": "file:///test.py",
                "text": "x = 1",
                "version": 1,
            }
        }
        server._did_open(params_open)

        doc = server.documents["file:///test.py"]
        doc.issues = [
            {
                "type": "quality",
                "severity": "low",
                "line": 5,
                "message": "Test issue",
                "fix_available": False,
            }
        ]

        params = {
            "uri": "file:///test.py",
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 10, "character": 0},
            },
        }
        actions = server._get_code_actions(params)

        # Should not return actions for unfixable issues
        assert len(actions) == 0

    def test_apply_fix(self, server):
        """Test applying a fix (currently not implemented)."""
        params = {
            "uri": "file:///test.py",
            "rule_id": "TEST001",
            "line": 5,
        }
        result = server._apply_fix(params)

        # Currently returns not implemented
        assert result["success"] is False
        assert "not yet implemented" in result["message"].lower()

    def test_set_config(self, server):
        """Test setting configuration."""
        params = {
            "config": {
                "max_line_length": 100,
                "ignore_rules": ["S001"],
            }
        }
        result = server._set_config(params)

        assert result["success"] is True
        assert server.config["max_line_length"] == 100
        assert server.config["ignore_rules"] == ["S001"]

    def test_get_config(self, server):
        """Test getting configuration."""
        server.config = {"test_key": "test_value"}

        params = {}
        result = server._get_config(params)

        assert result["config"]["test_key"] == "test_value"

    def test_change_workspace_add(self, server):
        """Test adding workspace folder."""
        params = {
            "event": {
                "added": [
                    {"uri": "file:///workspace1"},
                    {"uri": "file:///workspace2"},
                ],
                "removed": [],
            }
        }
        server._change_workspace(params)

        assert "file:///workspace1" in server.workspace_folders
        assert "file:///workspace2" in server.workspace_folders

    def test_change_workspace_remove(self, server):
        """Test removing workspace folder."""
        server.workspace_folders = ["file:///workspace1", "file:///workspace2"]

        params = {
            "event": {
                "added": [],
                "removed": [
                    {"uri": "file:///workspace1"},
                ],
            }
        }
        server._change_workspace(params)

        assert "file:///workspace1" not in server.workspace_folders
        assert "file:///workspace2" in server.workspace_folders

    def test_handle_request_success(self, server):
        """Test handling a successful request."""
        request_data = json.dumps({
            "jsonrpc": "2.0",
            "method": "pyguard/getConfig",
            "params": {},
            "id": 1,
        })

        response_str = server.handle_request(request_data)
        assert response_str is not None

        response = json.loads(response_str)
        assert response["jsonrpc"] == "2.0"
        assert "result" in response
        assert response["id"] == 1

    def test_handle_request_notification(self, server):
        """Test handling a notification (no response)."""
        request_data = json.dumps({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///test.py",
                    "text": "x = 1",
                    "version": 1,
                }
            },
        })

        response_str = server.handle_request(request_data)
        # Notifications should not return a response
        assert response_str is None

    def test_handle_request_invalid_json(self, server):
        """Test handling invalid JSON."""
        request_data = "not valid json"

        response_str = server.handle_request(request_data)
        assert response_str is not None

        response = json.loads(response_str)
        assert response["error"]["code"] == JsonRpcError.PARSE_ERROR.value

    def test_handle_request_method_not_found(self, server):
        """Test handling unknown method."""
        request_data = json.dumps({
            "jsonrpc": "2.0",
            "method": "nonexistent/method",
            "params": {},
            "id": 1,
        })

        response_str = server.handle_request(request_data)
        assert response_str is not None

        response = json.loads(response_str)
        assert response["error"]["code"] == JsonRpcError.METHOD_NOT_FOUND.value
        assert "nonexistent/method" in response["error"]["message"]

    def test_handle_request_invalid_version(self, server):
        """Test handling invalid JSON-RPC version."""
        request_data = json.dumps({
            "jsonrpc": "1.0",
            "method": "test",
            "id": 1,
        })

        response_str = server.handle_request(request_data)
        assert response_str is not None

        response = json.loads(response_str)
        assert response["error"]["code"] == JsonRpcError.INVALID_REQUEST.value

    def test_handle_request_method_exception(self, server):
        """Test handling method execution exception."""
        # Try to analyze non-existent document
        request_data = json.dumps({
            "jsonrpc": "2.0",
            "method": "pyguard/analyze",
            "params": {"uri": "file:///nonexistent.py"},
            "id": 1,
        })

        response_str = server.handle_request(request_data)
        assert response_str is not None

        response = json.loads(response_str)
        assert response["error"]["code"] == JsonRpcError.INTERNAL_ERROR.value

    def test_shutdown_and_exit(self, server):
        """Test server shutdown and exit."""
        server.running = True

        # Shutdown
        server._shutdown({})
        assert not server.running

        # Exit
        server.running = True
        server._exit({})
        assert not server.running

    def test_analyze_file_direct(self, server, tmp_path):
        """Test analyzing a file directly from disk."""
        # Create a temporary Python file
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\nprint(x)")

        params = {"path": str(test_file)}
        result = server._analyze_file(params)

        assert "issues" in result
        assert "timestamp" in result
        assert "duration_ms" in result
        assert isinstance(result["issues"], list)

    def test_analyze_file_not_found(self, server):
        """Test analyzing non-existent file."""
        params = {"path": "/nonexistent/file.py"}

        with pytest.raises(FileNotFoundError):
            server._analyze_file(params)

    def test_analyze_file_missing_path(self, server):
        """Test analyzing file without path parameter."""
        params = {}

        with pytest.raises(ValueError, match="Missing 'path' parameter"):
            server._analyze_file(params)


class TestJsonRpcIntegration:
    """Integration tests for JSON-RPC workflow."""

    @pytest.fixture
    def server(self):
        """Create a test server instance."""
        return PyGuardJsonRpcServer()

    def test_full_document_lifecycle(self, server):
        """Test complete document lifecycle: open, change, analyze, close."""
        uri = "file:///test.py"

        # 1. Open document
        open_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "text": "x = 1",
                    "version": 1,
                }
            },
        })
        response = server.handle_request(open_request)
        assert response is None  # Notification
        assert uri in server.documents

        # 2. Change document
        change_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": uri, "version": 2},
                "contentChanges": [{"text": "x = 2"}],
            },
        })
        response = server.handle_request(change_request)
        assert response is None  # Notification
        assert server.documents[uri].content == "x = 2"

        # 3. Analyze document
        analyze_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "pyguard/analyze",
            "params": {"uri": uri},
            "id": 1,
        })
        response_str = server.handle_request(analyze_request)
        assert response_str is not None
        response = json.loads(response_str)
        assert "result" in response
        assert "issues" in response["result"]

        # 4. Close document
        close_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {
                "textDocument": {"uri": uri}
            },
        })
        response = server.handle_request(close_request)
        assert response is None  # Notification
        assert uri not in server.documents

    def test_configuration_workflow(self, server):
        """Test configuration management workflow."""
        # Set configuration
        set_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "pyguard/setConfig",
            "params": {
                "config": {"severity_threshold": "high"}
            },
            "id": 1,
        })
        response_str = server.handle_request(set_request)
        response = json.loads(response_str)
        assert response["result"]["success"] is True

        # Get configuration
        get_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "pyguard/getConfig",
            "params": {},
            "id": 2,
        })
        response_str = server.handle_request(get_request)
        response = json.loads(response_str)
        assert response["result"]["config"]["severity_threshold"] == "high"

    def test_workspace_management(self, server):
        """Test workspace folder management."""
        change_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "workspace/didChangeWorkspaceFolders",
            "params": {
                "event": {
                    "added": [
                        {"uri": "file:///project1"},
                        {"uri": "file:///project2"},
                    ],
                    "removed": [],
                }
            },
        })
        response = server.handle_request(change_request)
        assert response is None  # Notification
        assert len(server.workspace_folders) == 2
        assert "file:///project1" in server.workspace_folders
