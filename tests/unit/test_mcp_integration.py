"""Unit tests for MCP integration module."""

from pyguard.lib.mcp_integration import (
    MCPIntegration,
    MCPQuery,
    MCPResponse,
    MCPServer,
)


class TestMCPServer:
    """Test MCP server dataclass."""

    def test_create_server(self):
        """Test creating an MCP server."""
        server = MCPServer(
            name="Test Server",
            url="mcp://test.com/api",
            enabled=True,
            capabilities=["security_analysis"],
        )

        assert server.name == "Test Server"
        assert server.url == "mcp://test.com/api"
        assert server.enabled is True
        assert "security_analysis" in server.capabilities

    def test_server_defaults(self):
        """Test default values."""
        server = MCPServer(name="Test", url="mcp://test.com")

        assert server.enabled is True
        assert server.api_key is None
        assert server.capabilities == []


class TestMCPIntegration:
    """Test MCP integration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mcp = MCPIntegration()

    def test_initialization(self):
        """Test MCP integration initialization."""
        assert self.mcp is not None
        assert "local" in self.mcp.servers
        assert "context7" in self.mcp.servers

    def test_default_servers_registered(self):
        """Test that default servers are registered."""
        assert len(self.mcp.servers) >= 2
        assert self.mcp.servers["local"].enabled is True
        assert self.mcp.servers["context7"].enabled is False

    def test_register_custom_server(self):
        """Test registering a custom MCP server."""
        custom_server = MCPServer(
            name="Custom",
            url="mcp://custom.com",
            capabilities=["custom_analysis"],
        )

        result = self.mcp.register_server(custom_server)
        assert result is True
        assert "Custom" in self.mcp.servers

    def test_query_security_intelligence(self):
        """Test querying security intelligence."""
        code = "eval(user_input)"
        response = self.mcp.query_security_intelligence(code)

        assert response is not None
        assert isinstance(response, MCPResponse)
        assert response.success is True
        assert len(response.recommendations) > 0

    def test_query_with_safe_code(self):
        """Test querying with safe code."""
        code = "x = 1 + 1"
        response = self.mcp.query_security_intelligence(code)

        assert response is not None
        assert response.success is True

    def test_is_available(self):
        """Test checking if MCP is available."""
        assert self.mcp.is_available() is True

    def test_get_server_status(self):
        """Test getting server status."""
        status = self.mcp.get_server_status()

        assert isinstance(status, dict)
        assert "local" in status
        assert status["local"]["enabled"] is True

    def test_get_enhanced_vulnerability_info(self):
        """Test getting enhanced vulnerability information."""
        # This returns None since we don't have external servers
        info = self.mcp.get_enhanced_vulnerability_info("CWE-89")
        # Should return None or a dict
        assert info is None or isinstance(info, dict)

    def test_get_code_recommendations(self):
        """Test getting code recommendations."""
        code = "eval(x)"
        recommendations = self.mcp.get_code_recommendations(code, "code_injection")

        assert isinstance(recommendations, list)


class TestMCPQuery:
    """Test MCP query dataclass."""

    def test_create_query(self):
        """Test creating an MCP query."""
        query = MCPQuery(
            query_type="security_check",
            code_snippet="eval(x)",
            language="python",
            context={"file": "test.py"},
        )

        assert query.query_type == "security_check"
        assert query.code_snippet == "eval(x)"
        assert query.language == "python"
        assert query.context["file"] == "test.py"


class TestMCPResponse:
    """Test MCP response dataclass."""

    def test_create_response(self):
        """Test creating an MCP response."""
        response = MCPResponse(
            success=True,
            data={"issues": 1},
            confidence=0.95,
            source="test",
            timestamp="2025-01-01T00:00:00",
            recommendations=["Fix issue"],
        )

        assert response.success is True
        assert response.confidence == 0.95
        assert len(response.recommendations) == 1

    def test_response_defaults(self):
        """Test default values."""
        response = MCPResponse(
            success=True,
            data={},
            confidence=0.8,
            source="test",
            timestamp="2025-01-01",
        )

        assert response.recommendations == []
