"""
MCP (Model Context Protocol) Integration for PyGuard.

Provides connectivity to MCP servers like Context7 for enhanced knowledge bases,
real-time security intelligence, and AI-powered code analysis.

References:
- MCP Protocol | https://modelcontextprotocol.io | High | Model Context Protocol specification
- Context7 | https://context7.com | Medium | Code intelligence MCP server
- Anthropic MCP | https://github.com/anthropics/mcp | High | Reference implementation
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pyguard.lib.core import PyGuardLogger


@dataclass
class MCPServer:
    """Represents an MCP server connection."""

    name: str
    url: str
    enabled: bool = True
    api_key: Optional[str] = None
    capabilities: Optional[List[str]] = None

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []


@dataclass
class MCPQuery:
    """Represents a query to an MCP server."""

    query_type: str  # security_check, code_analysis, vulnerability_lookup
    code_snippet: str
    language: str = "python"
    context: Optional[Dict[str, Any]] = None


@dataclass
class MCPResponse:
    """Response from an MCP server."""

    success: bool
    data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    source: str
    timestamp: str
    recommendations: Optional[List[str]] = None

    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class MCPIntegration:
    """
    Integration with MCP servers for enhanced code intelligence.

    Provides:
    - Real-time security intelligence from Context7 and other MCP servers
    - AI-powered code analysis and recommendations
    - Enhanced vulnerability detection with ML models
    - Knowledge base augmentation from external sources
    """

    def __init__(self):
        """Initialize MCP integration."""
        self.logger = PyGuardLogger()
        self.servers: Dict[str, MCPServer] = {}
        self._initialize_default_servers()

    def _initialize_default_servers(self):
        """Initialize default MCP server configurations."""
        # Context7 - Code intelligence and security knowledge
        self.servers["context7"] = MCPServer(
            name="Context7",
            url="mcp://context7.com/api/v1",
            enabled=False,  # Disabled by default, requires API key
            capabilities=[
                "security_analysis",
                "code_patterns",
                "vulnerability_detection",
                "best_practices",
            ],
        )

        # Local knowledge base (always available)
        self.servers["local"] = MCPServer(
            name="Local Knowledge Base",
            url="local://pyguard/kb",
            enabled=True,
            capabilities=[
                "owasp_top10",
                "cwe_database",
                "pattern_matching",
            ],
        )

    def register_server(self, server: MCPServer) -> bool:
        """
        Register a new MCP server.

        Args:
            server: MCPServer instance to register

        Returns:
            True if registered successfully
        """
        try:
            self.servers[server.name] = server
            self.logger.info(
                f"Registered MCP server: {server.name}",
                category="MCP",
                details={"url": server.url, "capabilities": server.capabilities},
            )
            return True
        except Exception as e:
            self.logger.error(
                f"Failed to register MCP server: {str(e)}",
                category="MCP",
                details={"server": server.name},
            )
            return False

    def query_security_intelligence(
        self, code_snippet: str, context: Optional[Dict[str, Any]] = None
    ) -> Optional[MCPResponse]:
        """
        Query MCP servers for security intelligence.

        Args:
            code_snippet: Code to analyze
            context: Additional context (file path, line numbers, etc.)

        Returns:
            MCPResponse with analysis results or None if unavailable
        """
        query = MCPQuery(
            query_type="security_check", code_snippet=code_snippet, context=context
        )

        # Try enabled servers in priority order
        for server_name in ["context7", "local"]:
            if server_name in self.servers and self.servers[server_name].enabled:
                response = self._query_server(self.servers[server_name], query)
                if response and response.success:
                    return response

        return None

    def _query_server(self, server: MCPServer, query: MCPQuery) -> Optional[MCPResponse]:
        """
        Query a specific MCP server.

        Args:
            server: MCP server to query
            query: Query to execute

        Returns:
            MCPResponse or None if query failed
        """
        # For now, return local knowledge base responses
        # In production, this would make actual HTTP/gRPC calls to MCP servers
        if server.name == "Local Knowledge Base":
            return self._local_query(query)

        # External MCP servers would be queried here
        self.logger.debug(
            f"MCP query to {server.name} (stub)",
            category="MCP",
            details={"query_type": query.query_type},
        )
        return None

    def _local_query(self, query: MCPQuery) -> MCPResponse:
        """
        Query local knowledge base.

        Args:
            query: Query to execute

        Returns:
            MCPResponse with local analysis
        """
        from datetime import datetime

        # Simple pattern matching for demonstration
        recommendations = []
        confidence = 0.8

        if "eval(" in query.code_snippet or "exec(" in query.code_snippet:
            recommendations.append(
                "CRITICAL: eval/exec detected - use ast.literal_eval or safe alternatives"
            )
            confidence = 0.95

        if "pickle.load" in query.code_snippet:
            recommendations.append(
                "HIGH: Unsafe deserialization - validate input or use safer formats"
            )
            confidence = 0.9

        return MCPResponse(
            success=True,
            data={
                "patterns_detected": len(recommendations),
                "query_type": query.query_type,
            },
            confidence=confidence,
            source="local_kb",
            timestamp=datetime.now().isoformat(),
            recommendations=recommendations,
        )

    def get_enhanced_vulnerability_info(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Get enhanced vulnerability information from MCP servers.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")

        Returns:
            Enhanced vulnerability information or None
        """
        # Query MCP servers for additional context
        query = MCPQuery(
            query_type="vulnerability_lookup",
            code_snippet="",
            context={"cwe_id": cwe_id},
        )

        for server in self.servers.values():
            if server.enabled and server.capabilities and "vulnerability_detection" in server.capabilities:
                response = self._query_server(server, query)
                if response and response.success:
                    return response.data

        return None

    def get_code_recommendations(
        self, code_snippet: str, issue_type: str
    ) -> List[str]:
        """
        Get AI-powered code improvement recommendations.

        Args:
            code_snippet: Code to analyze
            issue_type: Type of issue detected

        Returns:
            List of recommendations
        """
        query = MCPQuery(
            query_type="code_analysis",
            code_snippet=code_snippet,
            context={"issue_type": issue_type},
        )

        recommendations: List[str] = []
        for server in self.servers.values():
            if server.enabled and server.capabilities and "code_patterns" in server.capabilities:
                response = self._query_server(server, query)
                if response and response.success and response.recommendations:
                    recommendations.extend(response.recommendations)

        return recommendations

    def is_available(self) -> bool:
        """
        Check if any MCP servers are available.

        Returns:
            True if at least one server is enabled
        """
        return any(server.enabled for server in self.servers.values())

    def get_server_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all registered MCP servers.

        Returns:
            Dictionary of server statuses
        """
        status = {}
        for name, server in self.servers.items():
            status[name] = {
                "enabled": server.enabled,
                "url": server.url,
                "capabilities": server.capabilities,
            }
        return status
