# MCP Integration Guide

**PyGuard v0.5.0** introduces support for the **Model Context Protocol (MCP)**, enabling integration with external knowledge sources and AI-powered code analysis services.

---

## 📚 What is MCP?

The **Model Context Protocol (MCP)** is an open standard for connecting AI models with external context sources. It enables:

- **Enhanced Knowledge**: Access to external security databases and threat intelligence
- **Real-time Updates**: Latest vulnerability information from multiple sources
- **AI-Powered Analysis**: Advanced pattern recognition and recommendations
- **Extensibility**: Connect to multiple MCP servers for specialized analysis

**References:**
- MCP Specification: https://modelcontextprotocol.io
- Anthropic MCP: https://github.com/anthropics/mcp

---

## 🚀 Quick Start

### Basic Usage

```python
from pyguard.lib.mcp_integration import MCPIntegration

# Initialize MCP integration
mcp = MCPIntegration()

# Query security intelligence
code = "eval(user_input)"
response = mcp.query_security_intelligence(code)

if response and response.success:
    print(f"Security Issues: {response.recommendations}")
    print(f"Confidence: {response.confidence}")
```

### Enable Context7 Server

```python
from pyguard.lib.mcp_integration import MCPIntegration, MCPServer

mcp = MCPIntegration()

# Configure Context7 with API key
context7 = MCPServer(
    name="Context7",
    url="mcp://context7.com/api/v1",
    enabled=True,
    api_key="your-api-key-here",
    capabilities=[
        "security_analysis",
        "code_patterns",
        "vulnerability_detection",
    ]
)

# Register server
mcp.register_server(context7)

# Query with enhanced intelligence
response = mcp.query_security_intelligence("import os; os.system(user_cmd)")
```

---

## 🔌 Supported MCP Servers

### 1. Local Knowledge Base (Built-in)

**Always Available** - No configuration required

- OWASP Top 10 2021 database
- CWE Top 25 2023 database
- Pattern-based vulnerability detection
- Zero external dependencies

```python
# Already enabled by default
mcp = MCPIntegration()
assert mcp.servers["local"].enabled == True
```

### 2. Context7 (External)

**Requires API Key** - Advanced code intelligence

- Real-time security threat intelligence
- AI-powered vulnerability detection
- Code quality recommendations
- Industry best practices

**Setup:**
1. Sign up at https://context7.com
2. Get your API key
3. Configure in PyGuard:

```python
context7 = MCPServer(
    name="Context7",
    url="mcp://context7.com/api/v1",
    enabled=True,
    api_key=os.environ.get("CONTEXT7_API_KEY"),
)
mcp.register_server(context7)
```

### 3. Custom MCP Servers

**Extensible** - Add your own servers

```python
custom_server = MCPServer(
    name="Corporate Security Intel",
    url="mcp://internal.company.com/security",
    enabled=True,
    api_key="internal-key",
    capabilities=[
        "corporate_policies",
        "custom_rules",
        "compliance_check",
    ]
)
mcp.register_server(custom_server)
```

---

## 📖 API Reference

### MCPIntegration Class

```python
class MCPIntegration:
    """Main MCP integration class."""
    
    def __init__(self):
        """Initialize with default servers."""
        
    def register_server(self, server: MCPServer) -> bool:
        """Register a new MCP server."""
        
    def query_security_intelligence(
        self, 
        code_snippet: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[MCPResponse]:
        """Query for security intelligence."""
        
    def get_enhanced_vulnerability_info(self, cwe_id: str) -> Optional[Dict]:
        """Get detailed vulnerability information."""
        
    def get_code_recommendations(
        self, 
        code_snippet: str, 
        issue_type: str
    ) -> List[str]:
        """Get AI-powered recommendations."""
        
    def is_available(self) -> bool:
        """Check if any servers are available."""
        
    def get_server_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered servers."""
```

### MCPServer Class

```python
@dataclass
class MCPServer:
    """MCP server configuration."""
    
    name: str
    url: str
    enabled: bool = True
    api_key: Optional[str] = None
    capabilities: List[str] = None
```

### MCPResponse Class

```python
@dataclass
class MCPResponse:
    """Response from MCP server."""
    
    success: bool
    data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    source: str
    timestamp: str
    recommendations: List[str]
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Context7 API Key
export CONTEXT7_API_KEY="your-api-key"

# Custom server configuration
export MCP_SERVER_URL="mcp://custom.server.com"
export MCP_API_KEY="custom-key"
```

### Configuration File

Create `.mcp_config.json`:

```json
{
  "servers": [
    {
      "name": "Context7",
      "url": "mcp://context7.com/api/v1",
      "enabled": true,
      "api_key": "${CONTEXT7_API_KEY}",
      "capabilities": [
        "security_analysis",
        "code_patterns",
        "vulnerability_detection"
      ]
    },
    {
      "name": "Custom Internal",
      "url": "mcp://internal.company.com",
      "enabled": true,
      "api_key": "${INTERNAL_API_KEY}",
      "capabilities": ["compliance_check"]
    }
  ]
}
```

---

## 🎯 Use Cases

### 1. Enhanced Security Analysis

```python
from pyguard.lib.mcp_integration import MCPIntegration

mcp = MCPIntegration()

# Analyze potentially dangerous code
code = """
import pickle
data = pickle.loads(user_data)
"""

response = mcp.query_security_intelligence(code)

if response:
    print(f"Severity: {response.data.get('severity', 'UNKNOWN')}")
    for rec in response.recommendations:
        print(f"  - {rec}")
```

### 2. Real-time Vulnerability Lookup

```python
# Get latest information about a CWE
cwe_info = mcp.get_enhanced_vulnerability_info("CWE-89")

if cwe_info:
    print(f"CWE-89: {cwe_info.get('description')}")
    print(f"Mitigation: {cwe_info.get('mitigation')}")
```

### 3. Code Improvement Recommendations

```python
# Get recommendations for specific issues
code = "if type(x) == str:"
recommendations = mcp.get_code_recommendations(code, "type_comparison")

for rec in recommendations:
    print(f"💡 {rec}")
```

---

## 🔐 Security Considerations

### API Key Management

**Never hardcode API keys!**

✅ **Good:**
```python
api_key = os.environ.get("CONTEXT7_API_KEY")
```

❌ **Bad:**
```python
api_key = "12345-secret-key"  # Never do this!
```

### Data Privacy

- **Local Processing**: Local knowledge base never sends data externally
- **Opt-in External**: External servers require explicit configuration
- **No Code Storage**: Code snippets are analyzed in transit only
- **Secure Transport**: All MCP connections use TLS/HTTPS

### Network Security

- Verify server certificates
- Use VPN for corporate servers
- Implement rate limiting
- Monitor API usage

---

## 🧪 Testing MCP Integration

```python
import pytest
from pyguard.lib.mcp_integration import MCPIntegration, MCPServer

def test_mcp_availability():
    """Test MCP is available."""
    mcp = MCPIntegration()
    assert mcp.is_available()

def test_register_server():
    """Test registering custom server."""
    mcp = MCPIntegration()
    
    server = MCPServer(
        name="Test Server",
        url="mcp://test.com",
        capabilities=["test"],
    )
    
    result = mcp.register_server(server)
    assert result == True
    assert "Test Server" in mcp.servers

def test_query_security():
    """Test security intelligence query."""
    mcp = MCPIntegration()
    
    response = mcp.query_security_intelligence("eval(x)")
    
    assert response is not None
    assert response.success == True
    assert len(response.recommendations) > 0
```

---

## 📊 Performance

### Response Times

| Server Type | Typical Latency | Throughput |
|------------|----------------|------------|
| Local KB | <1ms | 10,000+ req/sec |
| Context7 | 50-200ms | 100 req/sec |
| Custom Server | Varies | Varies |

### Caching

MCP responses are cached for:
- Local KB: No caching needed (instant)
- External servers: 1 hour default
- Failed requests: 5 minutes

---

## 🤝 Contributing

Want to add support for a new MCP server?

1. Fork the repository
2. Implement server connector in `mcp_integration.py`
3. Add tests in `tests/unit/test_mcp_integration.py`
4. Update this documentation
5. Submit a pull request

---

## 📚 Additional Resources

- [MCP Protocol Specification](https://modelcontextprotocol.io)
- [Context7 Documentation](https://context7.com/docs)
- [PyGuard Architecture](./ARCHITECTURE.md)
- [API Reference](./api-reference.md)

---

## 🆘 Troubleshooting

### Server Not Responding

```python
# Check server status
status = mcp.get_server_status()
print(status)

# Verify network connectivity
import requests
response = requests.get("https://api.server.com/health")
print(response.status_code)
```

### Authentication Errors

```bash
# Verify API key
echo $CONTEXT7_API_KEY

# Test authentication
curl -H "Authorization: Bearer $CONTEXT7_API_KEY" \
     https://api.context7.com/v1/test
```

### Low Confidence Scores

- May indicate ambiguous code patterns
- Consider adding more context
- Check server capabilities
- Verify code snippet completeness

---

<p align="center">
  <strong>MCP Integration makes PyGuard smarter with every query!</strong>
  <br>
  Questions? Open an issue on GitHub!
</p>
