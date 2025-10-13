# GitHub Copilot MCP Servers

This repository is configured with Model Context Protocol (MCP) servers to enhance GitHub Copilot's capabilities. The configuration is stored in `.github/copilot-mcp.json`.

## What is MCP?

The Model Context Protocol (MCP) is an open standard for connecting AI models with external context sources and tools. It enables enhanced AI-powered assistance during development.

## Configured MCP Servers

### 1. Context7 (HTTP Server)

**What is Context7?**

LLMs rely on outdated or generic information about the libraries you use. Context7 pulls up-to-date, version-specific documentation and code examples directly from the source. Paste accurate, relevant documentation directly into tools like Cursor, Claude, or any LLM. Get better answers, no hallucinations and an AI that actually understands your stack.

- **Type**: HTTP
- **Endpoint**: `https://mcp.context7.com/mcp`
- **Authentication**: `$COPILOT_MCP_CONTEXT7_API_KEY` environment variable
- **Tools**: All available tools (*)

### 2. OpenAI Web Search (Local Server)

Enables web search capabilities through OpenAI for real-time information lookup during development.

- **Type**: Local
- **Command**: `uvx openai-websearch-mcp`
- **Authentication**: `COPILOT_MCP_OPENAI_API_KEY` environment variable
- **Tools**: `openai_web_search`

### 3. Fetch (Local Server)

Fetches web content for analysis, enabling GitHub Copilot to retrieve documentation and online resources.

- **Type**: Local
- **Command**: `npx -y mcp-fetch-server@latest`
- **Tools**: All available tools (*)

### 4. Playwright (Local Server)

Browser automation capabilities for testing and development, allowing GitHub Copilot to help with browser-based testing scenarios.

- **Type**: Local
- **Command**: `npx -y @playwright/mcp@latest`
- **Tools**: All available tools (*)

## Security Considerations

All API keys are referenced via environment variables to maintain security:
- No hardcoded secrets in the configuration
- Environment variables follow GitHub Copilot's standard naming pattern
- External servers require explicit API key configuration

## Setup

To use these MCP servers with GitHub Copilot:

1. Ensure you have the required environment variables set:
   - `COPILOT_MCP_CONTEXT7_API_KEY` - For Context7 server
   - `COPILOT_MCP_OPENAI_API_KEY` - For OpenAI Web Search

2. For local servers, ensure you have the required tools installed:
   - `uvx` - For OpenAI Web Search
   - `npx` - For Fetch and Playwright servers

3. GitHub Copilot will automatically use these configured servers when available.

## Configuration Format

### HTTP Servers (Context7)

HTTP servers require authentication via the `Authorization` header with Bearer token:

```json
{
  "type": "http",
  "url": "https://mcp.context7.com/mcp",
  "headers": {
    "Authorization": "Bearer $COPILOT_MCP_CONTEXT7_API_KEY"
  }
}
```

**Important:** Use the standard `Authorization` header with `Bearer` prefix for OAuth-style authentication.

### Local Servers (OpenAI, Fetch, Playwright)

Local servers use environment variables that must include the `$` prefix for substitution:

```json
{
  "type": "local",
  "command": "uvx",
  "args": ["openai-websearch-mcp"],
  "env": {
    "OPENAI_API_KEY": "$COPILOT_MCP_OPENAI_API_KEY"
  }
}
```

**Important:** The `$` prefix is required for environment variable substitution. Without it, the literal string is passed instead of the variable value.

## Validation

A validation script is available to check your configuration:

```bash
.github/validate-mcp-config.sh
```

This script verifies:
- JSON syntax validity
- Correct server configuration structure
- Proper authentication header formats
- Environment variable reference formats
- Required tool availability (npx, uvx)

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [Context7 Documentation](https://context7.com)
- [PyGuard MCP Integration Guide](../docs/MCP-INTEGRATION.md)
