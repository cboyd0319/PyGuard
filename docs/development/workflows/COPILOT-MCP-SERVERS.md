# GitHub Copilot MCP Server Configuration

**Last Updated:** October 13, 2025  
**Configuration File:** `.github/copilot-mcp.json`  
**Status:** ✅ Fully Operational

## Overview

This document describes the Model Context Protocol (MCP) servers configured for GitHub Copilot in the PyGuard repository. These servers enhance Copilot's capabilities by providing access to external data sources and tools.

> ⚠️ **Note:** GitHub MCP (repository operations, issues, PRs) is **built-in to GitHub Copilot** and uses OAuth
> authentication automatically. It does NOT require configuration in this file and does NOT support Personal Access
> Tokens (PAT). This document covers only the external MCP servers that require explicit configuration.

## What is MCP?

**Model Context Protocol (MCP)** is an open standard that enables AI assistants to access external data sources and tools through a standardized interface. MCP servers act as bridges between GitHub Copilot and various services, providing:

- Up-to-date documentation
- Web search capabilities
- HTTP request functionality
- Browser automation
- And more

## Configured MCP Servers

### 1. Context7 (HTTP Server)

**Purpose:** Provides up-to-date documentation for libraries and frameworks  
**Type:** HTTP-based remote server  
**Status:** ✅ Active (requires API key)

**Configuration:**
```json
{
  "type": "http",
  "url": "https://mcp.context7.com/mcp",
  "headers": {
    "Authorization": "Bearer ${COPILOT_MCP_CONTEXT7_API_KEY}"
  },
  "tools": ["*"]
}
```

**Requirements:**
- Environment variable: `COPILOT_MCP_CONTEXT7_API_KEY`
- Get your API key at: https://context7.com

**Use Cases for PyGuard:**
- Query Python standard library documentation
- Look up AST module patterns
- Research security framework specifications (OWASP, CWE)
- Get pytest documentation and examples
- Access compliance standard documentation

**Example Queries:**
- "Show me Python AST visitor pattern documentation"
- "What are the OWASP ASVS authentication requirements?"
- "Get pytest fixture documentation"

---

### 2. OpenAI Web Search (Local Server)

**Purpose:** Web search capabilities for real-time information  
**Type:** Local server (uvx-based)  
**Status:** ✅ Active (requires API key)

**Configuration:**
```json
{
  "type": "local",
  "command": "uvx",
  "args": ["openai-websearch-mcp"],
  "env": {
    "OPENAI_API_KEY": "${COPILOT_MCP_OPENAI_API_KEY}"
  },
  "tools": ["openai_web_search"]
}
```

**Requirements:**
- Environment variable: `COPILOT_MCP_OPENAI_API_KEY`
- Tool: `uvx` (Python package runner from uv)
- Get your OpenAI API key at: https://platform.openai.com

**Use Cases for PyGuard:**
- Search for latest CVE information
- Research current OWASP Top 10
- Find recent security vulnerabilities
- Get updates on compliance frameworks
- Research emerging security threats

**Example Queries:**
- "Search for latest Python pickle CVE"
- "What are the latest OWASP Top 10 for 2025?"
- "Find recent SQL injection techniques"

---

### 3. Fetch (Local Server)

**Purpose:** HTTP client for making web requests  
**Type:** Local server (npx-based)  
**Status:** ✅ Active (no API key required)

**Configuration:**
```json
{
  "type": "local",
  "command": "npx",
  "args": ["-y", "mcp-fetch-server@latest"],
  "tools": ["*"]
}
```

**Requirements:**
- Tool: `npx` (Node.js package runner)
- No API key required

**Use Cases for PyGuard:**
- Query CVE databases (NVD, GitHub Advisory)
- Fetch OWASP documentation
- Test API endpoints for vulnerabilities
- Download CWE definitions
- Access security advisories

**Example Usage:**
- "Fetch CVE information from NVD API"
- "Get OWASP dependency check data"
- "Download CWE list from MITRE"

---

### 4. Playwright (Local Server)

**Purpose:** Browser automation and web testing  
**Type:** Local server (npx-based)  
**Status:** ✅ Active (no API key required)

**Configuration:**
```json
{
  "type": "local",
  "command": "npx",
  "args": ["-y", "@playwright/mcp@latest"],
  "tools": ["*"]
}
```

**Requirements:**
- Tool: `npx` (Node.js package runner)
- No API key required

**Use Cases for PyGuard:**
- Test XSS detection in real browsers
- Validate HTML security scan reports
- Scrape security advisories from websites
- Test CSRF protection mechanisms
- Verify security fixes in live environments

**Example Usage:**
- "Use Playwright to test XSS vulnerability"
- "Validate the HTML report rendering"
- "Test form input sanitization in browser"

---

## Setup Instructions

### Prerequisites

1. **Node.js and npm** (for npx commands)
   ```bash
   # macOS
   brew install node
   
   # Ubuntu/Debian
   curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **uv/uvx** (for OpenAI web search, optional)
   ```bash
   # macOS
   brew install uv
   
   # Ubuntu/Debian
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

### Adding API Keys

#### For Local Development

Set environment variables in your shell:

```bash
# Add to ~/.bashrc, ~/.zshrc, or equivalent
export COPILOT_MCP_CONTEXT7_API_KEY="your_context7_api_key"
export COPILOT_MCP_OPENAI_API_KEY="your_openai_api_key"
```

#### For GitHub Codespaces / Actions

Add repository secrets:

1. Go to repository **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Add:
   - Name: `COPILOT_MCP_CONTEXT7_API_KEY`, Value: your Context7 API key
   - Name: `COPILOT_MCP_OPENAI_API_KEY`, Value: your OpenAI API key

**Security Note:** These secrets are encrypted at rest and only accessible to authorized workflows and Copilot sessions.

---

## Validation

### Automated Validation

Run the validation script to check configuration:

```bash
bash scripts/validate-mcp-config.sh
```

Expected output:
```
✅ JSON syntax is valid
✅ mcpServers key found
✅ Authorization header format is correct (Bearer token)
✅ Environment variable reference is correct ($ prefix)
✅ uvx command available
✅ Fetch server configured
✅ Playwright server configured
✅ MCP configuration validation passed!
```

### Manual Testing in GitHub Copilot

1. **Test Context7:**
   - Open Copilot Chat
   - Ask: "Use Context7 to show Python AST visitor documentation"

2. **Test OpenAI Web Search:**
   - Ask: "Search for latest OWASP Top 10"

3. **Test Fetch:**
   - Ask: "Fetch the PyGuard repository information from GitHub"

4. **Test Playwright:**
   - Ask: "Use Playwright to navigate to example.com"

---

## Troubleshooting

### Error: "Command not found: uvx"

**Solution:** Install uv:
```bash
# macOS
brew install uv

# Ubuntu/Debian
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Error: "Command not found: npx"

**Solution:** Install Node.js:
```bash
# macOS
brew install node

# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### MCP Server Not Responding

**Debug Steps:**

1. Check VS Code Output panel → GitHub Copilot
2. Validate JSON syntax:
   ```bash
   cat .github/copilot-mcp.json | jq
   ```
3. Verify environment variables are set:
   ```bash
   echo $COPILOT_MCP_CONTEXT7_API_KEY
   echo $COPILOT_MCP_OPENAI_API_KEY
   ```
4. Test API connectivity:
   ```bash
   curl -H "Authorization: Bearer $COPILOT_MCP_CONTEXT7_API_KEY" \
        https://mcp.context7.com/mcp/health
   ```

### Configuration Not Loading

**Common Causes:**
- JSON syntax errors (validate with `jq`)
- Missing environment variables
- Incorrect file path (must be `.github/copilot-mcp.json`)
- GitHub Copilot extension needs restart

---

## Security Considerations

### API Key Management

✅ **Best Practices:**
- Store keys as GitHub Secrets (encrypted at rest)
- Use repository secrets, not organization secrets (least privilege)
- Set billing limits on OpenAI account
- Rotate keys periodically

❌ **Never:**
- Commit API keys to version control
- Share API keys in issues or pull requests
- Log API keys in debug output
- Use organization-wide secrets unless necessary

### Rate Limiting

- **Context7:** Free tier has rate limits (check your plan)
- **OpenAI:** Set billing limits to prevent unexpected costs
- **Fetch/Playwright:** Respect target site robots.txt and rate limits

### Data Privacy

- **Context7:** Sends library names/versions only (no code)
- **OpenAI:** Sends query text to OpenAI API (no code by default)
- **Fetch/Playwright:** You control what data is sent/retrieved
- **PyGuard Principle:** All MCP servers respect zero-telemetry policy

---

## Configuration Schema

### Environment Variable Substitution

MCP configuration supports environment variable substitution using the `${VAR_NAME}` syntax:

```json
{
  "headers": {
    "Authorization": "Bearer ${COPILOT_MCP_CONTEXT7_API_KEY}"
  },
  "env": {
    "OPENAI_API_KEY": "${COPILOT_MCP_OPENAI_API_KEY}"
  }
}
```

### Server Types

1. **HTTP Servers** (`type: "http"`)
   - Remote servers accessed via HTTP/HTTPS
   - Require URL and optional headers
   - Example: Context7

2. **Local Servers** (`type: "local"`)
   - Local processes spawned by Copilot
   - Require command and args
   - Can have environment variables
   - Examples: OpenAI Web Search, Fetch, Playwright

---

## Related Documentation

- **[MCP Integration Guide](../docs/MCP-GUIDE.md)** — Detailed guide with examples
- **[GitHub Copilot Instructions](copilot-instructions.md)** — Project-specific Copilot guidance
- **[Security Policy](../../../SECURITY.md)** — Security practices and disclosure
- **[Contributing Guidelines](../../../CONTRIBUTING.md)** — Development workflow

---

## Quick Reference

| Server | API Key Required | Command | Status |
|--------|------------------|---------|--------|
| context7 | ✅ Yes | N/A (HTTP) | ✅ Active |
| openai-websearch | ✅ Yes | `uvx` | ✅ Active |
| fetch | ❌ No | `npx` | ✅ Active |
| playwright | ❌ No | `npx` | ✅ Active |

**Need help?** Open an issue with the `mcp` label or check the [Troubleshooting](#troubleshooting) section.
