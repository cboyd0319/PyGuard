# Model Context Protocol (MCP) Integration Guide

**Last Updated:** October 13, 2025  
**Status:** ✅ Operational (2 servers ready, 2 optional with API keys)

## TL;DR

PyGuard uses Model Context Protocol (MCP) servers to enhance GitHub Copilot with external knowledge sources. Two servers work out-of-the-box (`fetch`, `playwright`), two require API keys (`context7`, `openai-websearch`). GitHub operations work automatically through Copilot's built-in OAuth.

**Quick actions:**
- View config: `cat .github/copilot-mcp.json`
- Test in Copilot: Open Copilot Chat, mention `@github` and use MCP tools
- Add API keys: Repository Settings → Secrets → Actions (optional)

---

## What is MCP?

**Model Context Protocol** is an open standard that lets AI assistants (like GitHub Copilot) access external data sources and tools through a standardized interface.

### Key Benefits for PyGuard Development
- **Up-to-date documentation** — Context7 provides current library docs (Python, AST, security frameworks)
- **Web search** — OpenAI web search for latest CVE information and security research
- **Browser automation** — Playwright for testing security scanning on real websites
- **HTTP client** — Fetch for API requests and testing integrations
- **GitHub operations** — Built-in server for repos, issues, PRs (no config needed)

---

## Current Configuration

Configuration file: `.github/copilot-mcp.json`

| Server | Type | Status | Requirements |
|--------|------|--------|--------------|
| **fetch** | Local (npx) | ✅ Ready | None (npx available) |
| **playwright** | Local (npx) | ✅ Ready | None (npx available) |
| **context7** | HTTP | ⚠️ Needs API Key | `COPILOT_MCP_CONTEXT7_API_KEY` secret |
| **openai-websearch** | Local (uvx) | ⚠️ Needs API Key | `COPILOT_MCP_OPENAI_API_KEY` secret |
| **GitHub** | Built-in | ✅ Ready | OAuth (automatic) |

### ✅ What Works Out-of-the-Box

1. **fetch** — HTTP requests to security APIs, CVE databases
2. **playwright** — Browser automation for testing security features
3. **GitHub operations** — Repos, issues, PRs, workflows (OAuth-based, no config needed)

### ⚠️ What Needs API Keys (Optional)

1. **context7** — Library documentation lookup (Python, security frameworks, AST libraries)
   - Get API key: https://context7.com
   - Add secret: `COPILOT_MCP_CONTEXT7_API_KEY`

2. **openai-websearch** — Web search for CVE info, security research, latest vulnerabilities
   - Get API key: https://platform.openai.com
   - Add secret: `COPILOT_MCP_OPENAI_API_KEY`

---

## Setup Instructions

### Prerequisites
- Node.js/npm installed (for `npx` commands)
- Python 3.8+ with `uv` or `uvx` (for OpenAI web search, optional)
- GitHub Copilot enabled in VS Code or GitHub Codespaces

### Option 1: Use Without API Keys (Default)
The `fetch` and `playwright` servers work immediately. No setup required.

### Option 2: Enable All Servers (Recommended for Security Research)

#### Step 1: Get API Keys

1. **Context7 API Key**
   - Sign up at https://context7.com
   - Create API key (free tier available)
   - Useful for: Python stdlib, AST, security framework documentation

2. **OpenAI API Key**
   - Sign up at https://platform.openai.com
   - Create API key with appropriate billing limits
   - Useful for: CVE lookups, security research, latest vulnerability information

#### Step 2: Add Secrets to GitHub Repository

**Repository Settings → Secrets and variables → Actions → New repository secret**

| Name | Value |
|------|-------|
| `COPILOT_MCP_CONTEXT7_API_KEY` | Your Context7 API key |
| `COPILOT_MCP_OPENAI_API_KEY` | Your OpenAI API key |

**Security note:** These secrets are encrypted at rest and only accessible to GitHub Actions.

#### Step 3: Test in GitHub Copilot

Open VS Code or GitHub Codespaces:

1. Open GitHub Copilot Chat
2. Try context7: "Show me Python AST visitor pattern documentation"
3. Try web search: "What are the latest OWASP Top 10 for 2025?"
4. Try fetch: "Get CVE information from NVD API"

---

## Server Details

### 1. fetch (Local/npx)
**Purpose:** HTTP client for API requests  
**Status:** ✅ Ready (no config needed)

**Example use cases for PyGuard:**
- Query CVE databases (NVD, GitHub Advisory)
- Fetch OWASP documentation
- Test API endpoints for vulnerabilities
- Download CWE definitions

**Configuration:**
```json
{
  "fetch": {
    "command": "npx",
    "args": ["-y", "mcp-fetch-server@latest"]
  }
}
```

### 2. playwright (Local/npx)
**Purpose:** Browser automation and testing  
**Status:** ✅ Ready (no config needed)

**Example use cases for PyGuard:**
- Test XSS detection in real browsers
- Validate security scan reports (HTML output)
- Scrape security advisories
- Test CSRF protection

**Configuration:**
```json
{
  "playwright": {
    "command": "npx",
    "args": ["-y", "@playwright/mcp@latest"]
  }
}
```

### 3. context7 (HTTP)
**Purpose:** Up-to-date library documentation  
**Status:** ⚠️ Requires API key

**Supported libraries relevant to PyGuard:**
- Python stdlib (ast, pickle, subprocess, etc.)
- Security frameworks (OWASP, CWE)
- AST libraries
- Testing frameworks (pytest, unittest)
- Compliance standards documentation

**Configuration:**
```json
{
  "context7": {
    "url": "https://mcp.context7.com/mcp",
    "headers": {
      "Authorization": "Bearer ${COPILOT_MCP_CONTEXT7_API_KEY}"
    }
  }
}
```

**Example queries:**
- "Show me Python AST visitor pattern for security analysis"
- "What are the OWASP ASVS Level 2 requirements?"
- "Python pickle security best practices"

### 4. openai-websearch (Local/uvx)
**Purpose:** Web search for security research  
**Status:** ⚠️ Requires API key

**Example use cases:**
- Latest CVE information
- Current OWASP Top 10
- Security vulnerability research
- Emerging threat intelligence

**Configuration:**
```json
{
  "openai-websearch": {
    "command": "uvx",
    "args": ["openai-websearch-mcp"],
    "env": {
      "COPILOT_MCP_OPENAI_API_KEY": "${COPILOT_MCP_OPENAI_API_KEY}"
    }
  }
}
```

### 5. GitHub (Built-in)
**Purpose:** GitHub operations  
**Status:** ✅ Ready (OAuth-based, no config needed)

**Example capabilities:**
- List security-related issues
- Search for vulnerability patterns in code
- Trigger security scanning workflows
- Review security advisories

**Important:** ❌ **Do NOT configure GitHub MCP server manually**. It uses OAuth through Copilot's built-in integration.

---

## Security Considerations

### API Key Management
- ✅ Store keys as GitHub Secrets (encrypted at rest)
- ✅ Use repository secrets, not organization secrets (least privilege)
- ❌ Never commit API keys to version control
- ❌ Never log API keys in debug output

### Rate Limiting
- Context7: Free tier has rate limits (check your plan)
- OpenAI: Set billing limits to prevent unexpected costs
- Fetch/Playwright: Respect target site robots.txt and rate limits

### Data Privacy
- **Context7:** Sends library names/versions only (no code)
- **OpenAI:** Sends query text to OpenAI API (no code by default)
- **Fetch/Playwright:** You control what data is sent/retrieved
- **PyGuard principle:** All MCP servers respect zero-telemetry policy

---

## Example Workflows

### Security Research Workflow

1. **Find latest vulnerability:**
   ```
   @github Search web for "Python pickle deserialization CVE 2024"
   ```

2. **Get documentation:**
   ```
   @github Use Context7 to show Python pickle security documentation
   ```

3. **Test detection:**
   ```
   Create test case in PyGuard for the vulnerability
   ```

4. **Verify fix:**
   ```
   @github Use Playwright to test auto-fix in browser
   ```

### Compliance Workflow

1. **Research standard:**
   ```
   @github Search for "OWASP ASVS 5.0 authentication requirements"
   ```

2. **Get implementation guide:**
   ```
   @github Use Context7 for Python authentication best practices
   ```

3. **Check existing coverage:**
   ```
   @github Search PyGuard repo for OWASP ASVS implementation
   ```

---

## Troubleshooting

### Error: "Command not found: uvx"

**Cause:** `uv` not installed

**Fix:**
```bash
# macOS
brew install uv

# Ubuntu/Debian
curl -LsSf https://astral.sh/uv/install.sh | sh

# Verify
uvx --version
```

### Error: "Command not found: npx"

**Cause:** Node.js/npm not installed

**Fix:**
```bash
# macOS
brew install node

# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify
npx --version
```

### MCP Server Not Responding

**Debug steps:**
1. Check VS Code Output panel → GitHub Copilot
2. Verify config syntax: `cat .github/copilot-mcp.json | jq`
3. Test API keys:
   ```bash
   curl -H "Authorization: Bearer YOUR_KEY" https://mcp.context7.com/mcp/health
   ```

---

## Related Documentation

- **[Best Practices](best-practices.md)** — Production-grade development patterns
- **[Architecture](ARCHITECTURE.md)** — System design and data flow
- **[Security](../SECURITY.md)** — Security policies and disclosure
- **[Contributing](../CONTRIBUTING.md)** — Development guidelines

---

## Quick Reference

| Task | Command/Action |
|------|----------------|
| View config | `cat .github/copilot-mcp.json` |
| Add API key (local) | `export COPILOT_MCP_CONTEXT7_API_KEY="..."` |
| Test in Copilot | Open Copilot Chat, use `@github` |
| Check logs | VS Code → Output → GitHub Copilot |
| Validate JSON | `cat .github/copilot-mcp.json \| jq` |

---

**Need help?** See [Troubleshooting](#troubleshooting) or open an issue with relevant logs.
