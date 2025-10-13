#!/bin/bash
# MCP Configuration Validator
# Validates the GitHub Copilot MCP server configuration

set -e

CONFIG_FILE=".github/copilot-mcp.json"
echo "🔍 Validating MCP Configuration: $CONFIG_FILE"
echo ""

# Check if file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Validate JSON syntax
echo "1️⃣  Validating JSON syntax..."
if jq empty "$CONFIG_FILE" 2>/dev/null; then
    echo "   ✅ JSON syntax is valid"
else
    echo "   ❌ JSON syntax is invalid"
    exit 1
fi

# Check required structure
echo ""
echo "2️⃣  Checking configuration structure..."

# Check mcpServers key exists
if jq -e '.mcpServers' "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "   ✅ mcpServers key found"
else
    echo "   ❌ mcpServers key missing"
    exit 1
fi

# Validate each server configuration
echo ""
echo "3️⃣  Validating server configurations..."

# Context7 validation
echo "   📡 Context7 (HTTP server):"
if jq -e '.mcpServers.context7' "$CONFIG_FILE" >/dev/null 2>&1; then
    # Check Authorization header format
    AUTH_HEADER=$(jq -r '.mcpServers.context7.headers.Authorization // empty' "$CONFIG_FILE")
    if [[ "$AUTH_HEADER" == Bearer\ \$\{*\} ]] || [[ "$AUTH_HEADER" == Bearer\ \$* ]]; then
        echo "      ✅ Authorization header format is correct (Bearer token)"
    else
        echo "      ❌ Authorization header should use 'Bearer \${ENV_VAR}' or 'Bearer \$ENV_VAR' format"
        echo "         Current: $AUTH_HEADER"
        exit 1
    fi
else
    echo "      ⚠️  Context7 server not configured"
fi

# OpenAI Web Search validation
echo "   🔍 OpenAI Web Search (Local server):"
if jq -e '.mcpServers["openai-websearch"]' "$CONFIG_FILE" >/dev/null 2>&1; then
    # Check environment variable format
    OPENAI_KEY=$(jq -r '.mcpServers["openai-websearch"].env.OPENAI_API_KEY // empty' "$CONFIG_FILE")
    if [[ "$OPENAI_KEY" == \$\{*\} ]] || [[ "$OPENAI_KEY" == \$* ]]; then
        echo "      ✅ Environment variable reference is correct (\$ prefix)"
    else
        echo "      ❌ Environment variable should use '\${ENV_VAR}' or '\$ENV_VAR' format"
        echo "         Current: $OPENAI_KEY"
        exit 1
    fi
    
    # Check uvx command availability
    if command -v uvx >/dev/null 2>&1; then
        echo "      ✅ uvx command available"
    else
        echo "      ⚠️  uvx command not found (may affect server startup)"
    fi
else
    echo "      ⚠️  OpenAI Web Search server not configured"
fi

# Fetch validation
echo "   🌐 Fetch (Local server):"
if jq -e '.mcpServers.fetch' "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "      ✅ Fetch server configured"
    
    # Check npx command availability
    if command -v npx >/dev/null 2>&1; then
        echo "      ✅ npx command available"
    else
        echo "      ⚠️  npx command not found (required for server startup)"
    fi
else
    echo "      ⚠️  Fetch server not configured"
fi

# Playwright validation
echo "   🎭 Playwright (Local server):"
if jq -e '.mcpServers.playwright' "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "      ✅ Playwright server configured"
    
    # Check npx command availability
    if command -v npx >/dev/null 2>&1; then
        echo "      ✅ npx command available"
    else
        echo "      ⚠️  npx command not found (required for server startup)"
    fi
else
    echo "      ⚠️  Playwright server not configured"
fi

echo ""
echo "4️⃣  Summary:"
SERVER_COUNT=$(jq '.mcpServers | length' "$CONFIG_FILE")
echo "   📊 Total servers configured: $SERVER_COUNT"
echo ""
echo "✅ MCP configuration validation passed!"
echo ""
echo "📝 Note: Actual server connectivity depends on:"
echo "   - Environment variables being set (COPILOT_MCP_*)"
echo "   - Network connectivity to external servers"
echo "   - Required tools being installed (uvx, npx)"
