# Real Client MCP Integration Guide

This guide details how to integrate **Veylith — The AI Agent Security Boundary** with real MCP-enabled developer clients, including **Claude Desktop**, **Cursor**, and custom CLI agent runtimes.

---

## 1. Overview & Architecture

Veylith sits transparently between your MCP client and upstream MCP tool providers (such as filesystem servers, GitHub, databases, or terminal tools).

```
+--------------------+        stdio (JSON-RPC)        +------------------------+
|                    | -----------------------------> |                        |
|  Claude Desktop /  |                                |  Veylith Stdio Adapter |
|  Cursor / CLI Agent| <----------------------------- |     (veylith-stdio)    |
|                    |     stdout ONLY (logs: stderr) |                        |
+--------------------+                                +-----------+------------+
                                                                  |
                                              3-Stage Security    | Streamable HTTP
                                              Inspection Pipeline | or stdio spawn
                                                                  v
                                                      +------------------------+
                                                      |   Upstream MCP Tool    |
                                                      |  Server (e.g., Files)  |
                                                      +------------------------+
```

### Key Security Invariants

- **Stdout Integrity**: Only valid JSON-RPC 2.0 messages are emitted to stdout.
- **Stderr Logging**: All security evaluations and audit logs are routed strictly to stderr.
- **Secret Isolation**: Credential values and tokens are automatically scrubbed from logs.
- **Zero-Crash Policy Feedback**: Security violations return protocol-compliant `CallToolResult` with `isError: true`, providing explainable policy context to the LLM without crashing the client transport.

---

## 2. Configuration for Claude Desktop

Claude Desktop connects to local MCP servers via its configuration file.

### Configuration File Location

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Mode A: Gateway Bridge Mode (Recommended for Teams)

Run the Veylith Gateway daemon locally (`pnpm start` or docker), then configure Claude Desktop to connect via the adapter:

```json
{
  "mcpServers": {
    "veylith-protected-tools": {
      "command": "node",
      "args": [
        "/Users/nilambarbehera/Documents/Projects/veylith/bin/veylith-stdio.js",
        "--gateway-url",
        "http://127.0.0.1:3000/mcp"
      ],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Mode B: Standalone Subprocess Mode (Zero Daemon)

Wraps any existing MCP server (e.g. `@modelcontextprotocol/server-filesystem`) with Veylith security directly inside Claude Desktop without running a background gateway:

```json
{
  "mcpServers": {
    "protected-filesystem": {
      "command": "node",
      "args": [
        "/Users/nilambarbehera/Documents/Projects/veylith/bin/veylith-stdio.js",
        "--blocked-tools",
        "delete_file,format_disk",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/nilambarbehera/Documents/Projects/veylith"
      ],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

---

## 3. Configuration for Cursor

Cursor supports MCP servers configured via workspace or global configuration.

### Configuration File Location

- **Workspace**: `.cursor/mcp.json` (inside project root)
- **User Global**: `~/.cursor/mcp.json`

### Cursor Configuration (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "veylith-boundary": {
      "command": "node",
      "args": [
        "/Users/nilambarbehera/Documents/Projects/veylith/bin/veylith-stdio.js",
        "--gateway-url",
        "http://127.0.0.1:3000/mcp"
      ]
    }
  }
}
```

---

## 4. Verification with Harmless Local Test Server

Before connecting to sensitive production tools, verify the integration using Veylith's harmless local test server:

### Step 1: Start the Benign Test Server & Gateway

Terminal 1:

```bash
# Start benign server
pnpm tsx examples/benign-mcp-server/src/index.ts
```

Terminal 2:

```bash
# Start Veylith gateway with blocked demo tool
UPSTREAM_MCP_URL=http://127.0.0.1:8788/mcp \
BLOCKED_TOOLS=restricted_demo_tool \
pnpm tsx apps/gateway/src/server.ts
```

### Step 2: Run the Automated Demonstration

Terminal 3:

```bash
pnpm demo:client
```

This verifies the three core workflows:

1. **Workflow A (Normal Request)**: Harmless `echo` call succeeds.
2. **Workflow B (Restricted Invocation)**: `restricted_demo_tool` is blocked by policy (`isError: true`).
3. **Workflow C (Prompt Injection Interception)**: `poisoned_discovery_tool` is dropped from discovery, and indirect injection in `simulate_untrusted_source` is sanitized before reaching the client.

---

## 5. Manual Founder Verification Checklist

For founder manual testing in Claude Desktop or Cursor GUI:

- [ ] **Config Check**: Add the configuration block above to `claude_desktop_config.json` or `.cursor/mcp.json`.
- [ ] **Restart Client**: Fully quit and restart Claude Desktop / Cursor.
- [ ] **Discovery Check**: Ask the assistant "What MCP tools are available?". Verify that `echo` and `add` are listed, while `poisoned_discovery_tool` is absent.
- [ ] **Normal Execution Check**: Ask "Echo 'hello Veylith'". Verify the response is received.
- [ ] **Policy Enforcement Check**: Ask "Execute tool echo with argument rm -rf /". Verify the assistant receives the policy block message and does not execute.
- [ ] **Status**: _Pending Founder Manual GUI Test_. Automated headless stdio tests verified and passing.
