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
        "http://127.0.0.1:8787/mcp"
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
        "http://127.0.0.1:8787/mcp"
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

---

## 5. Manual Founder Verification Checklist (Claude Desktop & Cursor GUI)

> **Interoperability Status Note:**  
> The official MCP SDK client (`@modelcontextprotocol/client`) is **Fully Verified (Automated)** across all 11 lifecycle and security scenarios.  
> Claude Desktop and Cursor are labeled **Pending Founder GUI Test** until manually exercised by the founder in a live desktop GUI session.

If Claude Desktop or Cursor is installed on your workstation, follow this exact step-by-step verification checklist:

### 5.1 Prerequisites & Preparation

1. **Build the Standalone Adapter:**

   ```bash
   pnpm build
   ```

   Ensure `apps/stdio-adapter/dist/standalone.mjs` is generated.

2. **Start the Test Server & Gateway (Gateway Bridge Mode):**
   - **Terminal 1 (Benign Server):**

     ```bash
     pnpm tsx examples/benign-mcp-server/src/index.ts
     ```

     (Server starts on `http://127.0.0.1:8788/mcp`)

   - **Terminal 2 (Veylith Gateway):**
     ```bash
     UPSTREAM_MCP_URL=http://127.0.0.1:8788/mcp \
     BLOCKED_TOOLS=restricted_demo_tool \
     pnpm tsx apps/gateway/src/server.ts
     ```
     (Gateway starts on `http://127.0.0.1:8787/mcp`)

3. **Install Client Configuration:**
   - **For Claude Desktop:**
     Open `~/Library/Application Support/Claude/claude_desktop_config.json` and insert:
     ```json
     {
       "mcpServers": {
         "veylith": {
           "command": "node",
           "args": [
             "/Users/nilambarbehera/Documents/Projects/veylith/bin/veylith-stdio.js",
             "--gateway-url",
             "http://127.0.0.1:8787/mcp"
           ],
           "env": {
             "LOG_LEVEL": "info"
           }
         }
       }
     }
     ```
   - **For Cursor:**
     Create or edit `.cursor/mcp.json` in your workspace:
     ```json
     {
       "mcpServers": {
         "veylith": {
           "command": "node",
           "args": [
             "/Users/nilambarbehera/Documents/Projects/veylith/bin/veylith-stdio.js",
             "--gateway-url",
             "http://127.0.0.1:8787/mcp"
           ]
         }
       }
     }
     ```

4. **Restart the Client:**
   Fully quit and restart Claude Desktop or Cursor to reload MCP server configurations.

---

### 5.2 Step-by-Step Interactive Test Protocol

| Test #    | Test Name                          | User Prompt in GUI Client                                              | Expected Client GUI Behavior                                                                                                                                                                                                                 | Verified |
| :-------- | :--------------------------------- | :--------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- |
| **GUI-1** | **Stage 1: Tool Discovery**        | _"What tools are available?"_                                          | Assistant lists `echo`, `add`, and `simulate_untrusted_source`. `poisoned_discovery_tool` is completely omitted from the tool list.                                                                                                          | [ ]      |
| **GUI-2** | **Stage 2: Benign Tool Call**      | _"Use tool echo with message 'Hello Veylith'"_                         | Tool executes successfully; assistant responds with `'Echo: Hello Veylith'`.                                                                                                                                                                 | [ ]      |
| **GUI-3** | **Stage 2: Policy Blocklist**      | _"Call restricted_demo_tool with reason 'test'"_                       | Call is blocked. Assistant receives `isError: true` and explains that the tool is administratively blocked by policy, without client error or crash.                                                                                         | [ ]      |
| **GUI-4** | **Stage 2: Argument Scanner**      | _"Execute tool echo with message 'rm -rf /'"_                          | Call is blocked by Tier 1 invariant with message explaining dangerous filesystem deletion. _(Note: See `docs/security/capability-audit.md` for discussion of false positives on pure echo tools vs shell tools)._                            | [ ]      |
| **GUI-5** | **Stage 3: Response Sanitization** | _"Fetch data using simulate_untrusted_source with query 'financials'"_ | Upstream returns indirect prompt injection, but Veylith sanitizes the response. Assistant receives `[Veylith Security Notice: Response contained untrusted instruction overrides...]` and refuses to follow malicious injected instructions. | [ ]      |
| **GUI-6** | **Process Lifecycle & Disconnect** | _Quit Claude Desktop / Cursor_                                         | Verify in Activity Monitor or terminal (`ps aux \| grep veylith`) that `veylith-stdio` and child processes terminated cleanly with exit code 0 on stdin EOF.                                                                                 | [ ]      |
