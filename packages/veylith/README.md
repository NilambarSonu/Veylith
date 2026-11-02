# veylith

> **AI-agent security gateway for Model Context Protocol (MCP)**

[![npm version](https://img.shields.io/npm/v/veylith.svg)](https://www.npmjs.com/package/veylith)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/NilambarSonu/Veylith/blob/main/LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io)

Veylith sits as a transparent proxy between AI agent clients (Claude Desktop, Cursor, Cline, custom MCP agents) and upstream MCP servers. It enforces deterministic and semantic security inspection across every protocol phase—blocking prompt injection, intercepting hazardous tool arguments, sanitizing malicious schema descriptions, and quarantining suspicious response payloads.

---

## Key Features

- **Triple-Stage Inspection Boundary**:
  1. **Discovery Inspection** (`tools/list`): Sanitizes tool descriptions and schemas to prevent prompt injection and shadow instructions from reaching the agent context.
  2. **Argument Inspection** (`tools/call` outbound): Evaluates agent parameters against deterministic regex patterns and optional semantic models before upstream tools are executed.
  3. **Response Inspection** (`tools/call` return): Scans tool execution results for exfiltration payloads, prompt overrides, and system prompt extractors, applying field-level sanitization or full quarantine before delivering data to the agent.
- **Zero Protocol Overhead**: Implements standard MCP stdio transport. AI agents connect to Veylith exactly like any native MCP server.
- **Cryptographic Tamper-Evident Audit Chain**: Logs every decision (`ALLOW`, `BLOCK`, `REVIEW`, `QUARANTINE`) with SHA-256 hash chaining for compliance auditing.
- **Zero Config by Default**: Operates out of the box with bundled deterministic security rules without requiring external API keys.

---

## Quickstart

### 1. Instant Execution with `npx` (No Installation Required)

Wrap any existing stdio MCP server command with `veylith` using `--`:

```bash
npx veylith -- npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/directory
```

### 2. Global Installation

```bash
npm install -g veylith

# Run directly
veylith -- npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/directory
```

---

## Client Integration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "filesystem-protected": {
      "command": "npx",
      "args": [
        "-y",
        "veylith",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}
```

### Cursor

Add to your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem-protected": {
      "command": "npx",
      "args": [
        "-y",
        "veylith",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/directory"
      ]
    }
  }
}
```

---

## CLI Reference

```
Usage:
  veylith [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]
  veylith-stdio [OPTIONS] [-- UPSTREAM_COMMAND [UPSTREAM_ARGS...]]

Modes:
  1. Standalone Subprocess (Recommended)
     Runs Veylith's 3-stage security boundary in-process and wraps an upstream tool command.
     Example: veylith -- npx -y @modelcontextprotocol/server-filesystem /tmp

  2. Gateway Bridge
     Bridges downstream stdio to a running Veylith HTTP Gateway instance.
     Example: veylith --gateway-url http://127.0.0.1:8787/mcp

  3. Standalone HTTP
     Runs Veylith in-process and mediates an upstream MCP HTTP server.
     Example: veylith --upstream-url http://127.0.0.1:8788/mcp

Options:
  --gateway-url <url>      URL of Veylith Gateway (default: http://127.0.0.1:8787/mcp)
  --upstream-url <url>     URL of upstream MCP HTTP server (standalone mode)
  --command <cmd>          Executable command for upstream MCP server (standalone mode)
  --args <args>            Comma-separated arguments for upstream command
  --blocked-tools <list>   Comma-separated list of tool names to block
  --log-level <level>      Log level: debug, info, warn, error (default: info)
  --fail-closed <bool>     Block requests if security evaluation fails (default: true)
  --max-buffer-size <size> Maximum stdio buffer size in bytes (default: 10485760)
  --meta-mode <mode>       Meta AI mode: mock | live (default: mock)
  -h, --help               Show help message
```

---

## Security Boundary & Responsible Disclosure

> **Research Alpha Notice**  
> Veylith `0.1.0-alpha.1` is a defense-in-depth security layer. It does not replace OS-level sandboxing, container isolation, or strict process permissions. Always run upstream MCP tools with minimal required operating system privileges.

For technical documentation, benchmark evidence, and architectural specifications, visit the [Veylith Repository](https://github.com/NilambarSonu/Veylith).
