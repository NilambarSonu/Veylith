# Veylith Protocol & Transport Compatibility (Phase 2B)

## 1. Executive Summary & Specification Alignment

Veylith — The AI Agent Security Boundary operates as a security-enforcing Model Context Protocol (MCP) gateway and stdio proxy. It implements protocol compliance against the official Model Context Protocol specifications and uses the official modular TypeScript SDK v2 (`@modelcontextprotocol/server` ^2.4.0 and `@modelcontextprotocol/client` ^2.4.0).

Veylith acts as an inline security boundary between downstream MCP clients (such as Claude Desktop, Cursor, and custom agent runtimes) and upstream MCP tool providers (such as filesystem, database, developer tools, or cloud APIs).

---

## 2. Specification & Package Matrix

| Dimension             | Specification / Version                   | Status in Phase 2B            | Details & Reference                                          |
| :-------------------- | :---------------------------------------- | :---------------------------- | :----------------------------------------------------------- |
| **MCP Specification** | 2026-07-28 revision & 2024-11-05 legacy   | **Fully Supported**           | Supports both modern 2026 envelope and 2024/2025 legacy mode |
| **Server SDK**        | `@modelcontextprotocol/server` ^2.4.0     | **Integrated**                | Official modular SDK v2 (`McpServer`, `serveStdio`)          |
| **Client SDK**        | `@modelcontextprotocol/client` ^2.4.0     | **Integrated**                | Official modular SDK v2 (`Client`, `StdioClientTransport`)   |
| **Runtime Target**    | Node.js `>=20.0.0` (tested on `v24.21.0`) | **Tested & Verified**         | Strict ES2022 / Node16 ESM resolution                        |
| **Transports**        | Streamable HTTP & stdio                   | **Both Supported in Gateway** | HTTP gateway + stdio client adapter binary                   |
| **Validation**        | Zod `^4.2.0`                              | **Enforced**                  | Schema and payload type validation                           |

---

## 3. Protocol Feature Analysis: Supported vs. Unsupported

### 3.1 Transports

#### Streamable HTTP Transport

- **Status:** **Supported (Gateway Default)**
- **Mechanics:**
  - Standard HTTP server listening on configured host and port (default: `127.0.0.1:3000/mcp`).
  - Supports `POST` (JSON-RPC requests/notifications) and `GET` (stream connection/discovery).
  - Handles HTTP headers (`Accept: application/json, text/event-stream`, `Content-Type: application/json`).
  - Implements response streaming via Web Standard `ReadableStream` reader pump to Node.js `http.ServerResponse`, preventing infinite buffer accumulation.
- **Client Support:** Works with any MCP client supporting HTTP endpoints.

#### stdio Transport

- **Status:** **Supported (Stdio Adapter in Phase 2B)**
- **Mechanics:**
  - Client communicates over standard I/O (`process.stdin` and `process.stdout`).
  - Utilizes `@modelcontextprotocol/server/stdio` (`serveStdio` and `StdioServerTransport`).
  - **Stdout Integrity Rule:** `stdout` is exclusively reserved for valid newline-delimited JSON-RPC 2.0 messages. Zero diagnostic or log output is ever emitted to stdout.
  - **Stderr Logging:** All diagnostics, security evaluation logs, and debug information are routed strictly to `process.stderr`.
  - **Bounded Buffers:** Uses SDK `ReadBuffer` with a 10 MB maximum buffer size (`STDIO_DEFAULT_MAX_BUFFER_SIZE`) to protect against buffer exhaustion denial-of-service.
  - **Safe Process Lifecycle:** Monitors stdin `end` and `close` events; upon client disconnect or `SIGINT`/`SIGTERM`, performs graceful teardown of upstream connections and exits cleanly.

#### Legacy HTTP+SSE Transport

- **Status:** **Unsupported (Explicitly Deprecated)**
- **Rationale:** Legacy separate HTTP POST and SSE GET transports are superseded by modern Streamable HTTP in the official MCP specification.

---

### 3.2 Initialization & Protocol Negotiation

#### Initialization Handshake (`initialize`)

- **Status:** **Supported**
- **Flow:**
  1. Downstream client sends `initialize` request containing:
     - `protocolVersion`: e.g. `'2024-11-05'` or `'2026-07-28'`.
     - `capabilities`: client capabilities (e.g., `roots`, `sampling`, `experimental`).
     - `clientInfo`: `{ name: string, version: string }`.
  2. Veylith responds with:
     - `protocolVersion`: negotiated version matching the client.
     - `capabilities`: `{ tools: { listChanged?: boolean } }`.
     - `serverInfo`: `{ name: 'veylith-gateway' | 'veylith-stdio-adapter', version: '0.1.0' }`.
  3. Client sends `notifications/initialized`.

#### Protocol Version Negotiation

- **Status:** **Supported**
- **Mechanics:**
  - The stdio adapter and gateway employ `serveStdio` / `createMcpHandler` configured with `legacy: 'serve'`.
  - When legacy clients (such as Claude Desktop or Cursor sending `2024-11-05`) connect without `_meta` envelope claims, Veylith automatically pins the connection to the legacy era.
  - When modern clients (sending `2026-07-28`) connect with `_meta` claims, Veylith validates the per-request envelope and serves modern semantics.

---

### 3.3 Core MCP Methods: `tools/list` and `tools/call`

#### Discovery (`tools/list`)

- **Status:** **Supported with Security Inspection (Stage 1)**
- **Behavior:**
  - Upstream tools are fetched via the upstream MCP client.
  - Veylith's `SecurityInspectionEngine.inspectDiscovery()` evaluates tool descriptions, parameter schemas, and metadata against deterministic invariants, heuristic screener, and semantic classification.
  - Tools exhibiting **tool-description poisoning** (embedded `SYSTEM INSTRUCTION:`, hidden exfiltration URLs, privilege escalation prompts) or matching configured blocklists are dropped.
  - Downstream clients receive a standard, valid `tools/list` response containing only verified clean tools.
  - If a client attempts to invoke a dropped tool, the gateway returns standard JSON-RPC `-32601` (Method not found).

#### Tool Execution (`tools/call`)

- **Status:** **Supported with Security Inspection (Stages 2 & 3)**
- **Behavior:**
  - **Stage 2: Argument Inspection (Pre-Execution):**
    - Client sends `tools/call` with tool name and arguments.
    - Evaluated against Tier 1 deterministic rules (e.g. destructive commands `rm -rf`, SQL injection, directory traversal), Tier 2 heuristic screener, and Tier 3 semantic engine.
    - If blocked: Upstream is never called. Veylith returns a protocol-compliant `CallToolResult` with `isError: true` and an explainable security message:
      ```json
      {
        "content": [{ "type": "text", "text": "Veylith policy blocked this call: [Reason]" }],
        "isError": true
      }
      ```
  - **Stage 3: Response Inspection (Post-Execution):**
    - If arguments are allowed, request is forwarded to upstream MCP tool server.
    - Upstream output is inspected for indirect prompt injection and secret/credential leakage.
    - If an injection is detected, malicious content is redacted and replaced with a clean security notice (`[Veylith Security Notice]...`), and `isError: true` is flagged to prevent poisoning the agent context window.

---

### 3.4 MCP Session Lifecycle & State Management

- **HTTP Gateway Mode:**
  - Operates statelessly per-request.
  - Each request connects to upstream or reuses an established pool, ensuring zero state contamination between separate client sessions.
  - Multi-tenant inspection cache keys cryptographically bind `(stage, policyVersion, modelVersion, serverId, clientId, toolName, payloadHash)` to prevent unsafe verdict reuse.
- **stdio Adapter Mode:**
  - Operates with 1:1 process affinity. The adapter is spawned directly by the local client process (Claude Desktop or Cursor).
  - Pinned connection lifetime matches the client process lifetime.
  - On EOF or process termination, child processes and open handles are torn down.

---

### 3.5 Cancellation and Timeouts

- **Cancellation (`notifications/cancelled`):**
  - **Status:** **Supported**
  - Downstream client sends `notifications/cancelled` with `{ requestId: string | number, reason?: string }`.
  - Stdio adapter settles pending request waiters immediately.
  - In-flight upstream HTTP requests are aborted via standard `AbortController`/`AbortSignal`.
- **Timeouts:**
  - **Status:** **Supported**
  - Client request timeout defaults to 60,000 ms.
  - Upstream calls obey configurable timeouts; if an upstream tool hangs or is unreachable, Veylith returns `isError: true` with `Veylith gateway: upstream server unavailable`.

---

### 3.6 Error Propagation & Codes

Veylith adheres strictly to MCP and JSON-RPC 2.0 error specifications:

| Error Type                | Code / Structure                      | Veylith Handling                                                              |
| :------------------------ | :------------------------------------ | :---------------------------------------------------------------------------- |
| **Parse Error**           | `-32700`                              | Emitted when client or upstream sends unparseable JSON                        |
| **Invalid Request**       | `-32600`                              | Emitted when JSON-RPC message structure is invalid                            |
| **Method Not Found**      | `-32601`                              | Emitted when requesting an unknown tool or tool filtered out in discovery     |
| **Invalid Params**        | `-32602`                              | Emitted when arguments fail schema validation                                 |
| **Internal Error**        | `-32603`                              | Emitted on unhandled upstream errors or subscription limits                   |
| **Policy Security Block** | `CallToolResult` with `isError: true` | In-band error response returning explainable policy text to LLM without crash |
| **Sanitized Response**    | `CallToolResult` with `isError: true` | In-band redacted response neutralizing indirect prompt injection              |
| **Upstream Unavailable**  | `CallToolResult` with `isError: true` | Returns descriptive error message rather than unhandled exception             |

---

### 3.7 Client Authentication & Process Boundaries

- **Streamable HTTP:**
  - Supports standard HTTP authorization headers (`Authorization: Bearer <token>`, custom API keys).
  - Secret redaction ensures that credentials are never stored or logged in plaintext.
- **stdio Transport:**
  - Authentication boundary is the local operating system process boundary. The client spawns the adapter under the user's local operating system identity.
  - Inherits only safe environment variables via `getDefaultEnvironment()`.
  - Upstream subprocess execution is strictly validated: shell chaining (`;`, `&&`, `|`), arbitrary shell interpretation (`sh`, `bash -c`), and path traversal are rejected.

---

### 3.8 Server Capabilities & Notifications Summary

| MCP Feature                 | Status in Phase 2B   | Notes / Future Roadmap                                          |
| :-------------------------- | :------------------- | :-------------------------------------------------------------- |
| `tools/list`                | **Fully Supported**  | Stage 1 discovery inspection (filters poisoned tools)           |
| `tools/call`                | **Fully Supported**  | Stages 2 & 3 inspection (blocks args, sanitizes responses)      |
| `notifications/initialized` | **Fully Supported**  | Handshake completion                                            |
| `notifications/cancelled`   | **Fully Supported**  | Request cancellation propagation                                |
| `ping`                      | **Fully Supported**  | Protocol heartbeat                                              |
| `resources/list` & `read`   | _Planned (Phase 2C)_ | Resource retrieval inspection                                   |
| `resources/subscribe`       | _Planned (Phase 2C)_ | Subscription change monitoring                                  |
| `prompts/list` & `get`      | _Planned (Phase 2C)_ | Prompt template security scanning                               |
| `sampling/createMessage`    | _Out of Scope_       | Server-initiated client sampling; not required for gateway role |
| `roots/list`                | _Out of Scope_       | Client filesystem root reporting                                |

---

## 4. Real-Client Compatibility Matrix

| Client                  | Transport  | Support Status | Configuration Mechanism                                           | Notes                                                 |
| :---------------------- | :--------- | :------------- | :---------------------------------------------------------------- | :---------------------------------------------------- |
| **Claude Desktop**      | stdio      | **Compatible** | `~/Library/Application Support/Claude/claude_desktop_config.json` | Tested with `veylith-stdio` executable                |
| **Cursor**              | stdio      | **Compatible** | `~/.cursor/mcp.json` or `.cursor/mcp.json`                        | Tested with `veylith-stdio` executable                |
| **Official MCP Client** | stdio/HTTP | **Compatible** | `@modelcontextprotocol/client` (v2.4.0)                           | Used for automated integration and regression testing |
| **Windsurf / Cline**    | stdio      | **Compatible** | Standard MCP stdio configuration block                            | Conforms to standard stdio JSON-RPC protocol          |
