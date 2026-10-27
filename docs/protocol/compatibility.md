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
  - Standard HTTP server listening on configured host and port (default: `127.0.0.1:8787/mcp`).
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

### 3.9 Process Isolation, Subprocess Permissions, Environment Forwarding & Disconnect Lifecycle

The stdio transport model introduces critical security and operating system process boundaries:

1. **Process Isolation & Subprocess Spawning:**
   - When configured in standalone mode to wrap an upstream tool executable (e.g. `npx @modelcontextprotocol/server-filesystem`), Veylith spawns the upstream process using Node.js `child_process.spawn` with `shell: false`.
   - By disabling the shell intermediary, argument parsing cannot be hijacked via command separators or metacharacters.
   - Standard I/O streams are strictly piped: the upstream's `stdout` and `stdin` are controlled solely by Veylith's internal client transport, while the upstream's `stderr` is captured and routed to Veylith's sanitized log stream.

2. **Subprocess Permissions & Command Validation (`validateCommand`):**
   - Commands are validated before execution:
     - Rejects any shell metacharacters in the executable name (`[;&|`$><\n\r]`).
     - Disallows bare shell binaries (`sh`, `bash`, `zsh`, `cmd.exe`, `powershell.exe`) when combined with inline execution flags (`-c`, `/c`, `-e`).
     - Rejects null bytes (`\0`) in any command arguments to prevent POSIX path truncation exploits.
   - Enforces a strict read buffer limit (default: 10 MB via `DEFAULT_MAX_BUFFER_SIZE`) to prevent memory exhaustion and denial-of-service from runaway child output.

3. **Environment-Variable Forwarding, Allowlisting & Secret Isolation (`getSafeChildEnvironment`):**
   - Veylith enforces a strict **default-deny** credential inheritance model.
   - The host application's raw `process.env` is never blindly passed to upstream child processes.
   - Forwarding starts from the official MCP SDK safe baseline (`getDefaultEnvironment()`, which includes only standard OS variables like `PATH`, `HOME`, `USER`, `SHELL`, `LANG`).
   - **Per-Server Credential Allowlisting:** Developers may authorize specific environment variable names for a specific trusted server via `ServerCredentialPolicy`.
   - **Strict Isolation:** Credentials authorized for Server A (e.g. `GITHUB_TOKEN`) are NEVER forwarded to Server B.
   - **Protected Variable Immutability:** Any attempt by child processes or configurations to override gateway internal variables (`GATEWAY_PORT`, `META_MODEL_API_KEY`, `FAIL_CLOSED`) is rejected with a fatal configuration error.
   - **Sanitized Errors:** If a required credential is missing, a sanitized error identifies the missing variable name without ever leaking secret values or exposing them to logs or LLMs.

4. **Behavior on Disconnect & Teardown Lifecycle:**
   - **Client Disconnect (stdin EOF):** When Claude Desktop, Cursor, or a client terminates, the operating system closes the stdin pipe. The adapter detects `process.stdin.on('end')` and initiates a graceful teardown:
     - Closes all active upstream client connections (`this.activeUpstreamClients.forEach(c => c.close())`), which sends SIGTERM to child processes.
     - Closes the server handle.
     - Flushes remaining log messages to stderr.
     - Exits the process cleanly with code `0`.
   - **Signal Handling:** Listens for `SIGINT` and `SIGTERM` to ensure upstream subprocesses are never orphaned.
   - **Subprocess Exit:** If the upstream child process crashes or terminates unexpectedly, Veylith catches the error, logs a sanitized message to stderr, and returns `isError: true` on subsequent tool calls rather than crashing the client session.

5. **Honest Subprocess Security: Application Mediation vs. True OS Sandboxing:**
   Veylith clearly delineates what application-level mediation provides versus true operating system isolation:
   - **Command Validation:** Verifies executable names, rejects shell metacharacters, and disallows inline shell execution flags (`-c`, `/c`, `-e`).
   - **Environment Filtering:** Default-deny stripping of API keys and per-server allowlisting.
   - **Process Lifecycle Management:** Graceful termination, buffer capping, and orphan prevention on stdin EOF.
   - **OS Sandboxing Boundary:** Veylith does **not** claim that `shell: false` or command filtering provides kernel-level sandboxing. Once a valid binary is spawned, it executes under the host user's local operating system identity with the user's filesystem and network privileges. True host isolation requires OS-level containerization (e.g. Docker, Linux namespaces/seccomp, or microVMs). Veylith provides protocol-level mediation and argument inspection, not kernel virtualization.

---

### 3.10 Unsupported Capabilities & Explicit Protocol Behaviors

Veylith currently supports the core tool execution subset of MCP (tools, initialization, cancellation, and ping). The following capabilities are unsupported in Phase 2B:

| Capability                    | Phase Status         | Rationale & Gateway Behavior                                                                                                                                                                                                                                                                     |
| :---------------------------- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`resources/list` & `read`** | _Planned (Phase 2C)_ | Resources represent passive text/binary data (e.g. files, database schemas). While non-executable, retrieved resource content can contain indirect prompt injection. Resource inspection will be introduced in Phase 2C. Requests currently receive standard JSON-RPC `-32601 Method Not Found`. |
| **`resources/subscribe`**     | _Planned (Phase 2C)_ | Push notifications for resource updates. Unsupported in Phase 2B; calls return `-32601 Method Not Found`.                                                                                                                                                                                        |
| **`prompts/list` & `get`**    | _Planned (Phase 2C)_ | MCP Prompt templates will be supported in Phase 2C with static and semantic security scanning of prompt parameters. Unsupported in Phase 2B; calls return `-32601 Method Not Found`.                                                                                                             |
| **`sampling/createMessage`**  | _Out of Scope_       | Server-to-client LLM sampling allows an MCP server to request LLM generations from the client. As a security perimeter, Veylith does not solicit LLM sampling from clients, as this introduces bidirectional trust inversion. If requested by an upstream server, Veylith drops the capability.  |
| **`roots/list`**              | _Out of Scope_       | Client filesystem root boundary reporting. Not required for gateway security mediation.                                                                                                                                                                                                          |

---

## 4. Client Verification & Interoperability Matrix

| Client / Environment                                         | Transport               | Verification Status            | Configuration Mechanism                                           | Verification Evidence & Scope                                                                                                                         |
| :----------------------------------------------------------- | :---------------------- | :----------------------------- | :---------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Official MCP SDK Client** (`@modelcontextprotocol/client`) | stdio & Streamable HTTP | **Fully Verified (Automated)** | SDK programmatic client (`StdioClientTransport`)                  | Automated integration suite (`tests/integration/stdio-adapter.test.ts` & `scripts/demo-real-client.ts`). All 11 lifecycle scenarios passing.          |
| **Claude Desktop**                                           | stdio                   | **Pending Founder GUI Test**   | `~/Library/Application Support/Claude/claude_desktop_config.json` | Protocol, lifecycle, and stdio launcher validated via headless SDK harness; actual GUI interactive testing pending founder execution on host machine. |
| **Cursor**                                                   | stdio                   | **Pending Founder GUI Test**   | `.cursor/mcp.json` or `~/.cursor/mcp.json`                        | Protocol, lifecycle, and stdio launcher validated via headless SDK harness; actual GUI interactive testing pending founder execution on host machine. |
| **Windsurf / Cline / Zed**                                   | stdio                   | **Untested (Theoretical)**     | Standard MCP stdio server entry                                   | Syntactically compliant with MCP stdio JSON-RPC 2.0 specification; no active automated or manual tests performed.                                     |

---

## 5. Packaging Architecture, Runtime Portability & Current Packaging Limitations

### 5.1 Architecture & Standalone Bundling

To enable non-developer users and GUI clients to run Veylith without requiring local TypeScript compilers (`tsx`, `ts-node`), a custom esbuild pipeline bundles the stdio adapter into a self-contained ES module:

- **Source:** `apps/stdio-adapter/src/index.ts`
- **Output:** `apps/stdio-adapter/dist/standalone.mjs` (258 KB)
- **Inlined Modules:** `@veylith/core`, `@veylith/policy-engine`, `@veylith/meta-adapter` (all monorepo packages are compiled and bundled directly into `standalone.mjs`).
- **External Dependencies:** Only official MCP SDK packages (`@modelcontextprotocol/server`, `@modelcontextprotocol/client`, `@modelcontextprotocol/sdk`) and Node built-in modules (`node:*`) remain as runtime imports.

### 5.2 Standalone Launcher (`bin/veylith-stdio.js`)

The launcher script provides multi-tier resolution:

1. **Production Mode (Zero Dev Tooling):** Detects `dist/standalone.mjs` and invokes it directly using pure `node` (`process.execPath`). Runs with zero TypeScript development tools.
2. **Development Fallback:** If `standalone.mjs` is not present, falls back to local `tsx` if installed in `node_modules`.
3. **Native Node Type Stripping:** On modern Node.js versions (>= 22.6), falls back to `--experimental-strip-types`.

### 5.3 Current Packaging Limitations

1. **Local Monorepo Dependency Resolution:** In the current Phase 2B development state, the standalone bundle relies on the project's `node_modules` for external peer packages (`@modelcontextprotocol/server`, `@modelcontextprotocol/client`, `zod`). On an end-user machine without this repository cloned, the bundle cannot run until packaged for distribution.
2. **NPM Distribution Prerequisite (Planned):** For production distribution to general end users, Veylith will be published as an npm package (`veylith-stdio`) with bundled or declared runtime dependencies, allowing global installation via `npm install -g @veylith/stdio-adapter` or direct execution via `npx -y @veylith/stdio-adapter`.
3. **Node.js Runtime Requirement:** Veylith requires Node.js v20.0.0 or higher. It is not currently compiled as a single native executable (e.g. Node SEA / Single Executable Application or Bun standalone binary).
4. **Platform Testing:** Process spawning and signal handling have been thoroughly validated on macOS (Darwin arm64/x64) and Linux; Windows support relies on standard Node.js cross-platform process semantics but has not been verified on Windows hardware.
