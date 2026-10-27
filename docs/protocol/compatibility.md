# Veylith Protocol & Transport Compatibility (Phase 1)

## Overview

Veylith targets the modern Model Context Protocol (MCP) specification using official TypeScript SDK v2 packages (`@modelcontextprotocol/server` & `@modelcontextprotocol/client`).

---

## Specification & Package Matrix

| Dimension             | Value / Specification                     | Notes                          |
| :-------------------- | :---------------------------------------- | :----------------------------- |
| **MCP Specification** | 2026-07-28 revision                       | Modern protocol standard       |
| **Server SDK**        | `@modelcontextprotocol/server` ^2.4.0     | Official modular SDK v2        |
| **Client SDK**        | `@modelcontextprotocol/client` ^2.4.0     | Official modular SDK v2        |
| **Runtime Target**    | Node.js `>=20.0.0` (tested on `v24.21.0`) | ES2022 / Node16 ESM resolution |
| **Validation**        | Zod `^4.2.0`                              | Schema validation              |

---

## MCP Protocol Lifecycle & Enforcement Points

Veylith enforces security policies strictly within standard MCP protocol semantics without introducing non-compliant envelopes:

### 1. Discovery Filtering (`tools/list`)

- Upstream tools are fetched via MCP client.
- Scanned for **tool-description poisoning** (embedded directives, role spoofing, credential mandates).
- Poisoned tools are dropped from the downstream tool registration.
- Downstream clients receive a standard, valid `tools/list` response containing only verified clean tools.
- If a client subsequently attempts to invoke a tool that was dropped during discovery, the gateway returns a standard MCP protocol error (`code: -32601`, Tool not found).

### 2. Argument Interception (`tools/call`)

- When a client executes `tools/call`, the gateway inspects arguments before forwarding.
- If blocked (e.g. `rm -rf /`, SQL `DROP TABLE`, or static rule match):
  - Returns a standard MCP tool response conforming to `CallToolResult`:
    ```json
    {
      "content": [
        {
          "type": "text",
          "text": "Veylith policy blocked this call: Dangerous arguments blocked: Destructive filesystem deletion (rm -rf / or *)"
        }
      ],
      "isError": true
    }
    ```
  - Upstream is never contacted.
  - The client receives an explainable, protocol-compliant error result rather than an opaque transport disconnection.

### 3. Response Sanitization (`tools/call` output)

- When upstream returns a tool execution result, the gateway inspects all content blocks before returning downstream.
- If indirect prompt injection or credential leakage is detected:
  - The malicious text is replaced with a clean security notice:
    ```json
    {
      "content": [
        {
          "type": "text",
          "text": "[Veylith Security Notice]: Tool response from 'simulate_untrusted_source' contained potential prompt injection instructions and was redacted to protect the agent reasoning loop."
        }
      ],
      "isError": true
    }
    ```
  - This neutralizes the attack before it enters the agent's context window.

---

## Streamable HTTP Transport & Session Semantics

### HTTP Headers & Content Negotiation

- **Incoming Requests**: The gateway forwards standard MCP headers (`Accept: application/json, text/event-stream`, `Content-Type: application/json`, and optional session headers such as `mcp-session-id`).
- **Response Headers**: Preserves content-type headers returned by `@modelcontextprotocol/server`, including SSE event streams (`text/event-stream`) or JSON responses.
- **Body Streaming**: The gateway utilizes standard web streams (`webResponse.body.getReader()`) pumped to the underlying Node.js `http.ServerResponse`, supporting incremental SSE events without blocking or buffering infinite streams.

### Session Lifecycle

- **Stateless Request Routing**: The gateway maintains a stateless proxy architecture where each incoming MCP exchange is evaluated against live policy invariants.
- **Multi-tenant / Multi-client Isolation**: Inspection cache keys are cryptographically bound to `(stage, policyVersion, modelVersion, serverId, clientId, toolName, payloadHash)` to ensure that verdicts are never reused across different clients, tenants, or upstream server identities.

---

## Supported Transports

| Transport              | Phase 1 Status          | Details                                                                                    |
| :--------------------- | :---------------------- | :----------------------------------------------------------------------------------------- |
| **Streamable HTTP**    | **Supported (Default)** | Node.js `http` server bridged to web-standard `Request`/`Response` via `createMcpHandler`. |
| **stdio**              | Planned (Phase 2)       | Targeted for CLI agents (Claude Code, Cursor).                                             |
| **Request-Scoped SSE** | Supported               | Chunks are streamed through a web reader pump.                                             |
| **Legacy HTTP+SSE**    | Not Supported           | Deprecated in MCP specification; explicitly out of scope.                                  |
