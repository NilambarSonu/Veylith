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

### 2. Argument Interception (`tools/call`)

- When a client executes `tools/call`, the gateway inspects arguments before forwarding.
- If blocked (e.g. `rm -rf /`, SQL `DROP TABLE`, or static rule match):
  - Returns a standard MCP tool response:
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

## Supported Transports

| Transport              | Phase 1 Status          | Details                                                                                             |
| :--------------------- | :---------------------- | :-------------------------------------------------------------------------------------------------- |
| **Streamable HTTP**    | **Supported (Default)** | Node.js `http` server bridged to web-standard `Request`/`Response` via `createMcpHandler`.          |
| **stdio**              | Planned (Phase 2)       | Targeted for CLI agents (Claude Code, Cursor).                                                      |
| **Request-Scoped SSE** | Buffered                | Requests and responses are buffered per exchange. Streaming token pass-through planned for Phase 2. |
| **Legacy HTTP+SSE**    | Not Supported           | Deprecated in MCP specification; explicitly out of scope.                                           |
