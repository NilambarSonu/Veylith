# Veylith Protocol & Transport Compatibility

## Overview

Veylith targets the modern Model Context Protocol (MCP) specification using the official TypeScript SDK v2 split packages (`@modelcontextprotocol/server` and `@modelcontextprotocol/client`).

---

## Specification & SDK Versions

| Dimension             | Value / Specification                  | Notes                          |
| :-------------------- | :------------------------------------- | :----------------------------- |
| **MCP Specification** | 2026-07-28 revision                    | Modern protocol standard       |
| **Server SDK**        | `@modelcontextprotocol/server` ^2.4.0  | Official modular SDK v2        |
| **Client SDK**        | `@modelcontextprotocol/client` ^2.4.0  | Official modular SDK v2        |
| **Runtime Target**    | Node.js >= 20.0.0 (tested on v24.21.0) | ES2022 / Node16 ESM resolution |
| **Validation**        | Zod ^4.2.0                             | Schema validation              |

---

## Transport Support Matrix

| Transport              | Phase 0 Status     | Implementation Details                                                                                                |
| :--------------------- | :----------------- | :-------------------------------------------------------------------------------------------------------------------- |
| **Streamable HTTP**    | **Supported**      | Default primary transport. Node.js `http` server bridged to web-standard `Request`/`Response` via `createMcpHandler`. |
| **stdio**              | Planned (Phase 1)  | Targeted for local CLI-based agents (e.g., Claude Code, Cursor, terminal agents).                                     |
| **Request-Scoped SSE** | Partial (Buffered) | Requests and responses are buffered per HTTP exchange; streaming token chunks are not yet piped incrementally.        |
| **Legacy HTTP+SSE**    | Not Supported      | Deprecated in MCP specification; explicitly out of scope.                                                             |

---

## Supported MCP Capabilities (Phase 0)

### 1. Protocol Handshake & Initialization

- Implements standard `initialize` JSON-RPC handshake.
- Advertises gateway server capabilities (`tools: {}`).
- Responds to `notifications/initialized`.

### 2. Tool Listing (`tools/list`)

- Queries upstream server via MCP client.
- Dynamically mirrors upstream tool schemas and descriptions downstream.
- Proxies tool definitions to the client.

### 3. Tool Calling (`tools/call`)

- Intercepts incoming tool execution requests.
- Validates tool presence and arguments.
- Applies deterministic policy evaluation prior to any upstream transmission.
- Propagates tool results with proper JSON-RPC correlation IDs.

### 4. Protocol-Compatible Error Reporting

- Policy rejections return valid tool results with `isError: true` and descriptive security reasons rather than opaque socket disconnects or non-standard HTTP payloads. This prevents client crashes and provides explainable security feedback.
- Network and upstream faults return formatted error results (`isError: true`).
- Malformed HTTP payloads are rejected safely with standard HTTP 400/406/500 without crashing the gateway.

---

## Known Protocol Limitations (Phase 0)

1. **No Transparent SSE Streaming**: Responses are gathered and returned per exchange. Long-running streaming output from tools is buffered before delivery.
2. **No Server-Initiated Notifications**: Upstream server notifications (such as `notifications/tools/list_changed`) are not propagated downstream to clients during Phase 0.
3. **No Resource or Prompt Passthrough**: `resources/list`, `resources/read`, and `prompts/list` are not yet bridged. Phase 0 focuses exclusively on the critical tool-call boundary.
4. **Single-Upstream Routing**: The gateway binds to a single upstream server via `UPSTREAM_MCP_URL`. Multi-server routing and tool namespace prefixing are planned for Phase 2.
