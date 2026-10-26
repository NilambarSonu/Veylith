# Veylith Architecture Overview

## Introduction

**Veylith** is an AI-native security gateway positioned between Model Context Protocol (MCP) clients (AI agents, LLM runtimes, agent orchestrators) and upstream MCP servers (tools, resources, prompt providers).

During **Phase 0**, Veylith establishes the fundamental transport foundation, deterministic policy interception boundary, and protocol bridging architecture.

---

## Architectural Topology

```
+-------------------+             +-----------------------+             +----------------------+
|                   |  Streamable |                       |  Streamable |                      |
|    MCP Client     |    HTTP     |    Veylith Gateway    |    HTTP     |  Upstream MCP Server |
| (Agent / Runtime) | ----------> | (Security Interceptor)| ----------> |   (Target Tools)     |
|                   | <---------- |                       | <---------- |                      |
+-------------------+  (Port 8787)+-----------------------+  (Port 8788)+----------------------+
                                              |
                     +------------------------+------------------------+
                     |                        |                        |
           +--------------------+   +--------------------+   +--------------------+
           |   @veylith/core    |   | @veylith/policy-   |   | @veylith/meta-     |
           |   (Types, Errors,  |   |      engine        |   |     adapter        |
           |     Decisions)     |   |  (Deterministic)   |   |   (Phase 1 Stub)   |
           +--------------------+   +--------------------+   +--------------------+
```

---

## Core Components

### 1. `apps/gateway` (MCP Bridge Gateway)

The gateway application acts as a protocol-terminating bridge:

- **Downstream Interface**: Exposes a standard MCP server interface (`/mcp`) over Streamable HTTP, accepting standard MCP protocol handshakes and tool requests.
- **Upstream Interface**: Connects as an MCP client to upstream MCP servers using the official TypeScript SDK v2 (`@modelcontextprotocol/client`).
- **Bridge Design**: Rather than blindly relaying raw HTTP chunks, Veylith terminates the protocol on both sides. This ensures that every tool registration, tool invocation argument, and server response is structurally validated and inspected before transmission.

### 2. `packages/core` (Domain Foundation)

Contains shared types, error definitions, and decision primitives without protocol dependencies:

- `PolicyDecision`: Structured verdicts (`allow`, `block`, `review`).
- `PolicyVerdict`: Immutable result carrying rule IDs, timestamps, and evaluation latency.
- `VeylithError` hierarchy: Domain errors distinguishing policy violations, transport faults, and upstream timeouts.

### 3. `packages/policy-engine` (Deterministic Evaluator)

Fast, in-memory policy engine:

- Evaluates configured rules against MCP methods and tool names.
- Zero LLM latency for known invariant rules (e.g. blocking destructive demo tools or sensitive functions).
- First-match deterministic execution with configurable default fallback (fail-open in Phase 0 PoC, configurable to fail-closed).

### 4. `packages/meta-adapter` (Meta Muse Integration Stub)

Interface contract and types for semantic risk inspection using Meta Muse:

- Defines the `MetaRiskAdapter` contract.
- Establishes the boundary where tool descriptions, parameters, and tool outputs will be inspected for prompt injection, poisoned instructions, and exfiltration attempts in Phase 1.
- Guarantees zero credential leakage: API calls will strictly originate from the trusted gateway backend.

### 5. Observability & Sanitized Logger

Structured JSON logger in `apps/gateway/src/observability/logger.ts`:

- Emits machine-readable audit logs for every request ID, method, decision, and duration.
- Automatically redacts sensitive fields (Authorization headers, bearer tokens, API keys, passwords, private keys).
- Avoids storing raw tool payloads by default.

---

## Request Lifecycle

1. **Client Handshake**: Client initializes connection to `http://127.0.0.1:8787/mcp`.
2. **Tool Discovery**: Gateway connects to upstream `http://127.0.0.1:8788/mcp`, enumerates tools via `tools/list`, and dynamically registers proxy tools on the gateway server.
3. **Tool Invocation**: Client calls `tools/call` for a specific tool.
4. **Policy Interception**: Gateway passes method and tool name to `@veylith/policy-engine`.
   - **If BLOCKED**: Gateway halts execution and immediately returns an MCP-compliant error tool result (`isError: true`) with the policy reason. Upstream is never touched.
   - **If ALLOWED**: Gateway connects to upstream, forwards the tool call with sanitized arguments, receives the result, and returns it to the client.
5. **Observability**: Structured log event emitted with timing, request ID, and decision outcome.

---

## Trade-offs & Phase 0 Limitations

- **Protocol Bridging vs. Transparent Raw Proxy**: The bridge design provides complete protocol introspection at the cost of slight serialization overhead (~6–10ms per roundtrip locally).
- **Stateless Per-Request Lifecycle**: Streamable HTTP handles each connection cleanly. Server-sent background push notifications or streaming SSE multiplexing are planned for subsequent phases.
