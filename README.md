# Veylith

> **The AI Agent Security Boundary**  
> An AI-native security gateway for Model Context Protocol (MCP) agents, powered by Meta Muse.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![MCP Protocol](https://img.shields.io/badge/MCP_Protocol-2026--07--28-green.svg)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_ESM-3178C6.svg)](https://www.typescriptlang.org/)

---

## 1. What is Veylith?

**Veylith** is a specialized security gateway designed to sit between autonomous AI agents and the external tools, services, and databases they interact with via the **Model Context Protocol (MCP)**.

Rather than giving AI agents unmediated, direct access to external tool execution environments, Veylith acts as an inline security boundary and policy enforcement point. It inspects tool declarations, intercepts tool invocation requests, applies deterministic and semantic risk policies, and redacts sensitive credentials in real time.

---

## 2. What Problem Does It Address?

As autonomous AI agents adopt MCP to connect to enterprise filesystems, APIs, databases, and external cloud services, critical security vulnerabilities emerge:

1. **Tool Description Poisoning**: Malicious or compromised MCP servers embedding adversarial prompt injections inside tool schemas to hijack the agent's reasoning.
2. **Untrusted Tool Outputs & Indirect Injection**: Data returned from third-party APIs containing payloads that manipulate subsequent agent turns.
3. **Parameter Manipulation & Privilege Escalation**: Agents manipulated into invoking destructive commands (e.g., dropping database tables, deleting local files, executing arbitrary shell code).
4. **Credential & Secret Exfiltration**: Unintentional leakage of API keys, bearer tokens, or user privacy data through tool calls or unredacted log streams.
5. **Lack of Explainable Audit Trails**: Black-box agent actions where security teams cannot ascertain why a tool was allowed or blocked.

Veylith establishes an observable, inspectable, and policy-governed control plane at the transport layer to solve these challenges.

---

## 3. Current Development Status

- **Phase**: **Phase 0 (Foundation & Transport Proof of Concept)**
- **Development Branch**: `dev/phase-0-foundation`
- **Current Milestone**: Monorepo bootstrap, official MCP SDK v2 transport foundation (Streamable HTTP), deterministic policy evaluator, structured logger with secret redaction, and end-to-end integration test suite.
- **Hackathon Context**: Developed for the **Meta Global AI Developer Hackathon 2026** (Startup Track — Solo Founder: Nilambar Behera).

---

## 4. Architecture Overview

Veylith uses an **MCP Bridge Gateway** pattern:

```
+--------------------+            +------------------------+            +-----------------------+
|     AI Agent       | Streamable |    Veylith Gateway     | Streamable |  Upstream MCP Server  |
| (Claude / Cursor / |   HTTP     |  (Security Boundary)   |   HTTP     |   (Benign / 3rd Party |
|   Custom Agent)    | ---------> |                        | ---------> |      Tools/APIs)      |
|                    | <--------- | - Policy Evaluator     | <--------- |                       |
+--------------------+            | - Secret Redaction Log |            +-----------------------+
                                  | - Meta Muse (Phase 1)  |
                                  +------------------------+
```

### Monorepo Structure

```
veylith/
├── apps/
│   └── gateway/              # Core MCP bridge gateway application
├── packages/
│   ├── core/                 # Shared domain types, errors, and decision interfaces
│   ├── policy-engine/        # In-memory deterministic policy evaluator
│   └── meta-adapter/         # Meta Muse semantic inspection boundary (Phase 1 contract)
├── examples/
│   ├── benign-mcp-server/    # Harmless local MCP server for safe testing
│   └── test-client/          # TypeScript MCP test client
├── tests/
│   ├── integration/          # End-to-end multi-process integration tests
│   └── fixtures/             # Benign and malicious tool definitions
└── docs/                     # Technical architecture, security, and setup documentation
```

For in-depth details, see:

- [Architecture Overview](docs/architecture/overview.md)
- [Protocol & Transport Compatibility](docs/protocol/compatibility.md)
- [Threat Model & Security Boundaries](docs/security/threat-model.md)
- [Local Setup Guide](docs/development/local-setup.md)

---

## 5. Quick Start & Installation

### Prerequisites

- Node.js `>=20.0.0` (tested on `v24.21.0`)
- `pnpm` (`12.x` or Corepack)

### Setup

```bash
# Clone the repository
git clone https://github.com/NilambarSonu/Veylith.git
cd Veylith

# Checkout development branch
git checkout dev/phase-0-foundation

# Install dependencies
pnpm install

# Copy environment configuration
cp .env.example .env
```

---

## 6. Local Testing & Verification

To run manual end-to-end verification across the client, gateway, and upstream server:

```bash
# Terminal 1: Launch the upstream benign server (port 8788)
pnpm --filter @veylith/benign-mcp-server start

# Terminal 2: Launch the Veylith security gateway (port 8787)
pnpm --filter @veylith/gateway start

# Terminal 3: Run the test client through the gateway
pnpm --filter @veylith/test-client start:via-gateway
```

The test client will connect to the gateway, list discovered tools, execute allowed tools (`echo`, `add`), and attempt the restricted demo tool (`restricted_demo_tool`), which the gateway blocks with an explainable policy verdict.

---

## 7. Available Monorepo Commands

| Command                 | Description                                                    |
| :---------------------- | :------------------------------------------------------------- |
| `pnpm install`          | Install all workspace package dependencies                     |
| `pnpm build`            | Compile TypeScript packages to JavaScript (`dist/`)            |
| `pnpm typecheck`        | Perform strict TypeScript type checking without emitting files |
| `pnpm lint`             | Run ESLint across all packages and apps                        |
| `pnpm format:check`     | Verify code formatting with Prettier                           |
| `pnpm format`           | Auto-format files with Prettier                                |
| `pnpm test`             | Run fast in-memory unit tests                                  |
| `pnpm test:integration` | Run end-to-end integration tests (spawns server & gateway)     |
| `pnpm test:all`         | Run entire test suite (unit + integration)                     |
| `pnpm clean`            | Remove build artifacts and caches                              |

---

## 8. Honest Security Limitations (Phase 0)

Security engineering requires full transparency:

- **No Universal Prompt Injection Immunity**: Veylith does **not** claim to prevent 100% of LLM prompt injections in Phase 0. Phase 0 establishes the interception perimeter and deterministic policy checks.
- **Fail-Open PoC Default**: The initial demonstration rules operate in fail-open mode for unblocked tools. Production deployments will support explicit fail-closed allowlisting.
- **Protocol Bridge Latency**: Because the gateway terminates the MCP protocol on both sides to enable deep inspection, it introduces a small measured overhead (~6–10ms locally).
- **Buffered Responses**: Streaming SSE chunks are currently buffered per exchange rather than multiplexed live.

---

## 9. Future Roadmap

- **Phase 1: Semantic Risk Inspection (Meta Muse)**:
  - Deep inspection of tool descriptions during discovery using Meta Muse.
  - Natural language argument analysis to detect command injection and secret exfiltration.
  - Calibration of semantic risk scores with explainable verdicts.
- **Phase 2: Enterprise Protocol & Multi-Server Routing**:
  - `stdio` transport adapter for desktop/CLI agents (Claude Code, Cursor).
  - Virtual tool registry multiplexing multiple upstream servers behind a single gateway.
  - Streaming SSE pass-through with inline token sanitization.
- **Phase 3: Security Observability Dashboard**:
  - Web-based developer dashboard showing real-time agent tool calls, blocked actions, and policy metrics.

---

## 10. Acknowledgements & Attribution

- **Meta Global AI Developer Hackathon 2026**: Developed for the Startup Track (Solo Founder).
- **Meta Model API**: Semantic intelligence powered by Meta Muse (integrating in Phase 1).
- **Model Context Protocol**: Built on the open [Model Context Protocol](https://modelcontextprotocol.io) specification and the official TypeScript SDK v2.

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
