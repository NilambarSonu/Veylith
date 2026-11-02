# Local Development & Setup Guide (Phase 1)

This guide walks you through setting up, configuring, and verifying the Veylith Phase 1 environment locally.

---

## 1. Prerequisites

- **Node.js**: Active LTS (`>=20.0.0`, tested on `v24.21.0`).
- **pnpm**: `pnpm` (`12.x` or Corepack, tested on `12.10.1`).
- **Operating System**: macOS, Linux, or WSL2.

---

## 2. Installation & Workspace Setup

```bash
# Clone the repository
git clone https://github.com/NilambarSonu/Veylith.git
cd Veylith

# Switch to the Phase 1 development branch
git checkout dev/phase-1-security-engine

# Install all workspace dependencies
pnpm install
```

---

## 3. Environment Configuration

Copy the example environment configuration:

```bash
cp .env.example .env
```

### Key Environment Variables

| Variable                  | Default                     | Purpose                                                        |
| :------------------------ | :-------------------------- | :------------------------------------------------------------- |
| `GATEWAY_HOST`            | `127.0.0.1`                 | Local network binding interface.                               |
| `GATEWAY_PORT`            | `8787`                      | Port for the Veylith Security Gateway.                         |
| `UPSTREAM_MCP_URL`        | `http://127.0.0.1:8788/mcp` | Upstream target MCP server endpoint.                           |
| `META_AI_MODE`            | `mock`                      | Semantic model operating mode (`mock`, `live`, or `disabled`). |
| `META_MODEL`              | `muse-spark-1.3`            | Model identifier for Meta Muse.                                |
| `META_MODEL_API_BASE_URL` | `https://api.meta.ai/v1`    | Meta Model API base URL.                                       |
| `META_MODEL_API_KEY`      | _(blank)_                   | Backend API key for live inference. Never committed!           |
| `FAIL_CLOSED`             | `false`                     | If true, model errors or review outcomes trigger blocks.       |
| `BLOCKED_TOOLS`           | `restricted_demo_tool`      | Comma-separated statically blocked tool names.                 |

---

## 4. Quality Gates & Testing Commands

Run all quality checks from the workspace root:

```bash
# 1. Strict TypeScript type check across all 6 packages & apps
pnpm typecheck

# 2. Compile TypeScript packages to dist/
pnpm build

# 3. Lint codebase with ESLint
pnpm lint

# 4. Verify Prettier code style
pnpm format:check

# 5. Run full test suite (61 tests across 11 suites)
pnpm test:all

# 6. Run security benchmark evaluation specifically
pnpm vitest run tests/integration/security-engine.test.ts
```

---

## 5. Live Meta Muse Smoke Test

By default, all automated tests use `META_AI_MODE=mock` to ensure zero external cost and 100% offline reproducibility.

To manually test live connectivity to Meta Muse with a real API key:

```bash
META_MODEL_API_KEY="your-api-key" META_AI_MODE="live" pnpm smoke:meta
```

**Safety Invariants**:

- The smoke test enforces an application-level cap of **maximum 2 requests** and **$0.05 USD budget cap**.
- Reports exact token usage and estimated spend upon completion.

---

## 6. Multi-Process Local Testing

To manually observe request flow across the client, gateway, and upstream server, open three separate terminal windows:

### Terminal 1: Launch Upstream Benign MCP Server

```bash
pnpm --filter @veylith/benign-mcp-server start
```

_Listens on `http://127.0.0.1:8788/mcp`._

### Terminal 2: Launch Veylith Security Gateway

```bash
pnpm --filter @veylith/gateway start
```

_Listens on `http://127.0.0.1:8787/mcp`._

### Terminal 3: Run Test Client via Gateway

```bash
pnpm --filter @veylith/test-client start:via-gateway
```

_The client will connect through the gateway, list discovered clean tools, execute `echo` and `add`, and verify policy enforcement on `restricted_demo_tool`._
