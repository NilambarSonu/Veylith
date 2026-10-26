# Local Development & Setup Guide

This guide walks you through setting up, running, and verifying the Veylith development environment locally.

---

## 1. Prerequisites

- **Node.js**: Active LTS (`>=20.0.0`, tested on `v24.21.0`).
- **pnpm**: `pnpm` (`>=9.0.0` or `12.x`, tested on `12.10.1`).
- **Operating System**: macOS, Linux, or WSL2.

---

## 2. Installation

Clone and install dependencies:

```bash
# Clone the repository (if not already local)
git clone https://github.com/NilambarSonu/Veylith.git
cd Veylith

# Switch to the development branch
git checkout dev/phase-0-foundation

# Install monorepo dependencies
pnpm install
```

---

## 3. Environment Configuration

Copy the example environment configuration:

```bash
cp .env.example .env
```

Default configuration in `.env`:

```ini
NODE_ENV=development
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=8787
UPSTREAM_MCP_URL=http://127.0.0.1:8788/mcp
LOG_LEVEL=info
REDACT_SECRETS=true
BLOCKED_TOOLS=restricted_demo_tool
```

_(Note: Never commit `.env` or any real API keys to version control.)_

---

## 4. Multi-Process Local Testing

To manually observe request flow across the client, gateway, and upstream server, open three separate terminal windows:

### Terminal 1: Launch Upstream Benign MCP Server

```bash
pnpm --filter @veylith/benign-mcp-server start
```

_Output will indicate:_ `[benign-mcp-server] Listening on http://127.0.0.1:8788/mcp`

### Terminal 2: Launch Veylith Gateway

```bash
pnpm --filter @veylith/gateway start
```

_Output will indicate:_ `{"level":"info","msg":"Veylith gateway started","data":{"port":8787,...}}`

### Terminal 3: Run Test Client via Gateway

```bash
pnpm --filter @veylith/test-client start:via-gateway
```

_The client will connect to port 8787, list proxied tools, execute `echo`, execute `add`, and attempt `restricted_demo_tool` (which is blocked by policy with an explainable error)._

To run the client directly against the server (bypassing gateway):

```bash
pnpm --filter @veylith/test-client start
```

---

## 5. Automated Verification & Quality Gates

Run all quality checks from the workspace root:

```bash
# 1. Typecheck all workspace packages
pnpm typecheck

# 2. Build TypeScript outputs
pnpm build

# 3. Lint the codebase
pnpm lint

# 4. Check code formatting
pnpm format:check

# 5. Run in-memory unit tests
pnpm test

# 6. Run end-to-end integration tests (spawns server & gateway)
pnpm test:integration

# 7. Run full test suite (unit + integration)
pnpm test:all
```

---

## 6. Process Shutdown & Cleanup

- Use `Ctrl+C` to cleanly stop any running process.
- The servers implement graceful signal handlers (`SIGINT`, `SIGTERM`) ensuring no orphaned background processes remain bound to ports 8787 or 8788.
- To clean build artifacts:
  ```bash
  pnpm clean
  ```
