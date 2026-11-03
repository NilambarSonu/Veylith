# Veylith v0.1.0-alpha.1

> **AI-agent security gateway for Model Context Protocol (MCP)**  
> Developed for the **Meta Global AI Developer Hackathon 2026** (Startup Track).

This is the initial public alpha release candidate of **Veylith**, introducing an inline security boundary and policy enforcement control plane for MCP agents.

---

## What's Included

### 1. Standalone CLI Executable (`veylith` / `veylith-stdio`)
- Single standalone bundled binary (`dist/index.mjs`, 375 kB).
- Zero external workspace dependencies; only requires runtime MCP SDKs (`@modelcontextprotocol/client` and `@modelcontextprotocol/server`).
- **Subprocess Mode**: Wraps any stdio MCP server (e.g. `npx -y @modelcontextprotocol/server-filesystem ~/mcp-sandbox`).
- **Gateway Bridge Mode**: Connects downstream stdio clients to a centralized Veylith HTTP Gateway daemon.

### 2. Triple-Stage Inspection Pipeline
- **Stage 1 (Discovery)**: Strips prompt injection directives from tool descriptions and hides blocked tools.
- **Stage 2 (Arguments)**: Intercepts destructive commands (recursive wipes, SQL table drops, path traversals) in $<0.05$ ms before upstream execution.
- **Stage 3 (Responses)**: Quarantines indirect prompt injections and redacts sensitive leaked tokens from tool outputs.

### 3. Cryptographic Audit Chain
- Tamper-evident SHA-256 sequential event hash chain recording every `ALLOW`, `BLOCK`, and `REVIEW`/`QUARANTINE` decision.

### 4. Developer Quickstart & Client Integration
- Full integration reference for **Claude Desktop** and **Cursor**.
- Step-by-step verification walkthrough with test vectors.
- [Developer Quickstart Guide](https://github.com/NilambarSonu/Veylith/blob/feat/public-productization/docs/integration/QUICKSTART.md)
- [Full Changelog](https://github.com/NilambarSonu/Veylith/blob/feat/public-productization/CHANGELOG.md)

---

## Installation & Verification

### From GitHub Release Asset
```bash
# Install the release tarball directly
npm install -g https://github.com/NilambarSonu/Veylith/releases/download/v0.1.0-alpha.1/veylith-0.1.0-alpha.1.tgz

# Verify installation
veylith --help
```

### From Source (Local Build)
```bash
git clone -b feat/public-productization https://github.com/NilambarSonu/Veylith.git
cd Veylith
pnpm install
pnpm build

# Run directly
node packages/veylith/bin/veylith.js --help
```

---

## Release Verification & Checksums
- `veylith-0.1.0-alpha.1.tgz` (SHA-256: `95d9da491f5dd7901ad43dd415762d38725b55ee7df1095efee535bba379de46`)
- Frozen Dataset Hashes Verified:
  - `security-lab/v1/live-reserve.json`: `e4f918504d7a54bf89a4f599fe6c6a2ef7de9a42c86909613c80de5f826ee276`
  - `security-lab/phase-5c/validation-dataset.json`: `97383d1180b217130b270c9429dd94e5f6af752e4e92b14f12dfd5326c04df62`
- Test Suite: 43 test files passed, 408 tests passed (100%).
