# Changelog

All notable changes to the **Veylith** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-alpha.1] - 2026-11-03

Initial public alpha release developed for the **Meta Global AI Developer Hackathon 2026** (Startup Track).

### Added

- **Public CLI Binary Package (`veylith`)**:
  - Standalone bundled executable mapping to `veylith` and `veylith-stdio`.
  - Self-contained Node.js ESM bundle with zero workspace dependencies; only declares runtime dependencies on `@modelcontextprotocol/client` and `@modelcontextprotocol/server`.
  - Standalone Subprocess Mode: Directly mediates upstream stdio MCP tools (e.g. `npx -y @modelcontextprotocol/server-filesystem ~/mcp-sandbox`).
  - Gateway Bridge Mode: Bridges downstream stdio to a centralized Veylith HTTP Gateway daemon.
- **Three-Stage Security Inspection Boundary**:
  - **Stage 1 (Discovery Inspection)**: Intercepts `tools/list` schema advertisements from upstream MCP servers; sanitizes descriptions, strips shadow instructions, and filters blocked tools before the agent sees them.
  - **Stage 2 (Argument Inspection)**: Evaluates `tools/call` parameters against deterministic regex invariants and optional semantic models before upstream execution occurs.
  - **Stage 3 (Response Inspection)**: Inspects tool return content for indirect prompt injections, canary leaks, and data exfiltration directives; applies automatic field redaction or full quarantine.
- **Multi-Tier Policy Engine**:
  - **Tier 1 (Deterministic Rules)**: High-speed in-memory evaluation (<0.05 ms microbenchmarks) detecting destructive shell commands (`rm -rf`, `mkfs`, fork bombs), SQL drops, path traversals, and private IP / cloud metadata SSRF endpoints.
  - **Tier 2 (Heuristic Screener)**: Keyword density and entropy analysis (p50: 0.033 ms, p95: 0.057 ms) for routing ambiguous natural-language content.
  - **Tier 3 (Meta Muse Adapter)**: Optional semantic threat classification using Meta Muse (`muse-spark-1.3` / Fireworks `muse-spark-open`).
- **Cryptographic Audit Hash Chain**:
  - Tamper-evident sequential SHA-256 canonical JSON hash chain linking every discovery, argument, and response event from a genesis hash.
- **Three-Outcome Policy Enforcement**:
  - Evaluates every request to `ALLOW` (pass-through), `BLOCK` (pre-execution rejection with code `-32603`), or `REVIEW`/`QUARANTINE` (safe redaction of ambiguous payloads).
- **Product Landing Page & Developer Quickstart**:
  - Responsive landing page deployed to Vercel ([https://veylith-jade.vercel.app](https://veylith-jade.vercel.app)).
  - Comprehensive Quickstart guide with tested Claude Desktop and Cursor integration configurations.

### Changed

- Renamed monorepo root package name to `veylith-monorepo` to avoid pnpm workspace name collisions with the public `veylith` package.
- Hardened CLI entrypoint resolution using `realpathSync` to ensure reliable execution through npm global symlinks and `npx` wrappers.
- Configured static policy rules for `--blocked-tools` to apply across both discovery (`tools/list`) and invocation (`tools/call`) stages.

### Security & Threat Model

- **Defense-in-Depth Boundary**: Veylith operates at the protocol application layer (Layer 7 for MCP). It acts as an inline policy firewall.
- **Fail-Closed by Default**: When internal evaluators crash, upstream timeouts occur, or malformed protocol frames arrive, Veylith denies access rather than failing open.
- **Process Isolation**: Inherits a sanitized environment (`getSafeChildEnvironment`) to prevent parent host credentials and API tokens from leaking to untrusted child tools.

### Known Limitations

- **Alpha Status**: This is a research and hackathon release candidate (`0.1.0-alpha.1`). It is not yet certified for enterprise SOC2 / PCI production environments.
- **OS Sandboxing**: Veylith does not replace kernel-level isolation (Docker, Landlock, seccomp). Developers should always run upstream MCP servers with minimal operating system privileges.
- **Semantic Inference Latency**: When Tier 3 semantic inspection is enabled, API network round-trips add approximately 100–300 ms of latency to ambiguous tool calls. Deterministic Tier 1 rules run locally in sub-millisecond time.
