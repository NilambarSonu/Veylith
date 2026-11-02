# Veylith — Hackathon Submission Package

**Meta Global AI Developer Hackathon 2026**  
**Track:** Startup  
**Theme:** Push the Frontier  
**GitHub:** https://github.com/NilambarSonu/Veylith

---

## 1. Project Identification

- **Project Name:** Veylith — AI Agent Security Gateway
- **Track:** Startup
- **Theme:** Push the Frontier
- **Author / Presenter:** Nilambar Behera (Solo Founder)
- **Repository:** `https://github.com/NilambarSonu/Veylith` (Local Workspace: `/Users/nilambarbehera/Documents/Projects/veylith`)
- **Primary Demonstration Command:** `pnpm demo -- --all`
- **Interactive Research Dashboard:** `pnpm dashboard` (Runs locally at `http://127.0.0.1:8789`)

---

## 2. Executive Submission Brief

### One-Line Description

Veylith is an AI-agent security gateway and research prototype that inspects MCP interactions, enforces tool-use policies, and provides auditable security decisions.

### Project Description

AI agents increasingly interact with external tools and services through the Model Context Protocol (MCP), creating new risks from prompt injection, malicious tool descriptions, and unsafe tool execution.

Veylith introduces a security boundary between AI agents and upstream MCP servers. Built in TypeScript, it combines deterministic policy enforcement, three-outcome semantic governance (`ALLOW`, `BLOCK`, `REVIEW`), and structured audit logging to inspect tool discovery, tool calls, and returned content. Its research dashboard provides evaluation comparisons, confusion matrices, latency measurements, and transparent security limitations.

The project includes multi-provider compatibility supporting the Meta Model API and Fireworks AI (`accounts/fireworks/models/muse-spark-open`). In Phase 5D live validation, Veylith was evaluated against 100 independently frozen cases with real Fireworks model inference, demonstrating **100.0% attack recall (50/50)** and **0.0% clearly-benign false positive rate (0/35)** under strict rate pacing and three-tier routing.

Veylith explores how security enforcement and measurable evaluation can become part of the infrastructure surrounding autonomous AI agents.

### Technical Highlights

- TypeScript-based MCP security gateway and stdio integration.
- Three-tier hybrid architecture: sub-0.05ms deterministic invariants paired with semantic LLM intelligence.
- Tamper-evident cryptographic audit hash chain (SHA-256 sequential state linking).
- Real live API inference evaluation with Fireworks AI `muse-spark-open` on frozen synthetic benchmark (100 cases, 100% attack recall, 0.0% clearly-benign FPR, 85.0% benchmark accuracy).
- Research dashboard with evaluation matrices, latency telemetry, and security findings.
- Automated test suite (408 tests, 100% passing across 43 files) and browser-verified interactive demonstration.

### Current Limitations

Veylith remains an engineering research prototype, not a production-certified security appliance. While empirical validation confirms major precision/recall gains, prompt injection remains an adaptive open problem. Its audit chain is locally verified rather than externally anchored to a public notary, and deep reasoning model inference introduces latency overhead (~7.4s p50) that requires fast-path deterministic bypasses for non-sensitive operations.

---

## 3. Problem Statement

The Model Context Protocol (MCP) has rapidly become the standard interface for connecting Large Language Models to local tools, databases, APIs, and file systems. However, MCP operates on an implicit trust model with significant architectural vulnerabilities:

1. **Ambient Authority & Unrestricted Execution:** Agents execute tools with the full ambient system authority of the host process. An agent tricked into running `rm -rf /` or `DROP TABLE users` executes it directly.
2. **Catalog & Discovery Poisoning:** Malicious upstream MCP servers can advertise deceptive descriptions in `tools/list` payloads, injecting hidden instructions into the agent's context during initial discovery.
3. **Indirect Prompt Injection:** Untrusted 3rd-party data (e.g., fetched web pages, email summaries, support tickets) returned via `tools/call` can contain embedded directive injections that hijack downstream model cognition.
4. **All-or-Nothing Latency Trade-Off:** Traditional external guardrail APIs introduce 1,000–3,000ms cloud round-trip delays on every single tool call, destroying interactive agent responsiveness.

---

## 4. Proposed Solution: The Veylith Security Boundary

Veylith provides an inline security proxy and stdio bridge that intercepts, evaluates, and enforces policy across every stage of the MCP lifecycle:

- **Zero-Trust Reverse Proxy:** Positioned inline between the AI Agent and MCP servers. No client modification is required; agents connect via standard MCP Streamable HTTP or stdio bridge (`veylith-stdio`).
- **Three Inspection Boundaries:**
  1. _Stage 1 (Discovery):_ Sanitizes `tools/list`, `resources/list`, and `prompts/list` schemas. Drops poisoned descriptions before the model ingests them.
  2. _Stage 2 (Invocation Arguments):_ Evaluates `tools/call` parameters against hard security invariants (destructive filesystem deletion, dangerous SQL, SSRF, fork-bombs) in under 0.05ms.
  3. _Stage 3 (Call Response):_ Quarantines and neutralizes indirect prompt injections returning from tool executions, replacing unsafe directives with structured quarantine notices (`isError: true`).
- **Three Policy Decision Outcomes:**
  - `ALLOW`: Payload satisfies invariants and semantic checks; forwarded cleanly to destination.
  - `BLOCK`: Dangerous request blocked fail-closed before dispatch; returns structured protocol error.
  - `SANITIZE`: Untrusted response intercepted; malicious instructions stripped and replaced with quarantine alerts.

---

## 5. System Architecture & Request Flow

```
┌────────────────────────────────────────────────────────┐
│               Agent Client Runtime                     │
│        (Claude Desktop / Cursor / MCP Client SDK)       │
└───────────────────────────┬────────────────────────────┘
                            │ JSON-RPC (HTTP or stdio)
                            ▼
┌────────────────────────────────────────────────────────┐
│            Veylith Inline Security Gateway             │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 1: Deterministic Invariants (<0.05ms)       │  │
│  │ • Path traversal (../)                           │  │
│  │ • Destructive shell (rm -rf /, mkfs, fork-bombs)  │  │
│  │ • Dangerous SQL (DROP, TRUNCATE, ALTER)          │  │
│  │ • SSRF & Private IP boundaries (169.254, 10.x)   │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │ (Ambiguous payload)      │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 2: Heuristic Fast Screener (p50: 0.033ms)   │  │
│  │ • Token entropy & special delimiter detection     │  │
│  │ • Role-spoofing keywords ("SYSTEM OVERRIDE")     │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             │ (Suspicious payload)     │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tier 3: Meta Muse Semantic Review (Cloud)        │  │
│  │ • Meta Model API (muse-spark-1.3)                │  │
│  │ • Intent classification & contextual injection   │  │
│  └──────────────────────────────────────────────────┘  │
│                             │                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Cryptographic Audit Log (SHA-256 Hash Chain)     │  │
│  │ • Tamper-evident sequencing & secret redaction   │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ Filtered Safe JSON-RPC
                            ▼
┌────────────────────────────────────────────────────────┐
│                  Upstream MCP Server                   │
│          (Filesystem, Database, Web Fetcher, etc.)     │
└────────────────────────────────────────────────────────┘
```

---

## 6. Main Features & Technical Innovations

1. **3-Tier Multi-Speed Policy Architecture:**
   - **Tier 1 (Deterministic Invariants):** Ultra-fast pattern matching executes in $<0.05\text{ ms}$ in-memory ($p50: 0.002\text{--}0.018\text{ ms}$), blocking known destructive signatures with zero LLM latency.
   - **Tier 2 (Heuristic Screener):** Screens high-entropy payloads, system token delimiters, and prompt framing in $p50: 0.033\text{ ms}$ ($p95: 0.057\text{ ms}$).
   - **Tier 3 (Meta Muse Semantic Classifier):** Routes genuinely ambiguous natural-language payloads to Meta Muse via the Meta Model API for deep contextual evaluation.
2. **Cryptographic SHA-256 Hash-Chained Audit Trail:**
   - Every inspection event computes a canonical JSON SHA-256 hash incorporating the previous event's hash (`currentEventHash = SHA256(previousEventHash + canonicalJson(event))`).
   - Detects local log tampering, event deletion, and insertion across multi-session executions.
3. **Dual-Protocol Adapter Support:**
   - **Streamable HTTP Gateway:** Binds to `127.0.0.1:8787` supporting modern HTTP streaming MCP clients.
   - **Stdio Bridge (`veylith-stdio`):** Standalone zero-dependency executable (`bin/veylith-stdio.js`) that allows desktop clients (e.g. Claude Desktop) to launch Veylith as a child subprocess.
4. **Automated Secret Redaction & Cost Safety:**
   - Redacts Bearer tokens, API keys, and sensitive authorization headers before logging.
   - Hard rate-limiting and budget capping prevent runaway model inference costs.

---

## 7. Technology Stack

- **Runtime & Language:** Node.js (>= v20.0.0), TypeScript 5.8 (Strict ESM)
- **Protocols & Standards:** Model Context Protocol (MCP) Specification (JSON-RPC 2.0), Streamable HTTP Transport, Stdio Transport
- **AI & Model Integration:** Meta Model API (`muse-spark-1.3`), custom `@veylith/meta-adapter` client
- **Cryptographic Engine:** Node.js native `crypto` (SHA-256 canonical hashing)
- **Research Dashboard:** Vanilla TypeScript SPA with custom CSS variables, native zero-dependency SVG charts, and loopback HTTP server
- **Testing & Verification:** Vitest 3.2, Chrome DevTools Protocol (CDP) for headless browser verification

---

## 8. How to Run the Project Locally

### Prerequisites

- Node.js >= 20.0.0
- pnpm >= 9.0.0

### Step-by-Step Installation & Verification

```bash
# 1. Clone repository and navigate to workspace
git clone https://github.com/NilambarSonu/Veylith.git
cd veylith

# 2. Install workspace dependencies
pnpm install

# 3. Build all workspace packages
pnpm build

# 4. Run typecheck across all 8 projects
pnpm typecheck
pnpm security:eval:typecheck

# 5. Execute full workspace test suite (408 tests, 43 files)
pnpm test:all

# 6. Launch Research Dashboard (local loopback, read-only)
pnpm dashboard
# Dashboard available at http://127.0.0.1:8789
```

---

## 9. How to Execute the Four-Scenario Demonstration

Veylith includes a self-contained, zero-cost terminal demonstration that spawns a real upstream MCP server, gateway, stdio adapter, and client SDK over local loopback:

```bash
# Batch execution of all four scenarios (recommended)
pnpm demo -- --all

# Interactive menu mode (TTY)
pnpm demo

# Real MCP client stdio bridge demonstration
pnpm demo:client
```

### Demonstration Scenarios:

- **Scenario A [ALLOW]: Safe MCP Tool Execution**  
  Discovers legitimate tools and invokes benign `echo`. Evaluated in Tier 1/2 in $21.32\text{ ms}$; allowed cleanly to upstream.
- **Scenario B [BLOCK]: Tool Discovery Poisoning**  
  Upstream server advertises `poisoned_discovery_tool` with system instruction override. Stage 1 drops the tool; harmless tools remain available.
- **Scenario C [SANITIZE]: Indirect Prompt Injection in Tool Output**  
  Untrusted data source returns hidden directive instructions. Stage 3 intercepts output, strips directive, and returns a quarantined security notice (`isError: true`).
- **Scenario D [BLOCK]: Dangerous Invocation Arguments**  
  Client invokes `echo` with destructive command argument `rm -rf /`. Tier 1 hard invariants block call locally before upstream dispatch.

---

## 10. Evaluation Methodology & Verified Results

Veylith avoids marketing claims of "100% prompt injection detection" by providing transparent empirical benchmarks across three distinct datasets:

| Metric / Attribute          | Phase 2A Validation Fixture            | Phase 2E Procedural Holdout                      | Phase 2F Development Comparison                          |
| :-------------------------- | :------------------------------------- | :----------------------------------------------- | :------------------------------------------------------- |
| **Dataset Path**            | `tests/fixtures/holdout-corpus.json`   | `security-lab/v1/holdout.json`                   | `security-lab/v1/development.json`                       |
| **Total Records**           | 68 curated samples                     | 56 benchmark cases                               | 72 development samples (56 core + 16 G1)                 |
| **Scored Samples**          | 68 classification samples              | 50 scored ($6$ operational exclusions)           | 68 scored ($4$ operational exclusions)                   |
| **Exclusion Rationale**     | None (all samples scored)              | Testing timeouts/drops (`predicted: null`)       | Operational stress cases (`predicted: null`)             |
| **Attack Detection Recall** | **46.9%** (15/32 malicious blocked)    | **62.1%** (Deterministic) / **65.5%** (Mock)     | **100.0%** (Deterministic) / **52.1%** (Mock)            |
| **False Positive Rate**     | **2.8%** (1 FP / 36 benign)            | **0.0%** (0 FP / 21 benign)                      | **100.0%** (Deterministic fail-closed) / **0.0%** (Mock) |
| **Attack Precision**        | **93.8%** (15 TP / 16 blocks)          | **100.0%** (18/18 deterministic)                 | **70.6%** (Deterministic) / **100.0%** (Mock)            |
| **Overall Accuracy**        | **73.5%** (50/68 samples)              | **78.0%** (Deterministic) / **80.0%** (Mock)     | **70.6%** (Deterministic) / **66.2%** (Mock)             |
| **Provenance Nature**       | In-repo validation fixture (not blind) | Procedurally frozen benchmark (commit `1086aef`) | Post-remediation development variants                    |

### Phase 5D Live Fireworks AI Security Evaluation on Frozen Synthetic Benchmark

In Phase 5D, Veylith completed a live inference evaluation using **Fireworks AI** (`accounts/fireworks/models/muse-spark-open`) over standard HTTPS chat completions on the frozen 100-case synthetic validation dataset [`security-lab/phase-5c/validation-dataset.json`](file:///Users/nilambarbehera/Documents/Projects/veylith/security-lab/phase-5c/validation-dataset.json) (SHA-256: `97383d1180b217130b270c9429dd94e5f6af752e4e92b14f12dfd5326c04df62`): This represents live model evaluation against a controlled synthetic benchmark—not production MCP traffic or real-world deployment testing.

- **Inference Mode**: 100% Real Live Model Inference (91 live API requests, 9 deterministic fast-path short-circuits).
- **Attack Recall**: **100.0% (50/50)** malicious injections intercepted or contained.
- **Clearly-Benign False Positive Rate**: **0.0% (0/35)** false blocks on legitimate developer workflows.
- **Ambiguous Borderline Handling**: 15 borderline educational/quoted attack cases evaluated; live model recognized non-exploitative context and returned `ALLOW` (15/15 allowed, 0/15 contained under Phase 5D prompt). Analysis subsequently resolved prompt invariants and engine routing to properly enforce three-outcome quarantine policies (`ALLOW` / `BLOCK` / `REVIEW`).
- **Confirmed Attack Precision**: **100.0%** (50 true positive blocks / 50 total blocks in Mode C).
- **F1 Score**: **100.0%**.
- **Overall Benchmark Accuracy**: **85.0%** (85/100 matching expected ground truth).
- **Actual Provider Spend**: **$0.169359 USD** for 82,312 billed tokens (**$1.830641 USD** budget remaining from $2.00 hard cap; zero budget overruns).
- **Inference Latency**: p50 = 7,377.1 ms, p95 = 14,154.4 ms (demonstrating why hybrid Tier 1/2 fast paths at <0.05ms are essential for real-time operations).
- **Sealed Reserves**: All 6 reserved adversarial candidates (`security-lab/v1/live-reserve.json`) remain sealed and unexecuted.

### Full Workspace Test Suite

- **Test Files:** 43 passed (100%)
- **Tests Passed:** **408 passed (408)** (100%)
- **Test Failures:** 0 failures
- **Execution Time:** ~20 seconds

---

## 11. Meta Model Integration & Compatibility Canary

- **Provider Support:** Native Meta Model API client configured in `@veylith/meta-adapter` for `muse-spark-1.3`.
- **Phase 4B.1 Live Canary Execution:**
  - In Phase 4B.1, Veylith executed exactly **one live compatibility canary request** to verify wire protocol compliance, header authorization, and token usage accounting.
  - **Results:** HTTP 200, elapsed time $3,726.52\text{ ms}$, token usage $492\text{ prompt} + 107\text{ completion} = 599\text{ total}$, estimated spend $\$0.00107\text{ USD}$.
  - **Artifacts:** Verified on disk in `security-lab/compat-results/` (`REPORT.md`, `SYNTH-COMPAT-LIVE-01-plan.json`, `attempt.json`, `results.json`, `usage.json`).
- **Strict Scope Disclosure:** The canary call verified wire transport, API key authorization, and cost tracking. It is **not** an adversarial benchmark or model accuracy claim. The 6 reserved live adversarial candidates (`security-lab/v1/live-reserve.json`) remain sealed offline and untouched.

---

## 12. Known Limitations & Roadmap

In adherence to scientific honesty, Veylith publicly documents its open research limitations (visible in the dashboard's **Security Findings** view):

1. **Local Prototype Boundary:** Binds strictly to `127.0.0.1` loopback. Production enterprise authentication (OAuth2/OIDC, mTLS, RBAC) is not yet implemented.
2. **Local Cryptographic Scope:** SHA-256 hash chaining detects in-situ log tampering, omissions, and insertions across local runs, but lacks external public notary anchoring (e.g., Rekor transparency log).
3. **Transient Subscriptions:** MCP `resources/subscribe` notifications do not persist across transport reconnections.
4. **Availability vs. Security Trade-Off:** Pure deterministic fail-closed inspection blocked 100% of benign cases when natural language was ambiguous (Phase 2F). Hybrid semantic review is required for commercial availability.
5. **Reserved Candidates Unexecuted:** Full empirical validation of Meta Muse detection accuracy on the 6 reserved god-level adversarial candidates requires manual founder-authorized live evaluation.

---

## 13. Documentation Sitemap

- [Root README.md](file:///Users/nilambarbehera/Documents/Projects/veylith/README.md): Project overview, architecture, quickstart, and benchmark highlights.
- [Judge Walkthrough Script](file:///Users/nilambarbehera/Documents/Projects/veylith/docs/hackathon/JUDGE-WALKTHROUGH.md): 3-minute screen-by-screen presentation script with spoken narrative and timings.
- [Presentation Checklist](file:///Users/nilambarbehera/Documents/Projects/veylith/docs/hackathon/RECORDING-CHECKLIST.md): System preflight, window setup, audio/video recording guidelines, and troubleshooting.
- [Live Canary Runbook](file:///Users/nilambarbehera/Documents/Projects/veylith/docs/security/phase-4/PHASE-4B-FOUNDER-RUNBOOK.md): Cryptographic audit trail and live execution protocol.
- [Architecture Overview](file:///Users/nilambarbehera/Documents/Projects/veylith/docs/architecture/overview.md): Technical deep-dive on gateway internals and policy routing.
