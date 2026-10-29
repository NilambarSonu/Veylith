# Veylith Phase 3 — Local Security Research Dashboard

The **Veylith Research Dashboard** is a local, read-only developer and evaluator interface designed to honestly surface Veylith's security capabilities, offline evaluation benchmarks, and known architectural limitations.

---

## 1. Local-Only & Read-Only Security Architecture

The dashboard strictly adheres to local-first security boundaries:

- **Loopback Enforcement**: Binds strictly to `127.0.0.1` (never `0.0.0.0`). Rejects non-loopback connections, DNS rebinding (`Host` validation), and cross-origin access.
- **Strict Path Traversal & Symlink Confinement**: Blocks unnormalized paths, encoded sequences (`%2e%2e`, `%2f`, `%00`), and verifies symlink targets stay strictly within static asset roots using `fs.realpathSync`.
- **Content Security Policy**: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`. Inline scripts are completely forbidden; inline styles remain permitted for dynamic charting layouts.
- **Read-Only**: Zero tool-execution, credential-entry, or policy-mutation endpoints. Any `POST`, `PUT`, or `DELETE` receives HTTP 405 Method Not Allowed.
- **Secret Redaction**: Session identifiers, bearer tokens, API keys, passwords, and authorization headers are automatically masked prior to JSON emission or UI rendering.
- **XSS-Safe Rendering**: Zero `dangerouslySetInnerHTML`. All untrusted payloads and MCP texts are escaped.
- **Offline / Zero-Cost**: Does not initiate remote telemetry or external Meta API calls.

---

## 2. Dashboard Pages

| Page                  | Key Capabilities & Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| :-------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Overview**          | Branding, principal metrics (14 scenarios, 112 offline variants, 128 total dataset cases, 56 frozen holdouts, 6 reserved live candidates, 252/252 Phase 2F test baseline, 13/15 reliability probes), provenance, CI quality gates.                                                                                                                                                                                                                                                                                      |
| **Evaluation Lab**    | Separates **Phase 2F Development Comparison** from **Phase 2E Frozen Holdout**. Interactive confusion matrices (TP, TN, FP, FN), precision/recall/enforcement stats, SVG metrics bars, scenario breakdown across 5 difficulty tiers (Easy, Medium, Hard, Extremely Hard, God Level). Highlights Phase 2F deterministic-only 100% FPR and mock-semantic 52.1% recall.                                                                                                                                                    |
| **Audit Explorer**    | Read-only viewer for cryptographically linked SHA-256 audit event records. Mathematically verifies in-memory local audit chains across 72 cases (1,945 total events) using synthetic mutation tests (detecting payload tampering, broken links, and skipped sequence numbers). Note: Hash chaining guarantees local detection against tampering within the closed dataset, but requires external timestamping, public notary, or ledger anchoring to detect whole-chain re-generation by a privileged local root actor. |
| **Security Findings** | Honest presentation of the **8 known unresolved security issues** and the **6 reserved live Meta Muse candidates** (explicitly marked _"Pending separate founder authorization"_ with zero execution buttons).                                                                                                                                                                                                                                                                                                          |

---

## 3. Quickstart & Verification

```bash
# 1. Build client and server
pnpm run build

# 2. Run dashboard tests (36 security and server tests)
pnpm --filter @veylith/research-dashboard test

# 3. Start local dashboard on http://127.0.0.1:8789
pnpm dashboard
```

Open your browser to:
[http://127.0.0.1:8789](http://127.0.0.1:8789)
