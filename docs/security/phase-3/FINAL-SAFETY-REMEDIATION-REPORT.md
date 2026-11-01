# Veylith Phase 3 — Final Usage Validation & Network Boundary Safety Remediation Report

**Date:** October 30, 2026  
**Base Branch:** `dev/phase-3-live-usage-safety`  
**Base Commit:** `98d43d4`  
**Remediation Branch:** `dev/phase-3-final-safety-remediation`  
**Execution Environment:** macOS, Node.js v20+, Isolated Offline Lab (Zero External Provider Calls)  
**Safety Classification:** PASS — STRICT FAIL-CLOSED LIVE BOUNDARY VALIDATED

---

## 1. Executive Summary

This report documents the completion of the final security remediation phase for the Veylith AI-native security gateway before the scheduled read-only release gate. The remediation systematically resolves the three remaining findings identified in the prior security audit:

1. **Strict Provider Usage Validation Across Protocols:** Implemented strict, type-safe token validation (`isValidTokenCount`, `resolveTokenCountWithAliases`, `resolveOptionalTokenCount`, `extractValidatedUsage`) across OpenAI Chat Completions (Fireworks AI, Baseten) and Meta Responses API. All counts must be non-negative JavaScript safe integers (`Number.isSafeInteger(v) && v >= 0`). Fractional, string, `NaN`, `Infinity`, unsafe integers, negative values, and conflicting ambiguous aliases are rejected and fail closed, marking usage as unknown and cost as `null`.
2. **Complete IPv4-Mapped IPv6 Boundary Detection:** Replaced fragile string-prefix checks with byte-level extraction (`extractIpv4Bytes`) covering the entire subnets:
   - `127.0.0.0/8` (Loopback)
   - `10.0.0.0/8` (RFC 1918 Private)
   - `172.16.0.0/12` (RFC 1918 Private, 172.16.0.0 – 172.31.255.255)
   - `192.168.0.0/16` (RFC 1918 Private)
   - `169.254.0.0/16` (RFC 3927 Link-Local)
   - IPv6 Unique-Local (`fc00::/7`), Link-Local (`fe80::/10`), and Loopback (`::1`)
     Evaluated at beginning, middle, and end addresses across dotted-decimal (`::ffff:172.16.0.1`), WHATWG-normalized hex (`::ffff:ac10:1`), bracketed/unbracketed, and upper/lowercase formats, while preserving the strict approved-endpoint allowlist invariant.
3. **Actual Live-Runner Integration Verification:** Added a full subprocess orchestration test (`tests/integration/live-runner-orchestration.test.ts`) invoking `scripts/security-lab/live.ts` against a local mock server. Demonstrated that when Candidate 1 yields a valid classification but missing usage:
   - Candidate 1 observation is preserved in `results.json` and `REPORT.md`.
   - The candidate loop halts immediately (`runStatus: 'stopped_unknown_provider_usage'`, `stopReason: 'unknown_provider_usage'`).
   - `estimatedKnownUsageCostUsd: null` and `dollarBudgetEnforced: false` are serialized.
   - Candidate 2 is never dispatched (exactly 1 provider call made).
   - Zero production evidence, attempt-locks, or reserved candidates are touched.

All 40 workspace test files (375 tests), build, eval typecheck, remediation typecheck, and full 12-step browser CDP verification pass cleanly.

---

## 2. Repository and Baseline Verification

- **Base commit:** `98d43d4`
- **Working branch:** `dev/phase-3-final-safety-remediation`
- **Working tree:** Clean working directory with non-destructive changes strictly isolated to:
  - `packages/meta-adapter/src/adapter.ts`
  - `packages/meta-adapter/src/providers.ts`
  - `packages/meta-adapter/src/index.ts`
  - `scripts/security-lab/live.ts`
  - `packages/meta-adapter/tests/strict-usage-validation.test.ts` (new)
  - `tests/integration/live-runner-orchestration.test.ts` (new)
  - `docs/security/phase-3/FINAL-SAFETY-REMEDIATION-REPORT.md` (this report)

---

## 3. Detailed Remediation 1: Strict Provider Usage Validation

### 3.1 Strict Integer & Alias Validation Design

In [`packages/meta-adapter/src/adapter.ts`](file:///Users/nilambarbehera/Documents/Projects/veylith/packages/meta-adapter/src/adapter.ts), four complementary functions enforce token validation:

- `isValidTokenCount(val: unknown): val is number`: Ensures values are numbers, integers, within safe limits (`Number.isSafeInteger(val)`), and non-negative (`val >= 0`). Rejects floats (e.g. `10.5`), strings (`'100'`), `NaN`, `Infinity`, negative numbers (`-1`), and numbers exceeding `Number.MAX_SAFE_INTEGER`.
- `resolveTokenCountWithAliases(primary: unknown, alias: unknown)`: Validates that if both primary (e.g. `prompt_tokens`) and alias (e.g. `input_tokens`) are provided, their values must be strictly identical (`primary === alias`). If they conflict, the ambiguity is rejected immediately.
- `resolveOptionalTokenCount(...candidates: unknown[])`: Validates optional token fields (such as `cached_tokens` and `reasoning_tokens`) across nested details objects and top-level fields, detecting alias collisions and invalid integers.
- `extractValidatedUsage(rawUsage: unknown): TokenUsage | null`: Unified parser validating both OpenAI Chat Completions and Meta Responses API payloads. Enforces that:
  - Containers `prompt_tokens_details`, `input_tokens_details`, `completion_tokens_details`, `output_tokens_details` must be non-array plain objects if present.
  - `cachedPromptTokens <= promptTokens`: Cached tokens cannot exceed prompt tokens.
  - `reasoningTokens <= completionTokens`: Reasoning tokens cannot exceed output tokens.
  - If valid, returns strongly typed `TokenUsage` `{ promptTokens, completionTokens, totalTokens, cachedPromptTokens, reasoningTokens }`.
  - If invalid, missing, malformed, or ambiguous, returns `null`.

### 3.2 Protocol Unification & Fail-Closed Behavior

Both `isChatCompletions` and Meta Responses API parsers in `MetaMuseSecurityAdapter` as well as the fetch interceptor in `scripts/security-lab/live.ts` call `extractValidatedUsage(rawJson['usage'])`.

When usage is `null`:

- The classification result is preserved (`action`, `threatCategory`, `confidence`, `evidence`).
- `hasUnknownUsage: true` and `tokenUsage: undefined` are recorded on the inspection result.
- `tracker.recordSuccessWithUnknownUsage(durationMs)` records that an unmetered call occurred.
- `tracker.getReport().estimatedCostUsd` evaluates to `null`.
- `tracker.getReport().dollarBudgetEnforced` evaluates to `false`.
- Subsequent inference attempts are immediately blocked locally by `assertWithinBudget()` before any network dispatch can occur.

### 3.3 Test Coverage (18 Scenarios)

The test suite in [`packages/meta-adapter/tests/strict-usage-validation.test.ts`](file:///Users/nilambarbehera/Documents/Projects/veylith/packages/meta-adapter/tests/strict-usage-validation.test.ts) exercises all 18 core scenarios:

1. Negative input tokens (`prompt_tokens: -1` / `input_tokens: -10`) -> `null`
2. Negative output tokens (`completion_tokens: -5` / `output_tokens: -1`) -> `null`
3. Fractional input tokens (`prompt_tokens: 10.5`) -> `null`
4. Fractional output tokens (`completion_tokens: 20.7`) -> `null`
5. String input tokens (`prompt_tokens: '100'`) -> `null`
6. String output tokens (`completion_tokens: '200'`) -> `null`
7. `NaN` input tokens (`prompt_tokens: NaN`) -> `null`
8. `Infinity` / `-Infinity` input or output tokens -> `null`
9. Unsafe integers exceeding `Number.MAX_SAFE_INTEGER` -> `null`
10. Missing input tokens -> `null`
11. Missing output tokens -> `null`
12. Null / undefined usage object -> `null`
13. Array or primitive non-object usage (`[10, 20]`, `'usage string'`, `12345`, `true`) -> `null`
14. Ambiguous conflicting aliases (`prompt_tokens: 10, input_tokens: 20`) -> `null` (non-conflicting accepted)
15. Invalid cached/reasoning tokens (e.g. negative, float, non-object details container) -> `null`
16. Cached tokens exceeding input tokens (`cached: 51, input: 50`) -> `null`
17. Reasoning tokens exceeding output tokens (`reasoning: 21, output: 20`) -> `null`
18. Valid extraction for Meta Responses API, OpenAI Chat Completions, and zero-token counts (`0, 0`).

---

## 4. Detailed Remediation 2: Complete IPv4-Mapped IPv6 Boundary Detection

### 4.1 Byte-Level IP Extraction

In [`packages/meta-adapter/src/providers.ts`](file:///Users/nilambarbehera/Documents/Projects/veylith/packages/meta-adapter/src/providers.ts), `extractIpv4Bytes(cleanHost)` extracts octets `[b0, b1, b2, b3]` by parsing:

- Native dotted-decimal IPv4 (`127.0.0.1`, `172.16.0.1`).
- Dotted-decimal IPv4-mapped IPv6 (`::ffff:127.0.0.1` or `0:0:0:0:0:ffff:127.0.0.1`).
- WHATWG URL normalized hex chunks (`::ffff:7f00:1`, `::ffff:ac10:1`, `::ffff:aff:ffff`).
- Bracketed and unbracketed inputs, case-insensitively.

### 4.2 Comprehensive Subnet Boundary Enforcement

`isLoopbackEndpoint` and `isPrivateNetworkEndpoint` evaluate the extracted bytes against complete subnet specifications:

- **127.0.0.0/8:** Beginning `127.0.0.0`, middle `127.42.0.1`, end `127.255.255.255` (and hex `::ffff:7f00:0` to `::ffff:7fff:ffff`).
- **10.0.0.0/8:** Beginning `10.0.0.0`, middle `10.128.0.1`, end `10.255.255.255` (and hex `::ffff:a00:0` to `::ffff:aff:ffff`).
- **172.16.0.0/12:** Beginning `172.16.0.0`, middle `172.24.0.1`, end `172.31.255.255` (and hex `::ffff:ac10:0` to `::ffff:ac1f:ffff`). Public neighbors `172.15.255.255` and `172.32.0.0` correctly pass through the private filter without false matches.
- **192.168.0.0/16:** Beginning `192.168.0.0`, middle `192.168.100.1`, end `192.168.255.255` (and hex `::ffff:c0a8:0` to `::ffff:c0a8:ffff`).
- **169.254.0.0/16:** Beginning `169.254.0.0`, middle `169.254.128.1`, end `169.254.255.255` (RFC 3927 Link-Local).
- **Native IPv6:** Unique-Local (`fc00::/7`), Link-Local (`fe80::/10`), Loopback (`::1`, `[::1]`, `::`).

### 4.3 Approved Endpoint Allowlist Invariant

Even for public, non-private endpoints, `validateProviderConfiguration()` strictly enforces that `parsedUrl.protocol === 'https:'`, no non-standard port is specified, and the normalized endpoint exactly matches `APPROVED_PROVIDERS[provider].approvedEndpoints`. Path traversal (`../`), subdomain spoofing (`api.fireworks.ai.attacker.org`), and unapproved third-party APIs (`api.openai.com`) are rejected unconditionally.

---

## 5. Detailed Remediation 3: Actual Live-Runner Integration Testing

### 5.1 Test Architecture

[`tests/integration/live-runner-orchestration.test.ts`](file:///Users/nilambarbehera/Documents/Projects/veylith/tests/integration/live-runner-orchestration.test.ts) runs a true integration test that exercises the full multi-tier pipeline:

1. Spawns an in-process HTTP mock server on `127.0.0.1`.
2. Generates a temporary isolated directory under `os.tmpdir()` containing:
   - A synthetic 2-candidate dataset (`SYNTHETIC-LIVE-01`, `SYNTHETIC-LIVE-02`).
   - A preload script (`mock-preload.cjs`) that routes external provider HTTPS calls to the local mock server.
3. Asynchronously spawns `scripts/security-lab/live.ts` with:
   - `--allow-paid --provider=fireworks --allow-unverified-pricing --max-requests=2 --max-total-tokens=8192 --max-cost-usd=0.05 --input-rate=1.0 --output-rate=1.0 --cached-rate=0.5`
   - `SECURITY_LAB_DESTINATION` and `SECURITY_LAB_DATASET` pointing to the temporary directory.
4. The mock server responds to Candidate 1 with HTTP 200, valid classification JSON, and omitted `usage`.
5. The live runner detects missing usage metadata, preserves Candidate 1, writes `results.json`, `REPORT.md`, and `usage.json`, and halts immediately.

### 5.2 Assertions Proved

- **Preservation:** Candidate 1 output is stored in `results.json` (`outputs[0].id === 'SYNTHETIC-LIVE-01'`) and reflected in `REPORT.md`.
- **Halt Condition:** `results.runStatus === 'stopped_unknown_provider_usage'` and `results.stopReason === 'unknown_provider_usage'`.
- **No Subsequent Dispatch:** Mock server receives exactly 1 request. Candidate 2 is never dispatched.
- **Cost Gating:** `results.estimatedKnownUsageCostUsd === null`, `results.dollarBudgetEnforced === false`, and `results.hasUnknownUsage === true`.
- **Evidence Protection:** Production reserved candidates (`security-lab/v1/live-reserve.json`) and production attempt locks are untouched.

---

## 6. Preserved Invariants & Safety Controls

| Invariant                      | Implementation Mechanism                                                                      | Verification Result                          |
| :----------------------------- | :-------------------------------------------------------------------------------------------- | :------------------------------------------- |
| **No Silent Live Inference**   | CLI requires explicit `--allow-paid` and provider API key                                     | Verified (exits code 1 without flag)         |
| **Fail-Closed Missing Usage**  | Missing, malformed, negative, or fractional usage marks `hasUnknownUsage: true`, cost `null`  | Verified (18 scenarios tested)               |
| **Halt Candidate Loop**        | Runner halts immediately on first unknown usage                                               | Verified (subsequent requests blocked)       |
| **Strict Subnet Rejection**    | `extractIpv4Bytes` covers 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, loopback | Verified across beginning, middle, end       |
| **Strict Allowlist Invariant** | Endpoints must match provider `approvedEndpoints`                                             | Verified (spoofs & traversals fail)          |
| **Offline Test Purity**        | All unit and integration tests run offline                                                    | Verified (0 network calls to real providers) |
| **Frozen Evidence Isolation**  | Reserved candidates (`security-lab/v1/live-reserve.json`) remain untouched                    | Verified (`git diff` clean)                  |

---

## 7. Comprehensive Regression Verification Results

### 7.1 Package Build

- **Command:** `pnpm run build`
- **Result:** Success (Exit code 0). 8 workspace projects built cleanly in 2.2s.

### 7.2 Security Lab Evaluation Typecheck

- **Command:** `pnpm security:eval:typecheck`
- **Target:** `scripts/security-lab/tsconfig.json`
- **Result:** Success (Exit code 0, 0 type errors).

### 7.3 Security Remediation Typecheck

- **Command:** `pnpm security:remediation:typecheck`
- **Target:** `scripts/security-remediation/tsconfig.json`
- **Result:** Success (Exit code 0, 0 type errors).

### 7.4 Complete Workspace Test Suite

- **Command:** `pnpm run test:all`
- **Scope:** All 40 test files across `packages/`, `apps/`, and `tests/integration/`
- **Result:**
  - **Test Files:** 40 passed (40 total)
  - **Tests:** 375 passed (375 total)
  - **Duration:** 17.48s
  - **Failures:** 0

### 7.5 Interactive Browser CDP Verification

- **Command:** `pnpm --filter @veylith/research-dashboard run verify:browser`
- **Scope:** 12-step headless Chrome DevTools Protocol automation
- **Result:**
  - Step 1: Overview View Loaded (14 scenarios, 8 metric cards) — PASS
  - Step 2: Keyboard Navigation "2" to Evaluation Lab — PASS
  - Step 3: Switch to Phase 2E Holdout Tab — PASS
  - Step 4: Toggle Mode Pills (100% FPR warning vs 52.1% Recall notice) — PASS
  - Step 5: Keyboard Navigation "3" to Audit Explorer & SHA-256 Chain Validation — PASS
  - Step 6: Live Search & Decision Filter (25 rows blocked, 0 leaks) — PASS
  - Step 7: Pagination Next/Prev Cycles across 1,945 records — PASS
  - Step 8: Detail Drawer Secret Redaction (masked session IDs, 0 leaks) — PASS
  - Step 9: Security Findings (8 findings, 6 locked reserved candidates, 0 run buttons) — PASS
  - Step 10: Mouse Navigation to Overview — PASS
  - Step 11: CSP Script Security (0 inline onclick handlers in live DOM) — PASS
  - Step 12: CSP Console Health (0 violations, 0 uncaught exceptions) — PASS

---

## 8. Holdout and Reserved Evaluation Invariance Audit

- **Live Reserve Candidates File:** [`security-lab/v1/live-reserve.json`](file:///Users/nilambarbehera/Documents/Projects/veylith/security-lab/v1/live-reserve.json)
  - Pre-remediation Git hash (base `0650d23`): Verified identical.
  - Active branch Git hash (`dev/phase-3-final-safety-remediation`): `git diff 0650d23..HEAD -- security-lab/v1/live-reserve.json` output is completely empty.
  - All 6 reserved candidates remain intact, unexecuted, and unexposed.
- **Live Results Artifacts:**
  - `find . -name "*live-result*" -o -name "*attempt-lock*"` returned 0 files.
  - No production attempt lock was created.

---

## 9. Residual Risks and Operational Recommendations

1. **Provider-Side Account Billing:** The application-level budget enforcement strictly limits request count and UTF-8 byte length, but cannot enforce provider-side monthly or credit billing. Live runs must be monitored on provider dashboards.
2. **Provider Key Provisioning:** Real live evaluation must continue to use interactive silent shell prompts or session-scoped environment variables. API keys must never be committed to disk or logged in audit records.
3. **Founder Authorization:** When the founder authorizes real-model evaluation, candidates 1 through 6 in `security-lab/v1/live-reserve.json` should be executed under single-shot `--allow-paid` with `--max-requests=6`.

---

## 10. Concluding Decision

### Decision: **A** — `READY FOR FINAL READ-ONLY RELEASE-GATE AUDIT`

All remediation tasks are complete, tested, and strictly fail-closed. The codebase is fully prepared for final independent release-gate auditing.
