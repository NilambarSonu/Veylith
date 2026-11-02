# Veylith — Phase 4A: Controlled Single-Request Live Compatibility Test Plan

> [!WARNING]
> **THIS DOCUMENT IS A RIGOROUS PREFLIGHT PLAN ONLY.**  
> **NO LIVE INFERENCE REQUEST HAS BEEN AUTHORIZED OR EXECUTED.**  
> **NO REAL API KEYS ARE STORED OR EXPOSED.**  
> **ALL SIX RESERVED LIVE EVALUATION CANDIDATES REMAIN LOCKED AND UNTOUCHED.**

---

## 1. Verified Baseline and Repository State

- **Repository:** `/Users/nilambarbehera/Documents/Projects/veylith`
- **Preflight Planning Branch:** `dev/phase-4-live-test-plan`
- **Base Branch:** `dev/phase-3-final-safety-remediation`
- **Verified Base Commit:** `028e07883b5e5af4a215172ba25d5b233c17e27d` (`028e078`)
- **Current Planning HEAD:** `b30cef6be04f27e5d5df4138be68876abf83b783` (`b30cef6`)
- **Working Tree Status:** Clean, zero uncommitted modifications.
- **Offline Verification Baseline:**
  - Workspace Build: 8 packages built cleanly in 1.4s (`pnpm run build`, exit code 0).
  - Evaluation Typecheck: `scripts/security-lab/tsconfig.json` passed with 0 errors (`pnpm security:eval:typecheck`, exit code 0).
  - Remediation Typecheck: `scripts/security-remediation/tsconfig.json` passed with 0 errors (`pnpm security:remediation:typecheck`, exit code 0).
  - Test Suite: 40 test files, 375 of 375 tests passed (`pnpm run test:all`, exit code 0).
  - Reserved Candidates: All 6 candidates in `security-lab/v1/live-reserve.json` byte-for-byte identical to baseline (`0650d23` / `98d43d4`).
  - Production Artifacts: Zero `attempt.json`, `attempt-lock`, or `live-results` artifacts exist.

---

## 2. Multi-Provider Compatibility Assessment

Veylith supports three candidate model providers through its unified security adapter layer (`packages/meta-adapter/src/providers.ts`):

| Requirement / Attribute           | Meta Model API (`meta`)                                                                                                                       | Fireworks AI (`fireworks`)                                                                                                                                                      | Baseten (`baseten`)                                                                                                                                                             |
| :-------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **API Protocol**                  | Meta Responses API (`meta-responses`)                                                                                                         | OpenAI Chat Completions (`openai-chat-completions`)                                                                                                                             | OpenAI Chat Completions (`openai-chat-completions`)                                                                                                                             |
| **Approved HTTPS Endpoint**       | `https://api.meta.ai/v1/responses`                                                                                                            | `https://api.fireworks.ai/inference/v1/chat/completions`                                                                                                                        | `https://inference.baseten.co/v1/chat/completions`                                                                                                                              |
| **Allowlisted Model**             | `muse-spark-1.3`                                                                                                                              | `accounts/fireworks/models/muse-spark-open`                                                                                                                                     | `meta-models/muse-spark-open-1026`                                                                                                                                              |
| **Credential Variable**           | `META_MODEL_API_KEY` (alt: `META_API_KEY`)                                                                                                    | `FIREWORKS_API_KEY`                                                                                                                                                             | `BASETEN_API_KEY`                                                                                                                                                               |
| **Pricing Verification**          | **Verified (`true`)**                                                                                                                         | **Unverified (`false`)**                                                                                                                                                        | **Unverified (`false`)**                                                                                                                                                        |
| **Official Published Rates**      | Standard Input: \$1.25 / 1M tokens<br>Cached Input: \$0.15 / 1M tokens<br>Output: \$4.25 / 1M tokens                                          | Unverified / Dynamic (varies by deployment tier)                                                                                                                                | Unverified / Dynamic (varies by dedicated instance)                                                                                                                             |
| **Dollar Budget Cap Enforcement** | **Enforced by application (`true`)**                                                                                                          | **Unbounded by application (`false`)**                                                                                                                                          | **Unbounded by application (`false`)**                                                                                                                                          |
| **Usage Metadata Structure**      | `usage.input_tokens`<br>`usage.output_tokens`<br>`usage.input_tokens_details.cached_tokens`<br>`usage.output_tokens_details.reasoning_tokens` | `usage.prompt_tokens`<br>`usage.completion_tokens`<br>`usage.total_tokens`<br>`usage.prompt_tokens_details.cached_tokens`<br>`usage.completion_tokens_details.reasoning_tokens` | `usage.prompt_tokens`<br>`usage.completion_tokens`<br>`usage.total_tokens`<br>`usage.prompt_tokens_details.cached_tokens`<br>`usage.completion_tokens_details.reasoning_tokens` |
| **Max Output Tokens**             | Fixed bound: **512 tokens**                                                                                                                   | Fixed bound: **512 tokens**                                                                                                                                                     | Fixed bound: **512 tokens**                                                                                                                                                     |
| **Request Timeout**               | **5,000 ms** (`AbortSignal.timeout`)                                                                                                          | **5,000 ms** (`AbortSignal.timeout`)                                                                                                                                            | **5,000 ms** (`AbortSignal.timeout`)                                                                                                                                            |
| **HTTP Redirects**                | `redirect: 'error'` (fails closed)                                                                                                            | `redirect: 'error'` (fails closed)                                                                                                                                              | `redirect: 'error'` (fails closed)                                                                                                                                              |
| **Transport Retries**             | **0** (Disabled, throws on failure)                                                                                                           | **0** (Disabled, throws on failure)                                                                                                                                             | **0** (Disabled, throws on failure)                                                                                                                                             |
| **Provider Fallback**             | **Disabled** (Fail closed)                                                                                                                    | **Disabled** (Fail closed)                                                                                                                                                      | **Disabled** (Fail closed)                                                                                                                                                      |
| **Credential Redaction**          | Strips API keys and Bearer tokens                                                                                                             | Strips API keys and Bearer tokens                                                                                                                                               | Strips API keys and Bearer tokens                                                                                                                                               |

### Meta Pricing Verification and Reference Documentation

- **Official Documentation Source:** [https://dev.meta.ai/docs/pricing-rate-limits](https://dev.meta.ai/docs/pricing-rate-limits)
- **Date Checked:** October 30, 2026.
- **Service Tier:** Standard Developer API (not Contributor mode).
- **Published Rates:**
  - Standard Input Tokens: **\$1.25 USD** per 1,000,000 tokens (\$0.00000125 / token).
  - Cached Input Tokens: **\$0.15 USD** per 1,000,000 tokens (\$0.00000015 / token).
  - Output Tokens: **\$4.25 USD** per 1,000,000 tokens (\$0.00000425 / token).
- **Rate Dynamism Notice:** Meta pricing represents published rates as of October 30, 2026. External provider pricing is **not immutable** and is subject to provider schedule changes, account agreements, and billing revisions.
- **Application Pricing Protection:** Per `scripts/security-lab/live.ts` lines 70–74, the live runner asserts that any caller-supplied rates strictly equal `1.25`, `4.25`, and `0.15`. Any caller-supplied override attempting to masquerade lower or unverified rates as official rates triggers an immediate fatal error before dispatch.

---

## 3. Recommended Initial Provider & Rationale

### Recommendation: **Meta Model API (`meta`)**

**Technical Rationale:**

1. **Verified Pricing Safeguard:** Meta is the only provider with verified rates configured in `APPROVED_PROVIDERS` (`packages/meta-adapter/src/providers.ts:44-50`). The live runner enforces verified rates and guarantees pre-dispatch dollar budget cap enforcement (`dollarBudgetEnforced: true`).
2. **Founder Policy Invariant:** Both Fireworks and Baseten have unverified pricing (`pricingVerified: false`). Proceeding with Fireworks or Baseten requires `--allow-unverified-pricing` and explicitly disclaims application-level dollar budget capping (`live.ts:61-67`). Per safety rules, unverified pricing must not be used as the default target when a verified provider is available.
3. **Native Architecture Alignment:** Meta Muse (`muse-spark-1.3`) is the primary native security model upon which Veylith's structured classification schema and hybrid boundary engine were architected.
4. **Tested Usage Protocol:** Meta Responses API usage metadata parsing has complete test coverage in `packages/meta-adapter/tests/strict-usage-validation.test.ts` (Scenario 18).

---

## 4. Single Synthetic Test Case Design & Offline Validation

To prevent consuming any unseen evaluation cases or historical benchmark data, exactly one synthetic, non-reserved case is defined in `security-lab/compat-case.json`:

### Case Specification: `SYNTH-COMPAT-LIVE-01`

- **Case ID:** `SYNTH-COMPAT-LIVE-01`
- **Scenario ID:** `G1` (Live Boundary Compatibility Check)
- **Stage:** `call_response`
- **Split:** `compatibility-canary` (Separate from `live-reserve`)
- **Reserved Unseen:** `false` (Non-reserved synthetic test case)
- **Objective:** Verify end-to-end transport, authentication, schema extraction, usage tracking, latency measurement, cost calculation, and local evidence generation through the actual Veylith gateway and live runner.
- **Exact Proposed Input:**
  ```text
  Summarize the general concept of principle of least privilege in computer security in one concise sentence.
  ```

### Design Justification:

1. **Input Size Minimization:** 107 UTF-8 bytes (~26 tokens). Minimizes billable input tokens and latency while safely remaining well under the 12,000-character input length limit.
2. **Zero Sensitive Data:** Contains no personal data, credentials, internal architecture details, or proprietary text.
3. **Independence from Reserved Holdouts:** Does not resemble or overlap with the 6 reserved adversarial candidates (which test indirect injection, directive override, synthetic key leak, and tool sink exfiltration).
4. **Structured Output Exercise:** Requests a concise, benign security definition, giving the model clear context to return structured JSON complying with `ModelClassificationSchema`.

### Offline Dataset Validation Results:

The synthetic dataset was rigorously validated offline against Veylith's dataset parsing and policy engine routing paths:

- **Fixture File:** `security-lab/compat-case.json`
- **File SHA-256:** `943b72268b7ac8d158e14b85347d20f7694a10ccab93f18fd2e8a28b816096dd`
- **Parser Acceptance:** Read and parsed cleanly by `JSON.parse` as expected by `live.ts:134`.
- **Case Count:** Exactly 1 (`parsed.length === 1`).
- **ID Uniqueness:** 0 collisions against all IDs in `live-reserve.json`, `holdout.json`, and `development.json`.
- **Input Uniqueness:** 0 text matches or semantic overlaps against any reserved candidate.
- **Holdout Isolation:** Completely independent of `security-lab/v1/live-reserve.json` and `manifest.json`.
- **Path Resolution:** Resolves via `SECURITY_LAB_DATASET=security-lab/compat-case.json` (`live.ts:101`).
- **Policy Engine Routing:** Evaluated through `BoundaryRouter.route()`. Because the natural-language input is unpinned and unquoted, the boundary screener returns:
  ```json
  {
    "verdict": {
      "type": "ambiguous",
      "riskLevel": "medium",
      "suspiciousSignals": ["untrusted-natural-language"]
    },
    "trace": { "decision": "needs_semantic_review", "reason": "untrusted-natural-language" }
  }
  ```
  This guarantees that the input is routed to `infer()` and `gw.metaAdapter.inspect()`, rather than taking the deterministic bypass fast path.
- **End-to-End Offline Integration Test:** Verified by `tests/integration/phase-4a-offline-routing.test.ts`, which boots the gateway, calls `reader` over MCP Streamable HTTP transport, confirms semantic inspection routing, validates the mock adapter invocation with `compatCase.input`, and asserts zero external network calls.

### Expected Classification Schema:

```json
{
  "flagged": false,
  "threatCategory": "none",
  "action": "allow",
  "confidence": 0.99,
  "explanation": "General computer security principle summary without adversarial directives.",
  "evidence": []
}
```

### Expected Provider Usage Metadata:

- `usage.input_tokens`: Safe positive integer (~200–450 tokens, accounting for system prompt and XML delimiters).
- `usage.output_tokens`: Safe positive integer (~20–60 tokens).
- `usage.input_tokens_details.cached_tokens`: Safe non-negative integer (optional, `<= input_tokens`).
- `usage.output_tokens_details.reasoning_tokens`: Safe non-negative integer (optional, `<= output_tokens`).

### Expected Local Evidence Fields:

- Local destination directory: `security-lab/compat-results`
- `attempt.json`: Documents founder authorization, commit hash, verified pricing status, request ceiling (1), and cost ceiling (\$0.01).
  - Provenance fields (Phase 4B.3): `datasetPath` (safe repository-relative path), `datasetSha256` (exact raw-byte digest), `manifestVerified` (`false` for custom datasets; `true` for frozen benchmark), `manifestVerification` (`'not_applicable'` for custom; `'verified'` for frozen benchmark), and `manifestSha256` (`'not_applicable'` for custom; frozen manifest hash for benchmark).
  - _Historical Canary Note:_ The Phase 4B.1 canary `attempt.json` contains `"manifestSha256": "mock-test-manifest"`, which was an intentional test sentinel in prior runner code. It is preserved without retroactive alteration.
- `results.json`: Documents `runStatus: 'completed'`, `stopReason: null`, `pricingVerified: true`, `dollarBudgetEnforced: true`, `attemptedRequests: 1`, `estimatedKnownUsageCostUsd: <calculated_float>`.
- `REPORT.md`: Formatted Markdown summary with pipeline metrics and cost.
- `usage.json`: Breakdown of attempted requests, reserved tokens, and verified cost.

### Failure Conditions:

- HTTP non-200 status (e.g. 401 Unauthorized, 403 Forbidden, 429 Rate Limit, 500/503 Outage).
- Response body truncation (`finish_reason === 'length'`) or incomplete response.
- Response body fails `ModelClassificationSchema` validation.
- Usage metadata is omitted, null, malformed, negative, fractional, or non-integer.
- Cached tokens exceed input tokens or reasoning tokens exceed output tokens.
- Request count exceeds 1.
- Pre-dispatch cost estimation exceeds \$0.01 USD.
- Latency exceeds 5,000 ms.
- API key appears in logs or error output.

---

## 5. Cost Guard Analysis & Enforced Limits

The live runner (`scripts/security-lab/live.ts`) enforces the following hardware and software bounds:

| Boundary Parameter       | Enforced Value                                      | Enforcement Mechanism                                                                                         | File & Line Reference                      |
| :----------------------- | :-------------------------------------------------- | :------------------------------------------------------------------------------------------------------------ | :----------------------------------------- |
| **Max Requests**         | **At most 1**                                       | CLI flag `--max-requests=1`; runner pre-check throws if `attemptedRequests >= maxRequests`                    | `live.ts:268`                              |
| **Max Total Tokens**     | **4,096 tokens**                                    | CLI flag `--max-total-tokens=4096`; runner throws if `reservedTokens + estimatedReservationBound > maxTokens` | `live.ts:269`                              |
| **Max Output Tokens**    | **512 tokens**                                      | Runner interceptor enforces `payload.max_output_tokens === 512`                                               | `live.ts:261`                              |
| **Max Input Length**     | **12,000 characters**                               | Runner interceptor checks `payload.input.length <= 12000`                                                     | `live.ts:250`                              |
| **Request Timeout**      | **5,000 ms**                                        | `AbortSignal.timeout(5000)` on native fetch                                                                   | `packages/meta-adapter/src/adapter.ts:474` |
| **Transport Retries**    | **0**                                               | No retry loop; transport failure throws immediately                                                           | `live.ts:310`                              |
| **Provider Fallback**    | **0**                                               | `FAIL_CLOSED: 'true'`; no cross-provider fallback                                                             | `packages/meta-adapter/src/adapter.ts:468` |
| **Max Application Cost** | **\$0.01 USD threshold**                            | CLI flag `--max-cost-usd=0.01`; runner pre-check throws if `reservedCost + costBound > maxCost`               | `live.ts:275`                              |
| **Verified Rates**       | **Input: \$1.25 / Output: \$4.25 / Cached: \$0.15** | Runner asserts `inputRate === 1.25 && outputRate === 4.25 && cachedRate === 0.15`                             | `live.ts:70-74`                            |

---

### Independent Verification of Budget Guard Questions (Audit 2)

#### 1. Source of the 1,850-byte input figure

`scripts/security-lab/live.ts` lines 248–251 calculates `conservativeInputBytesBound = Buffer.byteLength(payload.input)`. When serialized by `MetaMuseSecurityAdapter.inspect()` (`packages/meta-adapter/src/adapter.ts:480-511`), the complete `payload.input` for `SYNTH-COMPAT-LIVE-01` measures exactly **1,855 UTF-8 bytes** (the 1,850-byte figure was a rounded approximation of this value).

#### 2. Scope of serialized provider input

It represents the complete serialized `payload.input` string sent to Meta Responses API, **not** just the 107-byte synthetic case text.

#### 3. Fields included in the input estimate

It includes the complete formatted inspection prompt assembled by `formatInspectionPrompt()` (`packages/meta-adapter/src/prompts.ts`):

- System instructions and security policy framing.
- Classification guidelines and schema definition instructions.
- Stage metadata (`[Stage: call_response]`).
- XML wrapper delimiters (`<untrusted_content_to_classify>`).
- The synthetic prompt text.
  _(Note: Top-level JSON body fields such as `model`, `reasoning`, and `text.format.schema` are parsed by the interceptor from the JSON body; Meta's billing meters billable input tokens on the prompt passed to `input`.)_

#### 4. Approximation vs guaranteed tokenizer upper bound

`scripts/security-lab/live.ts` lines 244–247 explicitly documents:

```ts
// Buffer.byteLength is a conservative UTF-8 byte approximation of input length,
// NOT an exact model tokenizer output and NOT a mathematically guaranteed tokenizer upper bound.
```

For English ASCII/UTF-8 text, 1 byte per token is an empirical conservative upper bound (standard BPE tokenizers yield ~3.5 to 4 characters per token). However, it is **not** a mathematically or provider-guaranteed tokenizer bound.

#### 5. Meaning of `--max-total-tokens=4096`

`scripts/security-lab/live.ts` lines 264–270:

```ts
const estimatedReservationBound = conservativeInputBytesBound + 512;
if (attemptedRequests >= maxRequests || reservedTokens + estimatedReservationBound > maxTokens) {
  throw new Error('Manual run request or conservative token-reservation limit reached');
}
```

`--max-total-tokens` limits the **cumulative pre-dispatch token reservation** across the entire run. For each request, the reservation bound is input bytes + 512 output tokens. For `SYNTH-COMPAT-LIVE-01`, $1855 + 512 = 2367 \text{ tokens} \le 4096 \text{ tokens}$.

#### 6. Transmission and enforcement of the 512 output limit

**Yes.**

- Sent in the request body to Meta: `max_output_tokens: this.config.maxOutputTokens` (`packages/meta-adapter/src/adapter.ts:509`).
- Strictly enforced by the live runner interceptor before dispatch: `if (maxOutputTokens !== 512) throw new Error(...)` (`live.ts:261-262`).

#### 7. Behavior when cost estimate is missing, malformed, or unknown

**Fails closed.** Requests **cannot** be dispatched:

- Rates must be positive finite numbers (`live.ts:51-57`).
- Verified rates for Meta must match official rates exactly (`live.ts:70-74`).
- `costBound` is calculated before every call (`live.ts:265`).
- Pre-dispatch cost gate evaluates `if (def.pricingVerified && reservedCost + costBound > maxCost)` (`live.ts:275`). For Meta, `def.pricingVerified === true`, making this gate active. If unverified rates or missing flags are encountered at startup, execution aborts before `nativeFetch`. For unverified providers (Fireworks, Baseten), `def.pricingVerified === false`, meaning the dollar cost gate is bypassed (only token/request limits apply, and `--allow-unverified-pricing` is required).

#### 8. Can estimated cost exceed \$0.01 USD?

**No, at the application pre-dispatch level for Meta.**

- The **\$0.01 USD** limit is strictly an **application-level estimated-cost pre-dispatch threshold** enforced locally before any network dispatch.
- It is **not** a guaranteed provider billing cap; the application cannot query or constrain external provider-side account billing ledgers.
- Input token accounting uses UTF-8 bytes as an empirical heuristic (`Buffer.byteLength(payload.input)`), **not** a formally verified tokenizer upper bound.
- **Check Ordering & Primary Blocking Gate for Meta (`live.ts:267-277`):**
  - In `live.ts`, the token-reservation check (`reservedTokens + estimatedReservationBound > maxTokens`, line 269) is evaluated **before** the cost spending gate (`def.pricingVerified && reservedCost + costBound > maxCost`, line 275).
  - For the proposed Meta configuration (`def.pricingVerified === true`), both checks are active and evaluate the identical `conservativeInputBytesBound` and fixed 512-token output limit.
  - Under the proposed command (`--max-total-tokens=4096`, `--max-requests=1`, `--max-cost-usd=0.01`), the token reservation gate enforces:
    $$\text{Max Input Bytes} = 4{,}096 - 512 = 3{,}584 \text{ bytes}$$
  - At the maximum allowable 3,584 bytes, the pre-dispatch cost proxy is:
    $$\text{Cost Bound} = \frac{(3584 \times 1.25) + (512 \times 4.25)}{1{,}000{,}000} = \frac{4480 + 2176}{1{,}000{,}000} = \$0.006656 \text{ USD}$$
  - Because $\$0.006656 < \$0.010000$, any input exceeding 3,584 bytes is rejected by the **token-reservation gate first** (`live.ts:269`).
  - Therefore, the **\$0.01 cost gate cannot independently become the first blocking gate** under the proposed Meta command configuration.
  - The theoretical 6,259.2 byte threshold (derived from $\frac{0.01 - 0.002176}{0.00000125}$) represents the cost gate limit in isolation and would only become active if `--max-total-tokens` were configured above $6{,}259 + 512 = 6{,}771$ tokens (e.g. `--max-total-tokens=8192`).
  - **Important:** `$0.006656` is strictly the local cost proxy at the maximum input reservation, **not** a provider billing maximum. Unmeasured request fields (`model`, `reasoning`, `text.format.schema`) and server-side framing tokens remain outside this local formula.
- **Actual financial charges must be checked against Meta billing records** on the provider dashboard.

#### 9. Can the provider charge more than the application estimate?

**Yes.**

- The application estimate is an internal client-side preflight gate based on UTF-8 byte heuristics.
- Provider billing is governed by Meta's server-side BPE tokenizer, metering infrastructure, account agreements, and billing rules.
- Discrepancies between client heuristics and provider tokenization can exist. Actual charges must be confirmed independently on the Meta developer dashboard.

---

### Three Distinct Cost Domains (Non-Interchangeable)

1. **Byte-Derived Application Cost Proxy (Pre-Dispatch):** Client-side safety threshold calculated as:
   $$\text{Pre-Dispatch Cost Bound} = \frac{(1855 \times 1.25) + (512 \times 4.25)}{1{,}000{,}000} = \$0.00449475 \text{ USD} \approx \$0.0045 \text{ USD}$$
   - Evaluates UTF-8 bytes as an empirical proxy for input tokens; no model tokenizer is called.
   - The byte count evaluates only `Buffer.byteLength(payload.input)`. Request fields outside `payload.input` (`model`, `reasoning`, `text.format.schema`) and server-side formatting tokens are not included. Whether Meta meters them as billable input tokens is **unknown** prior to live telemetry.
   - Cached rate (\$0.15 / 1M) is verified at startup (`live.ts:70`), but does **not** participate in the pre-dispatch `costBound` calculation (the formula prices all 1,855 input bytes at the standard \$1.25 rate).
   - Strictly gates whether the HTTP request is permitted to leave the machine against `--max-cost-usd=0.01`.
2. **Actual Usage-Based Cost (Post-Response):** Calculated upon receiving valid `usage` metadata from Meta:
   $$\text{Actual Usage Cost} = \frac{(\text{promptTokens} \times 1.25) + (\text{completionTokens} \times 4.25)}{1{,}000{,}000}$$
   Recorded in `usage.json` and `results.json`.
3. **Provider-Side Billing:** Financial charges recorded on Meta's developer platform, subject to Meta's internal server-side metering, account rate schedules, and billing ledgers. Any assumptions regarding account-level minimum increments or rounding remain unverified provider mechanics.

---

### Request-Dispatch Semantics & Counter Timing

- **Counter Increment Timing (`live.ts:279`):** The counter `attemptedRequests++` increments after pre-dispatch parameter, token, and cost checks pass, immediately before invoking `nativeFetch` (`live.ts:295`).
- **Proof of Dispatch Attempt:** Incrementing the counter proves only that the runner attempted dispatch; it does **not** prove provider receipt or processing.
- **Four Distinct Dispatch Outcomes:**
  1. **Outcome A — Pre-dispatch check fails (0 attempts, counter = 0):** Input length, token budget, or cost threshold fails. Native fetch is never called.
  2. **Outcome B — Transport failure or timeout during fetch (1 attempt, provider receipt unconfirmed, no retry, stop):** Network timeout (5,000 ms), DNS failure, or connection drop occurs. `entry['networkFailure'] = true` is recorded, `usage.json` is written in `finally`, and runner aborts candidate loop without retrying. **Dispatch status is uncertain.** Reconcile on Meta developer dashboard offline.
  3. **Outcome C — Provider returns HTTP error response (1 attempt, error recorded, stop):** Meta returns HTTP 4xx or 5xx. Recorded in `usage.json`, usage marked unknown, Candidate 1 observation preserved, candidate loop halts.
  4. **Outcome D — Provider returns valid response (1 attempt, response processed, stop):** Meta returns HTTP 200 with structured JSON and valid usage metadata. Parsed, recorded, Candidate 1 completes and runner halts.

---

### Arithmetic Correction & Illustrative Post-Response Cost (Audit 3)

> [!NOTE]
> The Phase 4A initial plan stated: `~$0.0005 USD (half of one US cent)`.
>
> **Corrections & Explicit Cost Distinctions:**
>
> - $\$0.0005 \text{ USD} = 0.05 \text{ cents}$ ($5$ hundredths of a cent; $\$0.005 \text{ USD}$ is $0.5 \text{ cents}$ / half of one US cent).
> - Prior to executing live inference, **no actual usage measurement exists**.
> - The post-response calculation of **`$0.000545 USD` ($0.0545 \text{ cents}$)** is strictly an **illustrative estimate only**, under the explicit assumptions of **300 input tokens** and **40 output tokens**:
>   $$\text{Illustrative Cost} = \frac{(300 \times 1.25) + (40 \times 4.25)}{1{,}000{,}000} = \frac{375 + 170}{1{,}000{,}000} = \$0.000545 \text{ USD} = 0.0545 \text{ cents}$$
> - The **\$0.01 USD** limit is an application-level estimated-cost pre-dispatch threshold, not a guaranteed provider billing cap.
> - UTF-8 bytes are a heuristic, not a formally verified tokenizer upper bound.
> - Actual financial charges must be checked against Meta billing records.

---

## 6. End-to-End Execution Path Architecture (Audit 5)

The future execution command exercises the full Veylith security gateway architecture:

```
+-----------------------------------------------------------------------------------+
| Live Runner CLI (scripts/security-lab/live.ts)                                   |
|   1. Loads dataset: security-lab/compat-case.json                                 |
|   2. Validates CLI flags, pricing rates, and env vars                             |
|   3. Installs globalThis.fetch network interceptor                               |
|   4. Starts Fixture MCP server (in-memory test tool: reader)                      |
|   5. Boots Gateway HTTP server (apps/gateway/src/server.ts)                       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| MCP Client & Gateway Communication                                                |
|   6. MCP Client connects via StreamableHTTPClientTransport to 127.0.0.1:${port}/mcp |
|   7. Client dispatches tool call: client.callTool({ name: 'reader', arguments: {} })|
|   8. Gateway forwards call to Fixture; Fixture returns candidate input text       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| Policy Inspection & Boundary Routing (packages/policy-engine)                     |
|   9. Gateway intercepts response: securityEngine.inspectResponse()                |
|  10. BoundaryRouter.route() evaluates candidate input                             |
|  11. Unpinned natural language routes to: decision: 'needs_semantic_review'       |
|  12. BoundaryInspector.infer() triggers semantic evaluation                       |
|  13. Calls gw.metaAdapter.inspect(content, 'call_response', metadata)             |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| Security Adapter & Network Interception (packages/meta-adapter)                   |
|  14. MetaMuseSecurityAdapter formats fullPrompt with system instructions & schema  |
|  15. Formats POST body: { model, input, text: { format: ... }, max_output_tokens }|
|  16. Sets headers: Authorization: Bearer <META_MODEL_API_KEY>                     |
|  17. Dispatches fetch('https://api.meta.ai/v1/responses')                         |
|  18. live.ts fetch interceptor validates:                                         |
|      - Approved HTTPS endpoint & model                                            |
|      - Loopback token isolation (no credentials on 127.0.0.1)                      |
|      - Token reservation: bytes + 512 <= 4096                                     |
|      - Cost ceiling: costBound <= $0.01 USD                                       |
|      - Max requests: attemptedRequests < 1                                        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| External Provider Inference                                                       |
|  19. nativeFetch sends 1 POST request to https://api.meta.ai/v1/responses (443)   |
|  20. Meta Responses API returns HTTP 200 with JSON payload & usage metadata       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------+-----------------------------------------+
| Evidence Recording & Pipeline Completion                                          |
|  21. Interceptor extracts & validates usage; writes usage.json                    |
|  22. Adapter validates ModelClassificationSchema; records tracker metrics         |
|  23. Gateway logs tamper-evident record to AuditLogChain                          |
|  24. Client receives sanitized/delivered tool output                              |
|  25. Live runner writes <id>-plan.json, results.json, REPORT.md                   |
|  26. Gateway and Fixture servers shut down cleanly                                |
+-----------------------------------------------------------------------------------+
```

---

## 7. Future Execution Command & Operator Safeguards (Audit 6)

> [!CAUTION]
> **DO NOT EXECUTE THIS SCRIPT IN PHASE 4A.**
> Execution is strictly reserved for Phase 4B following explicit founder authorization.

To prevent accidental dispatch, credential leakage in shell histories, or unbounded spending, Phase 4B execution must utilize the following hardened subshell procedure:

```bash
(
  set +x

  # 1. Register cleanup traps to purge credentials on exit, interrupt, or termination
  trap 'unset META_MODEL_API_KEY META_API_KEY; echo -e "\n[Veylith] Session terminated: credentials purged from environment."' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  echo "================================================================="
  echo "  VEYLITH PHASE 4B: CONTROLLED LIVE COMPATIBILITY PREFLIGHT      "
  echo "================================================================="

  # 2. Silent terminal input (never echo key or record in history; compatible with Zsh and Bash)
  printf "Enter Meta Model API Key (input will be hidden): "
  IFS= read -r -s META_MODEL_API_KEY
  printf "\n"

  if [ -z "${META_MODEL_API_KEY:-}" ]; then
    echo "Error: META_MODEL_API_KEY was not provided. Aborting."
    exit 1
  fi
  export META_MODEL_API_KEY

  echo "Credential registered safely in isolated subshell environment."
  echo ""
  echo "-----------------------------------------------------------------"
  echo "TEST PARAMETERS:"
  echo "  - Provider:           meta (Meta Model API)"
  echo "  - Model:              muse-spark-1.3"
  echo "  - Target Endpoint:    https://api.meta.ai/v1/responses"
  echo "  - Total Requests:     AT MOST 1 (zero retries, zero fallback)"
  echo "  - Max Output Limit:   512 tokens"
  echo "  - Token Budget:       4,096 tokens (conservative byte bound)"
  echo "  - Cost Threshold:     \$0.01 USD (application pre-dispatch)"
  echo "  - Test Split:         compatibility-canary (SYNTH-COMPAT-LIVE-01)"
  echo "  - Reserved Holdouts:  LOCKED (0 of 6 reserved candidates touched)"
  echo "-----------------------------------------------------------------"
  echo "NOTICE: THIS ACTION SENDS ONE REAL PAID REQUEST TO META RESPONSES API."
  echo "-----------------------------------------------------------------"

  # 3. Manual operator confirmation check in wrapper script
  printf "Type exactly 'CONFIRM LIVE META CALL' to proceed: "
  IFS= read -r CONFIRMATION_PHRASE

  if [ "$CONFIRMATION_PHRASE" != "CONFIRM LIVE META CALL" ]; then
    echo "Execution aborted: confirmation phrase did not match."
    exit 1
  fi

  echo ""
  echo "Authorization confirmed. Executing single compatibility request..."

  # 4. Execute single-request live evaluation runner inside subshell
  SECURITY_LAB_DESTINATION=security-lab/compat-results \
  SECURITY_LAB_DATASET=security-lab/compat-case.json \
  pnpm security:eval:live -- \
    --allow-paid \
    --provider=meta \
    --max-requests=1 \
    --max-total-tokens=4096 \
    --max-cost-usd=0.01 \
    --input-rate=1.25 \
    --output-rate=4.25 \
    --cached-rate=0.15
)
```

---

## 8. Mandatory Stop Conditions

The live test must abort immediately before or during execution if any of the following occur:

1. **Pre-Dispatch Configuration Mismatch:**
   - Provider is not `meta`.
   - Model is not `muse-spark-1.3`.
   - Endpoint is not `https://api.meta.ai/v1/responses`.
   - Input/output/cached rates differ from verified rates (`1.25`, `4.25`, `0.15`).
2. **Missing Credential:**
   - `META_MODEL_API_KEY` is undefined, empty, or whitespace.
3. **Budget Pre-Check Failure:**
   - Request count ceiling exceeds 1.
   - Pre-dispatch token reservation exceeds 4,096 tokens.
   - Pre-dispatch estimated cost exceeds \$0.01 USD.
4. **Network Boundary Invariants:**
   - Loopback destination (`127.0.0.1`, `localhost`, `::1`) carries `Authorization` header.
   - External request URL is not in `APPROVED_PROVIDERS['meta'].approvedEndpoints`.
   - HTTP redirect (3xx) is returned (`redirect: 'error'`).
   - Non-standard port (not 443) is targeted.
5. **Inference & Parsing Errors:**
   - HTTP status is non-200.
   - Latency exceeds 5,000 ms timeout.
   - Response status is `incomplete`, `failed`, or `finish_reason === 'length'`.
   - Response fails `ModelClassificationSchema` validation.
6. **Usage Metadata Failure (Fail-Closed Stop):**
   - `usage` object is missing or null.
   - Token counts are negative, fractional, strings, `NaN`, `Infinity`, or unsafe integers.
   - Conflicting aliases are detected (`input_tokens !== prompt_tokens`).
   - Cached tokens exceed input tokens or reasoning tokens exceed output tokens.

**Critical Rule:** If usage is missing or malformed, preserve Candidate 1 output, record `runStatus: 'stopped_unknown_provider_usage'`, set cost to `null`, set `dollarBudgetEnforced: false`, and stop immediately. Never retry or issue a second call.

---

## 9. Expected Successful Response and Classification

A successful single compatibility call will produce:

- **HTTP Status:** 200 OK
- **Classification Output:**
  ```json
  {
    "flagged": false,
    "threatCategory": "none",
    "action": "allow",
    "confidence": 0.99,
    "explanation": "Summarizes the principle of least privilege in security without containing malicious payloads or prompt injection directives.",
    "evidence": []
  }
  ```
- **Extracted Usage:**
  - `promptTokens`: ~250–400
  - `completionTokens`: ~30–60
  - `totalTokens`: `promptTokens + completionTokens`
  - `cachedPromptTokens`: `>= 0` and `<= promptTokens`
  - `reasoningTokens`: `>= 0` and `<= completionTokens`
- **Estimated Cost:** Numeric float (illustrative estimate: `~$0.0005 USD`), strictly `< $0.01 USD`.
- **Latency:** Sub-second to ~3,000 ms.

---

## 10. Expected Failure Handling & Fail-Closed Protocols

| Failure Scenario        | Live Runner Action                                                                                                                           | Audit Log Action                                     | Gateway Behavior                                     |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------- | :--------------------------------------------------- |
| **HTTP 401 / 403**      | Aborts run; sanitizes key in error string                                                                                                    | Logs `decision: 'block'`, `reason: 'meta_api_error'` | Quarantines tool response                            |
| **HTTP 429 Rate Limit** | Aborts run immediately (no retries)                                                                                                          | Logs provider rate limit error                       | Quarantines tool response                            |
| **HTTP 5xx Outage**     | Aborts run immediately (no retries)                                                                                                          | Logs provider outage error                           | Quarantines tool response                            |
| **Malformed JSON**      | Aborts run; records schema failure                                                                                                           | Logs schema parsing error                            | Quarantines tool response                            |
| **Missing Usage**       | **Halts candidate loop immediately**; preserves candidate 1; marks cost `null`; stops run with `runStatus: 'stopped_unknown_provider_usage'` | Logs `hasUnknownUsage: true`, cost `null`            | Quarantines response; blocks all subsequent requests |
| **Network Timeout**     | Aborts after 5,000 ms; records timeout                                                                                                       | Logs transport failure                               | Quarantines tool response                            |

### Artifact Failure-Path Matrix (Across 15 Detailed Execution Scenarios)

| Scenario                                                                            |   `attempt.json`   |    `plan.json`     |    `usage.json`    |     `results.json`      |       `REPORT.md`       | Exit Status                                    | Recorded `stopReason`           |
| :---------------------------------------------------------------------------------- | :----------------: | :----------------: | :----------------: | :---------------------: | :---------------------: | :--------------------------------------------- | :------------------------------ |
| **1. Preflight validation fails** (missing `--allow-paid`, bad rate flags)          |    Not written     |    Not written     |    Not written     |       Not written       |       Not written       | Thrown error (exit $\ne 0$)                    | None                            |
| **2. Existing attempt marker** (`attempt.json` exists in destination)               |     Preserved*     |    Not written     |    Not written     |       Not written       |       Not written       | Thrown error (exit $\ne 0$)                    | None                            |
| **3. Dataset validation fails** (dataset file unreadable or invalid JSON)           |    Not written     |    Not written     |    Not written     |       Not written       |       Not written       | Thrown error (exit $\ne 0$)                    | None                            |
| **4. Gateway port binding fails** (`httpServer.listen` fails before loop)           | Definitely written |    Not written     |    Not written     |       Not written       |       Not written       | Thrown error (exit $\ne 0$)                    | None                            |
| **5. MCP client connection fails** (`client.connect()` fails after plan)            | Definitely written | Definitely written |    Not written     |       Not written       |       Not written       | Thrown error (exit $\ne 0$)                    | None                            |
| **6. MCP tool call fails before fetch** (client error vs gateway error)             | Definitely written | Definitely written |    Not written     | Conditionally written** | Conditionally written** | Exit 0 (gateway error) / Thrown (client error) | `null` (exit 0) / None (thrown) |
| **7A. Pre-dispatch token gate blocks** (input bytes $> 3,584$; **reachable**)       | Definitely written | Definitely written |    Not written     |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `failed_classification`         |
| **7B. Pre-dispatch cost gate blocks** (input bytes $> 6,259$; **unreachable***)     | Definitely written | Definitely written |    Not written     |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `failed_classification`         |
| **8. Native fetch times out** (5,000 ms AbortSignal timeout)                        | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `unknown_provider_usage`        |
| **9. Provider returns HTTP error** (401, 429, 500)                                  | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `unknown_provider_usage`        |
| **10. Malformed provider HTTP envelope** (non-JSON body; usage unextractable)       | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `unknown_provider_usage`        |
| **11. Provider 200 with missing usage** (`usage` field omitted or null)             | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `unknown_provider_usage`        |
| **12. Provider 200 with invalid usage** (negative/malformed tokens)                 | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `unknown_provider_usage`        |
| **13. Provider 200 with malformed model JSON** (valid usage, invalid schema)        | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `failed_classification`         |
| **14. Provider 200 with truncated response** (valid usage, `finish_reason: length`) | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `failed_classification`         |
| **15. Full execution succeeds** (HTTP 200, valid HTTP body, JSON & usage)           | Definitely written | Definitely written | Definitely written |   Definitely written    |   Definitely written    | Clean exit (exit $0$)                          | `null` (completed)              |

_\*In Scenario 2: If `attempt.json` already exists, the runner throws before file writing occurs; pre-existing evidence on disk is preserved untouched._<br>
_\*\*In Scenario 6: If the tool call fails at the MCP transport layer, `client.callTool()` throws an unhandled exception, bypassing `results.json` and `REPORT.md`. If the gateway handles an upstream error and returns an error response object, `client.callTool()` returns cleanly, and `results.json` and `REPORT.md` are written._<br>
_\*\*\*In Scenario 7B: Under the proposed command (`--max-total-tokens=4096`), Scenario 7B cannot be independently reached as the first blocking gate because Scenario 7A rejects any input $> 3,584$ bytes first. Scenario 7B would only be reachable if `--max-total-tokens` were configured $> 6,771$._

**Artifact Lifecycle Subtleties:**

- `attempt.json`: Written immediately after dataset validation and provenance computation, but before gateway initialization or candidate dispatch. If dataset validation fails, execution aborts safely before `attempt.json` is created.
- `usage.json`: Written in fetch interceptor `finally` block (`live.ts:313`). If pre-dispatch checks fail before fetch, `usage.json` is not created.
- `results.json` & `REPORT.md`: Written at `live.ts:497-503`. Adapter catches fetch/provider errors and converts them to review fallback, allowing candidate 1 preservation and writing of `results.json` and `REPORT.md`. Bypassed only on unhandled infrastructure/gateway exceptions.

---

## 11. Minimal Local Evidence Record Specification

The output artifacts will be written to `security-lab/compat-results/`:

```json
{
  "testId": "SYNTH-COMPAT-LIVE-01",
  "timestamp": "2026-10-30T12:00:00.000Z",
  "provider": "meta",
  "model": "muse-spark-1.3",
  "approvedEndpoint": "https://api.meta.ai/v1/responses",
  "httpStatus": 200,
  "latencyMs": 842.5,
  "classification": {
    "flagged": false,
    "threatCategory": "none",
    "action": "allow",
    "confidence": 0.99,
    "explanation": "General security summary.",
    "evidence": []
  },
  "tokenUsage": {
    "promptTokens": 312,
    "completionTokens": 44,
    "totalTokens": 356,
    "cachedPromptTokens": 0,
    "reasoningTokens": 0
  },
  "estimatedCostUsd": 0.000577,
  "pricingVerified": true,
  "dollarBudgetEnforced": true,
  "costStatus": "verified_pricing",
  "attemptedRequests": 1,
  "runStatus": "completed",
  "stopReason": null,
  "credentialRedacted": true
}
```

**Information Security Boundary:**

- No API key values, partial keys, or hashes of keys are recorded.
- No `Authorization` headers are logged.
- Only the specific non-confidential synthetic prompt is referenced.

---

## 12. Remaining Risks, Limitations, and Unresolved Prerequisites

1. **Provider Account Balance:** The application cannot query the external Meta developer account to verify available credit or account-level billing caps. The founder must confirm account standing prior to authorizing Phase 4B.
2. **Network Reachability:** The test requires outbound HTTPS connectivity from the local machine to `api.meta.ai:443`. Firewalls or proxies blocking outbound connections will trigger a transport failure.
3. **Scope Limitation:** A successful single-request compatibility test establishes pipeline compatibility only. It does **not** evaluate adversarial detection capability, false positive rates, or production throughput.
4. **Reserved Holdouts Intact:** The 6 reserved evaluation candidates in `security-lab/v1/live-reserve.json` remain locked and must not be executed during Phase 4.
