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
- **Working Tree Status:** Clean, zero uncommitted modifications.
- **Offline Verification Baseline:**
  - Workspace Build: 8 packages built cleanly in 1.4s.
  - Evaluation Typecheck: `scripts/security-lab/tsconfig.json` passed with 0 errors.
  - Remediation Typecheck: `scripts/security-remediation/tsconfig.json` passed with 0 errors.
  - Test Suite: 40 test files, 375 tests passing (100% pass rate).
  - Browser CDP Automation: 12/12 interactive steps passing, 0 CSP violations, 0 console errors.
  - Reserved Candidates: All 6 candidates in `security-lab/v1/live-reserve.json` byte-for-byte identical to baseline (`0650d23` / `98d43d4`).
  - Production Artifacts: Zero `attempt.json`, `attempt-lock`, or `live-results` artifacts exist.

---

## 2. Multi-Provider Compatibility Assessment

Veylith supports three candidate model providers through its unified security adapter layer:

| Requirement / Attribute | Meta Model API (`meta`) | Fireworks AI (`fireworks`) | Baseten (`baseten`) |
| :--- | :--- | :--- | :--- |
| **API Protocol** | Meta Responses API (`meta-responses`) | OpenAI Chat Completions (`openai-chat-completions`) | OpenAI Chat Completions (`openai-chat-completions`) |
| **Approved HTTPS Endpoint** | `https://api.meta.ai/v1/responses` | `https://api.fireworks.ai/inference/v1/chat/completions` | `https://inference.baseten.co/v1/chat/completions` |
| **Allowlisted Model** | `muse-spark-1.3` | `accounts/fireworks/models/muse-spark-open` | `meta-models/muse-spark-open-1026` |
| **Credential Variable** | `META_MODEL_API_KEY` (`META_API_KEY`) | `FIREWORKS_API_KEY` | `BASETEN_API_KEY` |
| **Pricing Verification** | **Verified (`true`)** | **Unverified (`false`)** | **Unverified (`false`)** |
| **Official Published Rates** | Standard Input: \$1.25 / 1M<br>Cached Input: \$0.15 / 1M<br>Output: \$4.25 / 1M | Unverified / Dynamic (varies by deployment tier) | Unverified / Dynamic (varies by dedicated instance) |
| **Dollar Budget Cap Enforcement** | **Enforced by application (`true`)** | **Unbounded by application (`false`)** | **Unbounded by application (`false`)** |
| **Usage Metadata Structure** | `usage.input_tokens`<br>`usage.output_tokens`<br>`usage.input_tokens_details.cached_tokens`<br>`usage.output_tokens_details.reasoning_tokens` | `usage.prompt_tokens`<br>`usage.completion_tokens`<br>`usage.total_tokens`<br>`usage.prompt_tokens_details.cached_tokens`<br>`usage.completion_tokens_details.reasoning_tokens` | `usage.prompt_tokens`<br>`usage.completion_tokens`<br>`usage.total_tokens`<br>`usage.prompt_tokens_details.cached_tokens`<br>`usage.completion_tokens_details.reasoning_tokens` |
| **Max Output Tokens** | Fixed bound: **512 tokens** | Fixed bound: **512 tokens** | Fixed bound: **512 tokens** |
| **Request Timeout** | **5,000 ms** (`AbortSignal.timeout`) | **5,000 ms** (`AbortSignal.timeout`) | **5,000 ms** (`AbortSignal.timeout`) |
| **HTTP Redirects** | `redirect: 'error'` (fails closed) | `redirect: 'error'` (fails closed) | `redirect: 'error'` (fails closed) |
| **Transport Retries** | **0** (Disabled, throws on failure) | **0** (Disabled, throws on failure) | **0** (Disabled, throws on failure) |
| **Provider Fallback** | **Disabled** (Fail closed) | **Disabled** (Fail closed) | **Disabled** (Fail closed) |
| **Credential Redaction** | Strips API keys and Bearer tokens | Strips API keys and Bearer tokens | Strips API keys and Bearer tokens |

---

## 3. Recommended Initial Provider & Rationale

### Recommendation: **Meta Model API (`meta`)**

**Technical Rationale:**
1. **Verified Pricing Safeguard:** Meta is the only provider with verified, immutable rates (\$1.25 input, \$0.15 cached, \$4.25 output per 1M tokens) configured in `APPROVED_PROVIDERS`. The live runner strictly enforces verified rates and guarantees pre-dispatch dollar budget cap enforcement (`dollarBudgetEnforced: true`).
2. **Founder Policy Invariant:** Both Fireworks and Baseten have unverified pricing (`pricingVerified: false`). Proceeding with Fireworks or Baseten requires `--allow-unverified-pricing` and explicitly disclaims application-level dollar budget capping. Per safety rules, unverified pricing must not be used as the default target when a verified provider is available.
3. **Native Architecture Alignment:** Meta Muse (`muse-spark-1.3`) is the primary native security model upon which Veylith's structured classification schema and hybrid boundary engine were architected.
4. **Tested Usage Protocol:** Meta Responses API usage metadata parsing has complete test coverage in `packages/meta-adapter/tests/strict-usage-validation.test.ts` (Scenario 18).

---

## 4. Single Synthetic Test Case Design

To prevent consuming any unseen evaluation cases or historical benchmark data, exactly one synthetic, non-reserved case is defined:

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
1. **Input Size Minimization:** 104 characters (~26 tokens). Minimizes billable input tokens and latency while safely remaining well under the 12,000-character input length limit.
2. **Zero Sensitive Data:** Contains no personal data, credentials, internal architecture details, or proprietary text.
3. **Independence from Reserved Holdouts:** Does not resemble or overlap with the 6 reserved adversarial candidates (which test indirect injection, directive override, synthetic key leak, and tool sink exfiltration).
4. **Structured Output Exercise:** Requests a concise, benign security definition, giving the model clear context to return structured JSON complying with `ModelClassificationSchema`.

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

## 5. Strict Request, Token, and Cost Execution Limits

The live runner (`scripts/security-lab/live.ts`) enforces the following hardware and software bounds:

| Boundary Parameter | Enforced Value | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Max Requests** | **Exactly 1** | CLI flag `--max-requests=1`; runner pre-check throws if `attemptedRequests >= maxRequests` |
| **Max Total Tokens** | **4,096 tokens** | CLI flag `--max-total-tokens=4096`; runner throws if `reservedTokens + estimatedReservationBound > maxTokens` |
| **Max Output Tokens** | **512 tokens** | Runner interceptor enforces `payload.max_output_tokens === 512` |
| **Max Input Length** | **12,000 characters** | Runner interceptor checks `payload.input.length <= 12000` |
| **Request Timeout** | **5,000 ms** | `AbortSignal.timeout(5000)` on native fetch |
| **Transport Retries** | **0** | No retry loop; transport failure throws immediately |
| **Provider Fallback** | **0** | `FAIL_CLOSED: 'true'`; no cross-provider fallback |
| **Max Application Cost** | **\$0.01 USD ceiling** | CLI flag `--max-cost-usd=0.01`; runner pre-check throws if `reservedCost + costBound > maxCost` |
| **Verified Rates** | **Input: \$1.25 / Output: \$4.25 / Cached: \$0.15** | Runner validates `inputRate === 1.25 && outputRate === 4.25 && cachedRate === 0.15` |

### Pre-Dispatch Cost Analysis:
- Conservative input byte bound for `SYNTH-COMPAT-LIVE-01`: ~1,850 bytes (~1,850 token estimate).
- Fixed output token limit: 512 tokens.
- Pre-dispatch cost reservation:
  $$\text{Cost Bound} = \frac{(1850 \times 1.25) + (512 \times 4.25)}{1{,}000{,}000} = \frac{2312.5 + 2176}{1{,}000{,}000} = \$0.0044885 \text{ USD} \approx \$0.0045 \text{ USD}$$
- The pre-dispatch reservation (\$0.0045 USD) is strictly bounded within the proposed \$0.01 USD ceiling.
- Actual post-inference cost (for ~300 actual input tokens and ~40 output tokens) will be approximately:
  $$\text{Actual Cost} \approx \frac{(300 \times 1.25) + (40 \times 4.25)}{1{,}000{,}000} = \frac{375 + 170}{1{,}000{,}000} \approx \$0.000545 \text{ USD} \quad (\approx \text{half a cent of one US cent})$$

*(Note: While application-level budget gating strictly prevents issuing further requests if the estimate exceeds \$0.01, provider-side account billing must be verified independently on the Meta developer dashboard.)*

---

## 6. Exact Future Execution Command

```bash
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
```

> [!CAUTION]
> **DO NOT EXECUTE THIS COMMAND DURING PHASE 4A.**  
> Execution requires explicit founder authorization in Phase 4B.

---

## 7. Credential Setup Instructions (Hidden Terminal Input)

To ensure real API credentials are never recorded in shell history, conversation logs, terminal transcripts, or source control:

1. Open a local, non-recorded shell terminal session.
2. Enter the credential using silent terminal prompt:
   ```bash
   read -s META_MODEL_API_KEY
   export META_MODEL_API_KEY
   ```
3. Verify that the variable is set without printing its value:
   ```bash
   [ -n "$META_MODEL_API_KEY" ] && echo "Key is set (length: ${#META_MODEL_API_KEY})"
   ```
4. **Never** paste API keys into ChatGPT, Antigravity, or any LLM conversation.
5. Immediately after the single live request completes, purge the key from the environment:
   ```bash
   unset META_MODEL_API_KEY
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
- **Estimated Cost:** Numeric float (e.g. `~$0.0005 USD`), strictly `< $0.01 USD`.
- **Latency:** Sub-second to ~3,000 ms.

---

## 10. Expected Failure Handling & Fail-Closed Protocols

| Failure Scenario | Live Runner Action | Audit Log Action | Gateway Behavior |
| :--- | :--- | :--- | :--- |
| **HTTP 401 / 403** | Aborts run; sanitizes key in error string | Logs `decision: 'block'`, `reason: 'meta_api_error'` | Quarantines tool response |
| **HTTP 429 Rate Limit** | Aborts run immediately (no retries) | Logs provider rate limit error | Quarantines tool response |
| **HTTP 5xx Outage** | Aborts run immediately (no retries) | Logs provider outage error | Quarantines tool response |
| **Malformed JSON** | Aborts run; records schema failure | Logs schema parsing error | Quarantines tool response |
| **Missing Usage** | **Halts candidate loop immediately**; preserves candidate 1; marks cost `null`; stops run with `runStatus: 'stopped_unknown_provider_usage'` | Logs `hasUnknownUsage: true`, cost `null` | Quarantines response; blocks all subsequent requests |
| **Network Timeout** | Aborts after 5,000 ms; records timeout | Logs transport failure | Quarantines tool response |

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
