# Veylith — Phase 4B: Founder Readiness & Controlled Live Execution Runbook

> [!WARNING]
> **THIS RUNBOOK IS AN AUDITED OPERATIONAL PREPARATION DOCUMENT ONLY.**<br>
> **NO LIVE INFERENCE REQUEST HAS BEEN AUTHORIZED OR EXECUTED.**<br>
> **NO REAL API KEYS ARE STORED, PRINTED, OR ACCESSED.**<br>
> **ALL SIX RESERVED LIVE EVALUATION CANDIDATES REMAIN LOCKED AND UNTOUCHED.**<br>
> **EXECUTION REQUIRES EXPLICIT FOUNDER AUTHORIZATION.**

---

## 1. Project Status

Veylith has completed its security hardening, offline usage-accounting validation, provider compatibility adapters, and offline synthetic routing verification milestones:

- **Offline Hardening:** Complete fail-closed boundary enforcement, IPv4-mapped IPv6 private IP detection, strict positive token usage validation, and tamper-evident audit logging.
- **Provider Compatibility:** Verified support for Meta Responses API (`meta`), Fireworks AI (`fireworks`), and Baseten (`baseten`).
- **Offline Routing Verification:** Proven via integration test (`tests/integration/phase-4a-offline-routing.test.ts`) that the synthetic canary prompt traverses the MCP Gateway, evaluates through the boundary screener, routes to `needs_semantic_review`, and invokes the adapter semantic inspection path without making external network calls.
- **Test Baseline:** 41 test files, **376 of 376 tests passing** (all offline test suites pass; test count verifies executed test cases and does not imply 100% statement or branch code coverage across the codebase).
- **Reserved Holdouts:** All 6 reserved evaluation candidates (`VEY-2E-LIVE-01` through `VEY-2E-LIVE-06`) remain untouched and locked.

---

## 2. Current Verified Baseline

- **Local Repository:** `/Users/nilambarbehera/Documents/Projects/veylith`
- **GitHub Repository:** `https://github.com/NilambarSonu/Veylith`
- **Active Branch:** `dev/phase-4-live-test-plan`
- **Verified Planning HEAD:** `8ba576d38e211971db15a93691028affff9b00f3` (`8ba576d`)
- **Parent Commit:** `861d5c0ee396e636aa11b105c2db1df54e09fdf5` (`861d5c0`)
- **Hardened Security Baseline:** `028e078` (`dev/phase-3-final-safety-remediation`)
- **Sole Permitted Canary Fixture:** `security-lab/compat-case.json` (ID: `SYNTH-COMPAT-LIVE-01`)
- **Fixture SHA-256:** `943b72268b7ac8d158e14b85347d20f7694a10ccab93f18fd2e8a28b816096dd`
- **Reserved Live Candidates:** `security-lab/v1/live-reserve.json` (0 diff lines against baseline `0650d23`)

---

## 3. What Phase 4B Is

Phase 4B is a proposed **strictly controlled, single-request live compatibility canary** using the Meta Model API.

Its objective is to verify that one benign, non-reserved request can successfully transit the real external Meta Responses API infrastructure and return:

1. An HTTP 200 response with valid JSON matching `ModelClassificationSchema`.
2. Valid provider token usage metadata (`prompt_tokens`, `completion_tokens`).
3. An accurate round-trip latency measurement.
4. Correct pre-dispatch threshold checks and post-response cost tracking.
5. Verifiable local evidence records in `security-lab/compat-results/`.

**One-Request Semantics & Dispatch Mechanics:**
**The configuration limits the run to at most one provider dispatch. It does not guarantee exactly one request will occur.**

- **Counter Increment Timing (`live.ts:279`):** The request counter (`attemptedRequests++`) increments immediately after preflight validation and pre-dispatch cost checks, directly before initiating `nativeFetch` (`live.ts:295`).
- **Proof of Attempt, Not Receipt:** Incrementing `attemptedRequests` proves only that the runner passed preflight checks and initiated `nativeFetch`. It does **not** prove that Meta received, processed, or logged the request.
- **Four Distinct Dispatch Outcomes:**
  1. **Outcome A — Pre-dispatch check fails (0 attempts, counter = 0):** Input length, token budget, endpoint allowlist, or cost threshold fails. Native fetch is never called. Zero network packets transmitted.
  2. **Outcome B — Transport failure or timeout during fetch (1 attempt, provider receipt unconfirmed, no retry, stop):** Network timeout (5,000 ms), DNS failure, or connection drop occurs during fetch. The interceptor flags `networkFailure: true`, writes `usage.json`, throws an unretried error, and halts the candidate loop. **Dispatch status is uncertain.** The founder must inspect the Meta developer dashboard offline before any subsequent action. Never retry automatically.
  3. **Outcome C — Provider returns HTTP error response (1 attempt, error recorded, stop):** Meta returns HTTP 4xx or 5xx. The HTTP status is recorded in `usage.json`, usage is flagged unknown, Candidate 1 observation is preserved, and the runner terminates early without retrying.
  4. **Outcome D — Provider returns valid response (1 attempt, response processed, stop):** Meta returns HTTP 200 with structured JSON and valid usage metadata. Result is validated, evidence is written, and the run completes Candidate 1 and terminates.

**Execution Scope:**

- **At most 1 external HTTP POST request**.
- Zero transport retries (`Transport Retries: 0`).
- Zero cross-provider fallback (`FAIL_CLOSED: 'true'`).
- Zero execution of reserved evaluation candidates.

---

## 4. Why the Test Is Necessary

Before authorizing any multi-request evaluation or benchmark of Veylith against real model endpoints, a single-request live canary is necessary to establish:

1. **Transport Layer Validation:** Confirms that Veylith's Node.js runtime and fetch interceptor can establish an HTTPS/TLS connection to `api.meta.ai:443` without socket hangs or proxy interference.
2. **Authentication Protocol Compatibility:** Verifies that Meta's production API accepts the Bearer token formatting constructed by `MetaMuseSecurityAdapter`.
3. **Structured Output Schema Compliance:** Verifies that Meta's Responses API correctly parses Veylith's `json_schema` request payload and returns structured JSON conforming to `ModelClassificationSchema`.
4. **Production Usage Telemetry:** Confirms that Meta's live production responses deliver the expected `usage` metadata structure required by Veylith's strict usage validator.
5. **Cost Accounting Integrity:** Proves that Veylith's local cost tracker accurately reconciles post-response token usage against published rates without throwing accounting exceptions.

Skipping this canary and proceeding directly to multi-case evaluation would risk burning API budget or corrupting benchmark runs due to unverified protocol assumptions.

---

## 5. Exact Proposed Future Command

```bash
# ==============================================================================
# PROPOSED COMMAND — DO NOT RUN IN PHASE 4B.0
# Execution strictly requires explicit founder authorization in Phase 4B.1.
# ==============================================================================

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

---

## 6. Explanation of Every Command Argument

| Argument / Variable          | Type                 | Value                           | Plain English Explanation                                                                                                                                                                                                                                                                                                                                                                                                                      | Implementation Code Reference               |
| :--------------------------- | :------------------- | :------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------ |
| `SECURITY_LAB_DESTINATION`   | Environment Variable | `security-lab/compat-results`   | Directs all generated evidence files (`attempt.json`, `SYNTH-COMPAT-LIVE-01-plan.json`, `usage.json`, `results.json`, `REPORT.md`) into a dedicated directory separate from production benchmark evidence.                                                                                                                                                                                                                                     | `scripts/security-lab/live.ts:100`          |
| `SECURITY_LAB_DATASET`       | Environment Variable | `security-lab/compat-case.json` | Explicitly targets the single synthetic canary case. Skips the manifest check on `live-reserve.json` and ensures the 6 reserved candidates are never read.                                                                                                                                                                                                                                                                                     | `scripts/security-lab/live.ts:101-104`      |
| `pnpm security:eval:live --` | CLI Command          | Script entry point              | Invokes `tsx scripts/security-lab/live.ts`. The `--` separator ensures subsequent flags are passed directly to the script rather than consumed by `pnpm`.                                                                                                                                                                                                                                                                                      | `package.json:39`                           |
| `--allow-paid`               | CLI Flag             | Present                         | Mandatory founder authorization flag. If omitted, the runner throws an error immediately before configuring endpoints or resolving keys.                                                                                                                                                                                                                                                                                                       | `scripts/security-lab/live.ts:22-23`        |
| `--provider=meta`            | CLI Option           | `meta`                          | Selects Meta Model API (`muse-spark-1.3`) at approved endpoint `https://api.meta.ai/v1/responses`.                                                                                                                                                                                                                                                                                                                                             | `scripts/security-lab/live.ts:25-32`        |
| `--max-requests=1`           | CLI Option           | `1`                             | Limits candidate run loop to **at most one** provider dispatch. Slices dataset to 1 case and throws if `attemptedRequests >= 1`.                                                                                                                                                                                                                                                                                                               | `scripts/security-lab/live.ts:42, 134, 268` |
| `--max-total-tokens=4096`    | CLI Option           | `4096`                          | Binds cumulative token reservation across the run (`conservativeInputBytes + 512 <= 4096`). Under this single-request command, caps serialized input to at most 3,584 bytes ($4096 - 512 = 3584$).                                                                                                                                                                                                                                             | `scripts/security-lab/live.ts:45, 269`      |
| `--max-cost-usd=0.01`        | CLI Option           | `0.01`                          | **Byte-derived application-level cost proxy and pre-dispatch threshold** (\$0.01 USD). The pre-dispatch interceptor throws if the local byte-derived cost estimate exceeds \$0.01. Note: Evaluated after the token gate; because the token gate limits input to 3,584 bytes (cost proxy \$0.006656), the \$0.01 threshold acts as a secondary ceiling and cannot be independently reached as the first blocking gate under this configuration. | `scripts/security-lab/live.ts:48, 275`      |
| `--input-rate=1.25`          | CLI Option           | `1.25`                          | Verified rate: \$1.25 USD per 1,000,000 standard input tokens. Validated to match official Meta published rates. Used directly for all input bytes in the pre-dispatch cost proxy.                                                                                                                                                                                                                                                             | `scripts/security-lab/live.ts:51, 70`       |
| `--output-rate=4.25`         | CLI Option           | `4.25`                          | Verified rate: \$4.25 USD per 1,000,000 output tokens. Validated to match official Meta published rates. Used for the fixed 512-token output limit in the pre-dispatch cost proxy.                                                                                                                                                                                                                                                             | `scripts/security-lab/live.ts:51, 70`       |
| `--cached-rate=0.15`         | CLI Option           | `0.15`                          | Verified rate: \$0.15 USD per 1,000,000 cached input tokens. Validated to match official Meta published rates at startup (`live.ts:70`). Note: Cached rate does **not** participate in the pre-dispatch `costBound` formula (all input bytes are priced at the standard \$1.25 rate).                                                                                                                                                          | `scripts/security-lab/live.ts:51, 70`       |

---

## 7. Cost Explanation & Financial Caveats

### Meta Standard API Official Pricing (Checked October 30, 2026)

- **Standard Input Tokens:** \$1.25 USD per 1,000,000 tokens (\$0.00000125 / token).
- **Cached Input Tokens:** \$0.15 USD per 1,000,000 tokens (\$0.00000015 / token).
- **Output Tokens:** \$4.25 USD per 1,000,000 tokens (\$0.00000425 / token).
- **Source:** [https://dev.meta.ai/docs/pricing-rate-limits](https://dev.meta.ai/docs/pricing-rate-limits) (published rates subject to provider schedule revisions).

### Cost Calculation Semantics & Implementation Analysis (`live.ts:244-277`)

1. **UTF-8 Bytes Treated as Input Tokens:**
   The pre-dispatch formula treats serialized prompt UTF-8 bytes as if they were input tokens:
   $$\text{costBound} = \frac{(\text{conservativeInputBytesBound} \times \text{inputRate}) + (512 \times \text{outputRate})}{1{,}000{,}000}$$
   Here, $\text{conservativeInputBytesBound} = \text{Buffer.byteLength(payload.input)} = 1{,}855 \text{ bytes}$.
2. **No Model Tokenizer Invoked:**
   The runner evaluates `Buffer.byteLength()`, not an actual model tokenizer. No tokenizer binary or dictionary is bundled with or called by the live runner.
3. **Local Conservative Proxy, Not Proven Upper Bound:**
   While standard English text typically yields $\approx 3.5\text{--}4$ characters per token under BPE tokenizers, equating 1 byte to 1 token is an empirical engineering proxy, **not** a mathematically proven or provider-guaranteed upper bound.
4. **Pre-Dispatch Comparison Uses Local Proxy & Is Conditional on `pricingVerified` (`live.ts:275`):**
   The spending gate (`if (def.pricingVerified && reservedCost + costBound > maxCost) throw new Error(...)`) evaluates whether the byte-derived cost proxy exceeds the configured `--max-cost-usd=0.01` threshold. This check is **conditional**:
   - For Meta, `def.pricingVerified` is `true` (`packages/meta-adapter/src/providers.ts:44`), meaning this cost gate **is active** and will evaluate if the preceding token gate passes.
   - For unverified providers (Fireworks and Baseten), `def.pricingVerified` is `false` (`providers.ts:61, 73`), meaning the dollar cost gate is bypassed (only token-reservation and request limits are evaluated, and `--allow-unverified-pricing` is required at startup).
   - The comparison does not evaluate actual token counts or guarantee external provider billing limits.
5. **Cached Rate Does Not Participate in Pre-Dispatch Calculation:**
   Although the cached rate (\$0.15 / 1M) is asserted at startup (`live.ts:70`), it does **not** participate in the pre-dispatch `costBound` calculation. The formula prices 100% of the 1,855 input bytes at the full standard rate (\$1.25 / 1M).
6. **Provider-Side Billing Divergence:**
   Provider-side billing is determined entirely by Meta's server-side metering infrastructure and account billing ledger. It can diverge from or exceed the application's calculation if provider tokenization meters differently or if account-level billing rules diverge.
7. **Input Scope & Unmeasured Request Fields:**
   The pre-dispatch calculation evaluates only `Buffer.byteLength(payload.input)` (1,855 UTF-8 bytes). It does **not** evaluate additional request fields such as `payload.model`, `payload.reasoning`, the structured output JSON schema in `payload.text.format.schema`, or server-side protocol framing and grammar-conditioning tokens. Whether Meta's server-side metering includes these additional fields or overhead as billable input tokens is **unknown** prior to live telemetry. The application cannot guarantee that provider-metered prompt tokens will not exceed the input character or byte count.
8. **Check Ordering & Primary Blocking Gate Analysis for Meta (`live.ts:267-277`):**
   In `live.ts`, the token-reservation check (`reservedTokens + estimatedReservationBound > maxTokens`, line 269) is evaluated **before** the cost spending gate (`def.pricingVerified && reservedCost + costBound > maxCost`, line 275). For the Meta provider configuration (`def.pricingVerified === true`), both checks are active and use the identical `conservativeInputBytesBound` and fixed 512-token output reservation. Under the proposed command (`--provider=meta`, `--max-total-tokens=4096`, `--max-requests=1`, `--max-cost-usd=0.01`), the token reservation gate enforces `inputBytes + 512 <= 4096`, which caps input to at most 3,584 bytes. At the maximum permitted 3,584 bytes, the pre-dispatch cost proxy is:
   $$\text{Cost Bound} = \frac{(3584 \times 1.25) + (512 \times 4.25)}{1{,}000{,}000} = \frac{4480 + 2176}{1{,}000{,}000} = \$0.006656 \text{ USD}$$
   Because $\$0.006656 < \$0.010000$, any input exceeding 3,584 bytes is rejected by the **token-reservation gate first** (`live.ts:269`). Therefore, although active for Meta, the **\$0.01 cost gate cannot independently become the first blocking gate** under the proposed Meta command configuration. The theoretical 6,259.2 byte threshold represents the cost gate in isolation and would only become active if `--max-total-tokens` were configured above $6{,}259 + 512 = 6{,}771$ tokens (e.g. `--max-total-tokens=8192`). Note that `$0.006656` is strictly the local cost proxy at maximum reservation, **not** a provider billing maximum; unmeasured fields and server-side framing remain outside this local formula.

### Mathematical Cost Projections

1. **Application Pre-Dispatch Bound Calculation:**
   - Prompt input byte length for `SYNTH-COMPAT-LIVE-01`: 1,855 bytes.
   - Fixed output token reservation: 512 tokens.
   - Pre-dispatch cost reservation:
     $$\text{Cost Bound} = \frac{(1855 \times 1.25) + (512 \times 4.25)}{1{,}000{,}000} = \frac{2318.75 + 2176}{1{,}000{,}000} = \$0.00449475 \approx \$0.0045 \text{ USD}$$
   - The pre-dispatch reservation (\$0.0045 USD) is strictly within the \$0.01 USD **byte-derived application-level cost proxy and pre-dispatch threshold**.
2. **Illustrative Post-Response Cost (Hypothetical):**
   - Assuming Meta's tokenizer meters ~300 prompt tokens and ~40 completion tokens:
     $$\text{Illustrative Cost} = \frac{(300 \times 1.25) + (40 \times 4.25)}{1{,}000{,}000} = \frac{375 + 170}{1{,}000{,}000} = \$0.000545 \text{ USD} = 0.0545 \text{ cents}$$
   - _(Note: Prior to live execution, no actual usage measurement exists. $\$0.000545 \text{ USD}$ is approximately $5$ hundredths of one cent; half of one cent is $\$0.005 \text{ USD}$)_.

### Four Distinct Financial Dimensions

| Item                                   | What It Means                                                                                                                                                                                | What It Does NOT Guarantee                                                                                                                                                     |
| :------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Estimated Cost Proxy**               | Client-side mathematical proxy using serialized prompt UTF-8 byte length and fixed 512-token output limit (\$0.00449475 USD).                                                                | Does not guarantee that Meta's server-side BPE tokenizer will count tokens identically; not a mathematical upper bound on provider metering.                                   |
| **Application Pre-Dispatch Threshold** | Byte-derived application-level cost proxy and pre-dispatch threshold (`--max-cost-usd=0.01`). If local pre-dispatch estimate exceeds \$0.01, Veylith aborts without sending an HTTP request. | Does not guarantee external provider-side billing caps if external provider metering diverges from local heuristics.                                                           |
| **Actual Meta Charge**                 | Real monetary charge billed to the founder's Meta developer account based on Meta's internal server-side metering and account rate card.                                                     | Does not guarantee that charges will match local client estimates. Any assumptions regarding minimum billing increments or rounding remain unverified account-level mechanics. |
| **Provider Spending Controls**         | Provider-side spending controls have not been independently verified for this account. Do not assume a configurable hard spending cap is available.                                          | Does not exist automatically within Veylith. Must be verified directly by the founder on `https://dev.meta.ai/`.                                                               |

---

## 8. Secure Credential Procedure (macOS Zsh & Bash Compatible)

### Environment Variable Resolution Hierarchy

In `packages/meta-adapter/src/providers.ts:280-293`, credentials for `meta` resolve with strict precedence:

1. `overrideKey` argument (not passed by live runner).
2. Primary variable: `process.env['META_MODEL_API_KEY']`
3. Alternate variable: `process.env['META_API_KEY']`

### Safe Entry Protocol (Temporary Subshell)

To ensure compatibility across macOS default Zsh (`/bin/zsh`) and Bash (`/bin/bash`), use an isolated temporary subshell. This ensures that credential variables exist only for the duration of the subshell and are automatically discarded upon exit. The entire future command runs inside this subshell:

```bash
(
  set +x

  trap 'unset META_MODEL_API_KEY META_API_KEY' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  printf 'Enter Meta API key (input hidden): '
  IFS= read -r -s META_MODEL_API_KEY
  printf '\n'

  if [ -z "$META_MODEL_API_KEY" ]; then
    echo "Missing credential. Stop."
    exit 1
  fi

  export META_MODEL_API_KEY

  # PROPOSED LIVE COMMAND (REQUIRES EXPLICIT FOUNDER AUTHORIZATION IN PHASE 4B.1):
  # SECURITY_LAB_DESTINATION=security-lab/compat-results \
  # SECURITY_LAB_DATASET=security-lab/compat-case.json \
  # pnpm security:eval:live -- \
  #   --allow-paid \
  #   --provider=meta \
  #   --max-requests=1 \
  #   --max-total-tokens=4096 \
  #   --max-cost-usd=0.01 \
  #   --input-rate=1.25 \
  #   --output-rate=4.25 \
  #   --cached-rate=0.15
)
```

### Why This Procedure Is Safer:

- **Subshell Isolation:** Enclosing the procedure in `( ... )` creates a subshell. When the subshell exits, the credential variable is discarded from the shell environment automatically, preventing leakage into subsequent commands in the parent terminal.
- **Entire Command Encapsulated:** The proposed live evaluation runner executes within the subshell itself. Credential variables are never exposed to the interactive parent terminal.
- **Cross-Shell Portability & Compatibility:** `printf` combined with `IFS= read -r -s` is verified to operate reliably in both macOS default Zsh (`/bin/zsh`) and Bash (`/bin/bash`), avoiding Zsh's coprocess `read -p` syntax failure.
- **Shell Limitation Warning:** Do **not** execute under plain POSIX `sh` (or lightweight shells like `dash`), where `read -s` is not defined in IEEE Std 1003.1 and will either fail with a syntax error or echo sensitive keystrokes.
- **Signal Traps:** Dedicated signal handlers for `EXIT`, `INT` (SIGINT / exit 130), `TERM` (SIGTERM / exit 143), and `HUP` (SIGHUP / exit 129) ensure that `unset` executes even if the operator presses `Ctrl+C`.
- **Syntax Verification Scope:** Syntax checks using `zsh -n` and `bash -n` verify shell grammar and command syntax parsing only; they do not prove runtime credential safety or OS memory isolation.
- **Security Boundary Clarification:** Unsetting environment variables prevents ambient shell process leakage, but does **not** guarantee cryptographic wiping of process memory buffers from OS memory pages.
- **Prohibitions:** Never print the key, never print its character length, never pass keys in CLI flags, never write to `.env` files, and never paste keys into AI chat interfaces.

---

## 9. Manual Provider-Account Checklist

Before authorizing execution in Phase 4B.1, the founder must manually log in to [https://dev.meta.ai/](https://dev.meta.ai/) and verify:

- [ ] **Account Standing:** Developer account is active and in good standing.
- [ ] **Billing Method:** Valid payment method is active and recognized by Meta.
- [ ] **Provider-Side Spending Controls:** Review account billing settings on [https://dev.meta.ai/](https://dev.meta.ai/). Provider-side spending controls have not been independently verified for this account. Do not assume a configurable hard spending cap is available.
- [ ] **Model Access:** Account has access to the `muse-spark-1.3` model.
- [ ] **Endpoint Availability:** Developer dashboard displays normal API operational status for `https://api.meta.ai/v1/responses`.
- [ ] **No Conflicting Keys:** Key used belongs to the intended project and workspace.

---

## 10. Step-by-Step Future Execution Instructions

When the founder decides to authorize execution, follow these 12 numbered steps:

1. **Verify Repository Location:**
   Ensure current directory is `/Users/nilambarbehera/Documents/Projects/veylith`.
2. **Verify Branch:**
   Run `git branch --show-current`. Must output `dev/phase-4-live-test-plan`.
3. **Verify Commit & Clean Tree:**
   Run `git status`. Must confirm `working tree clean` and commit `8ba576d38e211971db15a93691028affff9b00f3`.
4. **Check Reserved Holdouts:**
   Run `git diff 0650d23..HEAD -- security-lab/v1/live-reserve.json`. Must return zero output.
5. **Verify Synthetic Fixture:**
   Run `shasum -a 256 security-lab/compat-case.json`. Must match `943b72268b7ac8d158e14b85347d20f7694a10ccab93f18fd2e8a28b816096dd`.
6. **Complete Manual Account Checklist:**
   Review Section 9 checklist items on `https://dev.meta.ai/`.
7. **Initiate Temporary Subshell:**
   Begin the subshell wrapper with signal traps as documented in Section 8.
8. **Set Credential Silently:**
   Enter key via `IFS= read -r -s META_MODEL_API_KEY && export META_MODEL_API_KEY`.
9. **Manual Confirmation Gate:**
   Review command parameters. Note: Typing `CONFIRM LIVE META CALL` is a **manual founder confirmation step** in the execution runbook, not an automated CLI prompt in the runner.
10. **Execute Proposed Command:**
    Execute the command from Section 5 inside the subshell (limits run to at most one provider dispatch).
11. **Verify Evidence Artifacts:**
    Inspect `security-lab/compat-results/`:
    - `attempt.json`: Confirms commit, model, and pre-dispatch parameters.
    - `SYNTH-COMPAT-LIVE-01-plan.json`: Records planned scenario metadata.
    - `usage.json`: Confirms attempted requests ($\le 1$), valid token usage, and cost.
    - `results.json`: Confirms `runStatus: 'completed'`, `stopReason: null`.
    - `REPORT.md`: Formatted execution report.
12. **Reconcile Provider Billing & Close Subshell:**
    Check Meta dashboard to confirm actual charge matches expectation. Exiting the subshell purges `META_MODEL_API_KEY`.

---

## 11. Strict Stop Conditions

If any of the following occur, execution must immediately abort:

| Condition                         | Description                                                                                                 | Required Action              |
| :-------------------------------- | :---------------------------------------------------------------------------------------------------------- | :--------------------------- |
| **Branch / Commit Mismatch**      | Repository is not on `dev/phase-4-live-test-plan` or HEAD $\ne$ `8ba576d38e211971db15a93691028affff9b00f3`. | `STOP — INVESTIGATE OFFLINE` |
| **Fixture Mismatch**              | `security-lab/compat-case.json` SHA-256 differs from `943b722...` or case count $\ne 1$.                    | `STOP — INVESTIGATE OFFLINE` |
| **Missing Credential**            | `META_MODEL_API_KEY` is empty, unset, or whitespace.                                                        | `STOP — INVESTIGATE OFFLINE` |
| **Request Limit Breach**          | Runner detects `attemptedRequests >= 1` or CLI flag is not `--max-requests=1`.                              | `STOP — NO RETRY`            |
| **Budget Gate Exceeded**          | Pre-dispatch cost estimate exceeds \$0.01 USD.                                                              | `STOP — NO RETRY`            |
| **Rate Configuration Mismatch**   | Supplied pricing rates do not equal official rates (`1.25`, `4.25`, `0.15`).                                | `STOP — NO RETRY`            |
| **Unexpected Endpoint**           | Target URL is not `https://api.meta.ai/v1/responses` or protocol is not HTTPS.                              | `STOP — NO RETRY`            |
| **Missing / Invalid Usage**       | Provider response omits `usage` or tokens are negative, fractional, or non-integer.                         | `STOP — NO RETRY`            |
| **Classification Schema Error**   | Provider response fails `ModelClassificationSchema` validation or body is truncated.                        | `STOP — NO RETRY`            |
| **HTTP Error (4xx / 5xx)**        | Provider returns 401 Unauthorized, 429 Rate Limit, or 500 Outage.                                           | `STOP — NO RETRY`            |
| **Timeout Exceeded**              | Request exceeds 5,000 ms timeout.                                                                           | `STOP — NO RETRY`            |
| **Uncertain Dispatch Status**     | Transport failure or timeout during native fetch.                                                           | `STOP — NO RETRY`            |
| **Reserved Candidate Referenced** | Any case from `live-reserve.json` is loaded or referenced.                                                  | `STOP — NO RETRY`            |
| **Unexpected External Network**   | Any request to an unapproved host or non-443 port is attempted.                                             | `STOP — NO RETRY`            |

**Rule:** Under NO circumstances should an automatic retry, cross-provider fallback, or diagnostic second request be executed.

---

## 12. Expected Output & Artifact Locations

A successful compatibility run generates exactly 5 artifacts in `security-lab/compat-results/`:

- **Destination Directory:** `security-lab/compat-results/` (configured via `SECURITY_LAB_DESTINATION`)
- **Generated Artifacts on Success:**
  1. `attempt.json`: Written before dispatch (`live.ts:113`). Documents commit hash, provider (`meta`), model (`muse-spark-1.3`), verified pricing (`true`), max requests (`1`), and application threshold (`$0.01`).
     - Provenance fields (Phase 4B.3): `datasetPath` (safe repository-relative path), `datasetSha256` (exact raw-byte digest), `manifestVerified` (`false` for custom datasets; `true` for frozen benchmark), `manifestVerification` (`'not_applicable'` for custom; `'verified'` for frozen benchmark), and `manifestSha256` (`'not_applicable'` for custom; frozen manifest hash for benchmark).
     - _Historical Canary Note:_ The Phase 4B.1 canary `attempt.json` contains `"manifestSha256": "mock-test-manifest"`, which was an intentional test sentinel in prior runner code. It remains preserved as originally recorded to maintain historical evidence integrity without retroactive tampering.
  2. `SYNTH-COMPAT-LIVE-01-plan.json`: Written before case execution (`live.ts:399`). Records planned scenario metadata and ground truth.
  3. `usage.json`: Written in fetch interceptor finally block (`live.ts:313`). Documents attempted requests ($\le 1$), reserved tokens, verified cost, and raw provider usage metadata.
  4. `results.json`: Complete execution record written after case execution (`live.ts:502`). Contains `runStatus: 'completed'`, `stopReason: null`, classification payload, latency measurement, and cost status.
  5. `REPORT.md`: Formatted Markdown summary written after case execution (`live.ts:497`). Contains pipeline metrics table, latency, token usage, and cost calculation.
- **Console Log:**
  `Manual live run finished: 1 attempted provider calls. Inspect security-lab/compat-results; provider billing is separate.`

### Artifact Lifecycle & Persistence Subtleties

- **`attempt.json` Exposure Marker:** Written immediately after dataset validation and provenance computation, but before gateway initialization or candidate dispatch. If dataset validation fails (unreadable file or malformed JSON), execution aborts safely before `attempt.json` is created, preventing corrupt or spurious attempt locks.
- **`<id>-plan.json` Candidate Context:** Written at `live.ts:399` at the start of Candidate 1 loop, prior to client connection or tool dispatch.
- **`usage.json` Interceptor Scope:** Written exclusively in the `finally` block of the fetch interceptor (`live.ts:313`). If execution aborts prior to entering the fetch interceptor (e.g. parameter check fails, loopback server bind error, or pre-dispatch token/cost gate throws before native fetch), `usage.json` is **not created**. If native fetch is initiated, `usage.json` is written unconditionally upon completion or error (recording `networkFailure: true` on transport fault).
- **`results.json` & `REPORT.md` Fault Preservation:** Written at `live.ts:497-503`. Because the security adapter (`packages/meta-adapter/src/adapter.ts:672`) catches all downstream network transport errors, timeouts, HTTP non-200 responses, and schema parse errors and maps them to a fail-closed inspection fallback (`{ flagged: true, action: 'review' }`), `client.callTool()` returns without throwing an unhandled exception. This ensures Candidate 1 observation is preserved, and `results.json` and `REPORT.md` are written with the appropriate early termination `stopReason`. However, if an unhandled infrastructure error occurs before candidate execution or during MCP client connection setup (`client.connect()`), execution jumps directly to the outer server teardown `finally` block (`live.ts:534`), and `results.json` and `REPORT.md` are bypassed.

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

---

## 13. Post-Execution Verification Procedure

Immediately following execution:

1. **Verify Request Count:** Confirm `attemptedRequests === 1` in `usage.json` and console output.
2. **Verify Run Status:** Confirm `runStatus === 'completed'` and `stopReason === null` in `results.json`.
3. **Verify Usage Extraction:** Confirm `usageKnown === true` and token counts are non-negative integers.
4. **Verify Cost Bounds:** Confirm `estimatedCostUsd < 0.01`.
5. **Verify Tamper-Evident Audit Chain:** Inspect gateway logs to confirm the event was logged with `stage: 'call_response'`, `mcpMethod: 'tools/call'`, `decision: 'allow'`.
6. **Reconcile Meta Billing:** Log in to [https://dev.meta.ai/](https://dev.meta.ai/) and check the billing log to verify the recorded request and charged amount.
7. **Confirm Reserved Holdouts Intact:** Run `git diff 0650d23..HEAD -- security-lab/v1/live-reserve.json`.

---

## 14. Failure-Handling Procedure

If the live canary fails:

1. **HTTP 401 / 403 (Authentication Error):**
   - Do NOT retry.
   - Run `unset META_MODEL_API_KEY`.
   - Verify key permissions and model access on the Meta developer portal offline.
2. **HTTP 429 (Rate Limit):**
   - Do NOT retry.
   - Check account rate limit tier on Meta portal.
3. **Missing Usage Metadata:**
   - The live runner automatically preserves Candidate 1, writes `runStatus: 'stopped_unknown_provider_usage'`, sets cost to `null`, and aborts.
   - Inspect `usage.json` to review raw response payload offline.
4. **Malformed Classification JSON:**
   - The live runner quarantines the response and records schema error.
   - Inspect `results.json` offline.
5. **Network Timeout / Connection Refused:**
   - Check local internet connectivity, DNS resolution of `api.meta.ai`, and corporate firewalls offline.

---

## 15. What the Test Proves and Does Not Prove

### What A Successful Canary PROVES:

- Outbound network reachability to `https://api.meta.ai/v1/responses` via HTTPS.
- Active validity of the provided Meta API key.
- End-to-end MCP Gateway protocol forwarding and response interception.
- Compatibility of Meta Muse (`muse-spark-1.3`) with Veylith's `json_schema` response format.
- Functionality of Veylith's strict provider usage parser and post-response cost tracker.
- Tamper-evident audit logging of live model inspection events.
- Enforcement of pre-dispatch budget gating and token bounds.

### What A Successful Canary DOES NOT PROVE:

- **Adversarial Detection Capability:** The canary is a single benign definition; it does not evaluate detection of indirect injection or directive overrides.
- **Statistical False-Positive Rate:** One benign case cannot establish false-positive rates across diverse agent workflows.
- **Jailbreak Robustness:** Does not evaluate model robustness against adversarial attacks.
- **Production Concurrency / Load:** Does not test performance under multi-session concurrent traffic.
- **Independent Evaluation Validity:** Benchmark evaluation on unseen holdouts remains separate.
- **Security Certification:** Does not constitute formal security verification.

---

## 16. Final Founder Authorization Gate

```
+-----------------------------------------------------------------------------------+
|                        FOUNDER AUTHORIZATION DECISION GATE                        |
|                                                                                   |
|  [ ] 1. I have read and understood this runbook.                                  |
|  [ ] 2. I have manually verified my Meta account standing and billing settings.   |
|  [ ] 3. I understand that the $0.01 setting is an application-level               |
|         estimated-cost pre-dispatch threshold, not a guaranteed provider billing  |
|         cap, and that provider-side spending controls are unverified.             |
|  [ ] 4. I authorize AT MOST ONE live compatibility request to Meta.               |
|  [ ] 5. I confirm that the 6 reserved holdout candidates must remain untouched.   |
|                                                                                   |
|  Type 'AUTHORIZE PHASE 4B LIVE CANARY' to provide explicit founder authorization. |
+-----------------------------------------------------------------------------------+
```
