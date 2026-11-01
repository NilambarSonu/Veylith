# Veylith — 3-Minute Technical Judge Walkthrough Script

**Project:** Veylith — AI Agent Security Boundary for Model Context Protocol (MCP)  
**Track:** Meta Global AI Developer Hackathon 2026 (Startup Track)  
**Presenter:** Nilambar Behera (Solo Founder)  
**Target Duration:** ~3 minutes (180 seconds)  
**Local Dashboard URL:** `http://127.0.0.1:8789`  
**Interactive Terminal Demo:** `pnpm demo -- --all`

---

## Presentation Overview & Time Allocation

| Timestamp       | View / Screen                                | Primary Objective                                                                                             | Key Disclosures                                                                              |
| :-------------- | :------------------------------------------- | :------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------- |
| **0:00 – 0:30** | **Overview** (`#overview`)                   | Explain MCP security problem, gateway architecture, 3 inspection boundaries, and 3 decision outcomes.         | Non-production research prototype; local loopback binding.                                   |
| **0:30 – 1:15** | **Terminal Demo** (`pnpm demo`)              | Execute 4 live scenarios: safe echo, discovery poisoning, indirect prompt injection, and dangerous arguments. | 100% offline execution; zero paid external API spend.                                        |
| **1:15 – 2:00** | **Evaluation Lab** (`#evaluation-lab`)       | Walk through Phase 2A (68 samples), Phase 2E (56 cases), and Phase 2F (72 cases) with exact denominators.     | Phase 2A is in-repo validation fixture, not blind holdout; operational exclusions explained. |
| **2:00 – 2:35** | **Audit Explorer** (`#audit-explorer`)       | Demonstrate SHA-256 canonical JSON hash chain, secret masking, and detail drawer.                             | Local chain validates in-situ integrity; not an external Rekor notary ledger.                |
| **2:35 – 3:00** | **Security Findings** (`#security-findings`) | Review 8 open findings, 6 locked live candidates, and single compatibility canary.                            | Canary tested transport/cost only; 6 live candidates remain untouched.                       |

---

## Detailed Minute-by-Minute Script

### Step 1 (0:00 – 0:30): Architecture & Problem Framing (Overview Screen)

- **Navigation:** Open browser to `http://127.0.0.1:8789/#overview` (or press keyboard shortcut `1`).
- **Visual Focus:** Hero card, Architecture Diagram, 3 Inspection Boundaries, and Latency Table.
- **Presenter Action:** Point mouse to the visual architecture flow and inspection boundary cards.

#### Spoken Presentation:

> _"Autonomous AI agents interacting with tools via Model Context Protocol inherit ambient system authority without transport-layer security. If an MCP server returns indirect prompt injection or an agent is coerced into running destructive commands, the system executes it directly._
>
> *Veylith solves this by sitting directly between the agent and external tools as an inline security boundary. It enforces three distinct inspection boundaries:
>
> 1. **Discovery Inspection** (`tools/list`): Drops poisoned tool descriptions before the agent builds its context.
> 2. **Invocation Inspection** (`tools/call`): Blocks destructive shell (`rm -rf /`), destructive SQL, and SSRF in under 0.05 milliseconds in-memory.
> 3. **Response Inspection** (`tools/call` returns): Quarantines untrusted tool output containing prompt injections before it hijacks the agent reasoning loop.*
>
> _Decisions resolve to ALLOW, BLOCK, or SANITIZE."_

#### Mandatory Disclosures to Highlight:

- Veylith is a local research prototype for the hackathon, not a certified production appliance.
- In-memory Tier 1 microbenchmarks (<0.05 ms) are distinct from HTTP proxy overhead (~5.9 ms warm p50).

---

### Step 2 (0:30 – 1:15): Live Terminal Demonstration (`pnpm demo`)

- **Terminal Command:** In a clean terminal window, execute:
  ```bash
  pnpm demo -- --all
  ```
- **Visual Focus:** The four terminal scenario boxes and final summary table.
- **Presenter Action:** Let the batch run complete (~2 seconds) and highlight each scenario output.

#### Spoken Presentation:

> _"Here is Veylith running live over local loopback using real MCP client SDKs, our security gateway, and an upstream test server:_
>
> _- **Scenario A [ALLOW]**: Normal echo request matches zero threat invariants and passes transparently to upstream in 24 ms._  
> _- **Scenario B [BLOCK]**: An upstream server advertises a poisoned tool with embedded system override instructions. Veylith's discovery filter intercepts it and drops the tool so downstream agents never see it._  
> _- **Scenario C [SANITIZE]**: An untrusted external document returns an embedded prompt injection. Veylith intercepts the tool response, quarantines the directive, and returns a structured security notice with `isError: true`._  
> _- **Scenario D [BLOCK]**: The client attempts to execute `rm -rf /`. Tier 1 hard invariants intercept the call locally before upstream dispatch._
>
> _All 4 scenarios pass with zero external network requests and zero paid inference."_

#### Mandatory Disclosures to Highlight:

- All processes communicate strictly over `127.0.0.1` loopback.
- Both `META_MODEL_API_KEY` and `META_API_KEY` are scrubbed in demonstration environments.

---

### Step 3 (1:15 – 2:00): Evaluation Lab & Transparent Denominators (`#evaluation-lab`)

- **Navigation:** Return to browser and press `2` (or click `Evaluation Lab` in sidebar).
- **Visual Focus:** The three dataset tabs: Phase 2F, Phase 2E, and Phase 2A.
- **Presenter Action:**
  1. Click `Phase 2A Internal Validation Fixture (68 Samples)` (`#tab-p2a`).
  2. Click `Phase 2E Frozen Holdout Benchmark (56 Cases)` (`#tab-p2e`).
  3. Click `Phase 2F Development Comparison (72 Samples)` (`#tab-p2f`).

#### Spoken Presentation:

> _"Rather than claiming 100% prompt injection detection, we disclose transparent empirical benchmarks across three datasets:_
>
> _First, in **Phase 2A** across 68 curated validation samples (`tests/fixtures/holdout-corpus.json`): Attack Precision is **93.8%**, but Attack Recall is **46.9%** with 17 false negatives. Complex multilingual and encoded attacks bypassed static rules. Overall accuracy is 73.5%. This is an internal validation fixture, not an external blind holdout._
>
> _Second, in **Phase 2E**, we evaluated 56 holdout cases. We explicitly disclose that 6 operational stress cases (testing network timeouts and payload truncation) are excluded from binary classification scoring because their predicted status is null. Across the 50 scored classification samples, recall was 62.1% with zero false positives._
>
> _Third, in **Phase 2F**, we evaluate 72 development samples (68 scored). Notice the trade-off: in deterministic-only mode, fail-closed policy achieved 100% recall, but blocked all 20 benign cases (100% false-positive rate). Security guardrails always present availability trade-offs."_

#### Mandatory Disclosures to Highlight:

- Phase 2A is in-repo fixture data, not an independently blinded external benchmark.
- Mock-semantic evaluations test deterministic orchestration and policy routing, not real Meta Muse LLM weights.

---

### Step 4 (2:00 – 2:35): Cryptographic Audit Chain (`#audit-explorer`)

- **Navigation:** Press `3` (or click `Audit Explorer` in sidebar).
- **Visual Focus:** `Chain Integrity Validated` badge, Genesis hash bar, and Audit Event Table.
- **Presenter Action:** Click the top row in the table to slide open the Detail Drawer.

#### Spoken Presentation:

> _"Every single discovery, argument, and response event is cryptographically linked in a sequential SHA-256 canonical JSON hash chain originating from a 64-zero genesis hash._
>
> *In the detail drawer, you can verify:
>
> - Sequence continuity ($0, 1, 2, \dots$).
> - Current event hash mathematically incorporating the previous event hash.
> - Authorization context, stage, and decision reasoning.
> - Automated secret masking: API keys and sensitive tokens are redacted before storage.*
>
> _This local hash chain proves in-situ immutability—it mathematically detects event insertion, deletion, or resequencing across local runs."_

#### Mandatory Disclosures to Highlight:

- Local hash chaining proves local integrity; it is not an externally anchored transparency ledger (e.g. Rekor) and does not provide hardware HSM write-once protection.

---

### Step 5 (2:35 – 3:00): Open Limitations & Live Canary Status (`#security-findings`)

- **Navigation:** Press `4` (or click `Security Findings` in sidebar).
- **Visual Focus:** 8 Open Findings Grid and Locked Reserved Candidates Panel.
- **Presenter Action:** Scroll down to the locked panel showing 6 reserved candidates.

#### Spoken Presentation:

> _"We conclude with honest security reporting:_
>
> _We track 8 confirmed open findings, including response payload truncation on large documents above 16KB and lack of production multi-tenant authentication._
>
> _Notice this locked panel: we preserved **6 reserved live adversarial candidates completely unexecuted and untouched**. They are reserved for independent founder validation._
>
> _Our single live Meta Model API call in Phase 4B.1 was a transport compatibility canary verifying HTTP headers and token cost reservation; it was not an adversarial benchmark._
>
> _Veylith brings verifiable, transparent defense-in-depth to autonomous agent tool interactions."_

---

## Presenter Quick Reference Card

| View         | Shortcut | Key Metric / Point to Mention                                                           |
| :----------- | :------: | :-------------------------------------------------------------------------------------- |
| **Overview** |   `1`    | 3 boundaries (discovery, arguments, responses); <0.05ms invariants vs ~5.9ms proxy.     |
| **Demo**     |   CLI    | `pnpm demo -- --all`: 4 scenarios pass, zero external requests, loopback only.          |
| **Eval Lab** |   `2`    | Phase 2A: 93.8% precision, 46.9% recall (honest FN disclosure); 50/56 and 68/72 scored. |
| **Audit**    |   `3`    | Sequential SHA-256 canonical JSON chain; secret masking (`***`); local integrity.       |
| **Findings** |   `4`    | 8 open limitations; 6 live candidates untouched; 1 compatibility canary completed.      |
