# Phase 2F — targeted security boundary remediation

Targeted code and regression work is complete. The boundary is suitable for continued local research and a constrained local dashboard, subject to the restrictions below. It is **not production certified**. Unknown prose now reaches review without depending on an attack keyword, supported tool contracts survive real MCP transport, unsupported subscriptions are explicitly disabled, and audit retention is bounded. Real semantic detection quality, production authentication, persistent subscriptions, external audit anchoring and retained heap growth remain unresolved.

## 1. Reproduced defects and evidence integrity

The starting branch was clean at `82b492a5d8c8ae54d2b7974df342e976914a7c49`. New development assertions reproduced three untrusted-prose routing omissions (novel wording, French, and ordinary prose), fragmented prompt-message bypass, and unbounded audit retention: **5/5 failed before remediation**. Protocol assertions reproduced schema widening/invalid-argument acceptance and unsupported subscription advertisements/forwarding: **9/10 failed before**, with one compatibility control already passing. All original **194 tests passed** on that baseline.

The original source audit and final-run evidence were reviewed before changes. Frozen holdout inputs/labels/outcomes, the six reserved live candidates, their manifest, Phase 2E reports and original evidence are unchanged. No Phase 2E holdout prediction or reserved live evaluation was run during remediation. Existing integrity tests only hash-check the frozen dataset. All fixes use new development assertions; the 72-case comparison uses previously available development cases and is not independent accuracy evidence. A later run of the previously evaluated holdout must be labeled a previously-seen regression evaluation.

Before/intermediate failed logs are retained under [before evidence](../../../security-lab/phase-2f/before/provenance.json), including the exact-echo regression, SDK capability auto-advertisement, metadata key-order discrepancy, modern-protocol fixture negotiation and loaded-test deadline failures. An initial lifecycle harness sent only echoes while expecting a mixed workload; its 400 mismatches are retained. Request wiring was corrected without changing expected semantics. No original test assertion or dataset label was relaxed.

## 2. Concrete changes and source files

| Area                       | Principal source changes                                                                               | Security effect                                                                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Routing                    | `packages/policy-engine/src/routing/{boundary,inspector}.ts`, `engine/index.ts`, core inspection types | Four explicit routing states, provenance/capability decisions, aggregate normalized inspection, scoped prior context, bounded review concurrency/attempts and reason counters   |
| Contracts                  | `contracts/tool-schema.ts`, `capabilities/registry.ts`, gateway `server.ts`, stdio `adapter.ts`        | Preserve accepted JSON Schema, validate current arguments without coercion/defaults, canonical hashes, separate validators per contract and bounded baseline tracking           |
| Protocol lifecycle         | Gateway/stdio serving and forwarding                                                                   | Disable legacy and SDK-owned modern subscriptions; no false notification advertisement; propagate dispatched-request cancellation signals; refresh security-sensitive SDK reads |
| Local admission            | Gateway `http/local-boundary.ts`, `config/index.ts`                                                    | Loopback peer/Host and browser Origin checks, fail-closed defaults, no header-based remote exposure                                                                             |
| Retention                  | `audit/chain.ts`, `sessions/manager.ts`                                                                | Bounded audit tail/checkpoint, streaming full-archive restart verification, disk/line caps, active-session context pruning                                                      |
| Evidence and manual runner | `scripts/security-lab/{fixture,worker,live}.ts`, `scripts/security-remediation/`, root scripts         | Forwarded-argument evidence, routing counters, extended lifecycle, fixed-metadata-only manual approvals                                                                         |

The complete changed-file inventory is in the evidence provenance. [BOUNDARY-DESIGN.md](BOUNDARY-DESIGN.md) specifies bounds, schema exclusions, hash migration, fail-open opt-outs and rotation. No attack-vocabulary rule was added and the mock classifier was not tuned.

## 3. Test results

**252/252 tests passed across 32 files: all 194 existing tests plus 58 focused regressions.** Formatting, lint, workspace typecheck, build, full tests, MCP client demo, security-lab typecheck and remediation-harness typecheck passed. The three demo workflows and JSON-RPC-only stdio output passed. The new local development evaluation completed with negative findings preserved; successful runner execution does not mean every security case passed.

All 15 separate Phase 2E reliability probes were rerun. Their actual outcomes, including any failure, appear in the evidence and reliability discussion below. [REPRODUCE.md](REPRODUCE.md) provides the commands; compressed full logs and machine-readable results are in `security-lab/phase-2f/evidence/`.

## 4. Fast paths, review and fail-safe behavior

Verified fast paths require scalar non-instructional data, validated client arguments to an operator-bound read-only capability, a byte-exact echo of that client data, or an exact operator-pinned content/metadata hash. Read-only retrieval does not establish output trust. First-seen metadata and client/upstream labels cannot establish operator trust.

Untrusted natural-language metadata, resources, prompts and responses need review, including unfamiliar language and missing keywords. Raw, NFKC-normalized and compact aggregate representations face existing invariants. Delivered benign text is unchanged. Only delivered untrusted content is remembered within bounded active upstream/session scopes; it participates in later review and high-impact argument inspection. Different sessions/upstreams do not share history.

Disabled, unavailable, malformed or contradictory semantic output is unknown; default fail-closed policy quarantines it. This is containment through policy, not evidence that an attack was identified. Explicit `FAIL_CLOSED=false` still permits some medium-risk reviews and must not be represented as verified safety. Binary opt-out is marked uninspectable. The detailed request/context/budget bounds are in the design document; the 16-attempt inspection bound is not a universal transport-level paid budget.

In the 72-case mock development run, the router recorded **112 fast-path decisions, 1795 review decisions and 23 deterministic blocks**. Review used 593 actual mock invocations plus 1202 scoped cache hits, with zero budget rejections. Disabled mode made zero inference calls and recorded 1551 unavailable review decisions. These are boundary-decision counts across discovery/requests, not unique samples.

With explicitly pinned fixed fixture metadata, the extended mixed lifecycle recorded 122,000 fast-path decisions and 4,000 reviews (4,000 mock invocations), zero unavailable/budget failures and zero retained session contexts after cleanup. Its 20,000 calls deliberately combine 16,000 exact client echoes and 4,000 untrusted prose outputs; it is a constructed workload, not a representative real deployment.

This deliberately broader routing costs substantially more inference work. Mock timings are not Muse timings or billing estimates. Operators can approve exact known fixture metadata; broad prose approvals would undermine the boundary. Changed content no longer matches its approval; policy revisions require operator review of existing pins. Existing insertion-order-based external schema hashes must be regenerated with the canonical helper.

## 5. Development comparison, classification and enforcement

**72 previously available development cases per mode; 68 classified, including 48 malicious and 20 benign; four operational cases excluded from classification.** These samples reuse the Phase 2E development corpus and 16 seeded local generator cases. They are not newly independent variants. The frozen 56-case holdout and six live reserves were not evaluated. Tiny scenario/tier samples are descriptive, not population estimates. Mock semantic results measure deterministic orchestration and policy behavior, never real model accuracy.

| Run / mode                           | TP / TN / FP / FN (N=68) | Precision / recall | FPR / FNR     | Accuracy | Enforcement (N=72) | Mock calls |
| ------------------------------------ | ------------------------ | ------------------ | ------------- | -------- | ------------------ | ---------- |
| Phase 2E before / deterministic-only | 20 / 20 / 0 / 28         | 100.0% / 41.7%     | 0.0% / 58.3%  | 58.8%    | 45/72 (62.5%)      | 0          |
| Phase 2E before / mock-semantic      | 21 / 20 / 0 / 27         | 100.0% / 43.8%     | 0.0% / 56.2%  | 60.3%    | 47/72 (65.3%)      | 8          |
| Phase 2F after / deterministic-only  | 48 / 0 / 20 / 0          | 70.6% / 100.0%     | 100.0% / 0.0% | 70.6%    | 50/72 (69.4%)      | 0          |
| Phase 2F after / mock-semantic       | 25 / 20 / 0 / 23         | 100.0% / 52.1%     | 0.0% / 47.9%  | 66.2%    | 50/72 (69.4%)      | 593        |

The original before evidence records source `43afac2a4179338a5516e45dae59c78c0b99e834`; it was already preserved on the Phase 2E base. These are separate recorded runs, not a simultaneous controlled performance experiment. After-remediation direct MCP delivered the expected outcome in 19/72 cases (no classification), with 17 forwarding violations under gateway-policy expectations. Disabled mode has one unsupported operational case; mock mode has none. Per-scenario confusion matrices and raw negatives are in the archived summary and observations.

The deterministic-only after result blocks all 20 benign classified cases: unapproved upstream metadata requires unavailable review and is quarantined. Its apparent recall is **not 100% attack detection**. The legacy scorer maps enforced blocks to the binary block label; routing traces retain the missing-inference/unknown reason. A usable disabled-mode installation needs explicit operator-reviewed exact approvals for trusted content. This is a material availability tradeoff.

The unchanged mock still misses all 16 generated development candidates and other attacks despite review being invoked. A stolen local session with a matching forged client label is still accepted: one isolation failure and one prohibited forward remain. It is the same local bearer-impersonation limitation, not repaired authentication. G2 also illustrates why detection and final enforcement must remain separate: policy can prevent a privileged mock action even when retrieved prose was not identified as malicious. Detailed per-case audit and upstream-method evidence is retained.

| Tier           | Cases | Disabled TP / TN / FP / FN | Disabled enforcement | Mock TP / TN / FP / FN | Mock enforcement |
| -------------- | ----: | -------------------------- | -------------------- | ---------------------- | ---------------- |
| easy           |     8 | 4 / 0 / 4 / 0              | 5/8                  | 4 / 4 / 0 / 0          | 8/8              |
| medium         |    12 | 6 / 0 / 6 / 0              | 6/12                 | 5 / 6 / 0 / 1          | 11/12            |
| hard           |    12 | 10 / 0 / 2 / 0             | 10/12                | 9 / 2 / 0 / 1          | 11/12            |
| extremely-hard |    12 | 6 / 0 / 6 / 0              | 6/12                 | 5 / 6 / 0 / 1          | 11/12            |
| god-level      |    28 | 22 / 0 / 2 / 0             | 23/28                | 2 / 2 / 0 / 20         | 9/28             |

Direct MCP has no classifier and lacks gateway-specific session/failure controls; 15 cases are unsupported in that comparison. No third-party gateway was installed/executed or assigned scores. Known paid calls, provider input/output tokens and estimated paid cost are all **zero** for this phase. Mock token fields are simulated and are not provider usage. No real detection-quality claim follows from these numbers.

## 6. MCP schema compatibility evidence

Actual SDK HTTP MCP tests verify structural equality of the published nested schema, including local `$ref`/`$defs`, enum, arrays, bounds, union, required fields and `additionalProperties:false`. Valid arguments reach the fixture unchanged. Six invalid forms (enum, bound, empty array, union type, missing required field and unexpected property) never reach upstream execution. The actual stdio bridge preserves the same contract. Regression checks also cover defaults without insertion/coercion and conflicting upstream `$id` values without validator reuse.

Installed SDK 2.4.0 `fromJsonSchema` and its AJV validator support the accepted structures without a generic-record fallback. Local safety policy deliberately excludes regex patterns, recursive/dynamic/remote references, incompatible dialect vocabulary, unknown validation formats/keywords and header projection. Such tools are quarantined; this reduces compatibility and is not an SDK losslessness claim. Schema size/depth/node and metadata inspection bounds also apply. Security-critical discovery uses `cacheMode:'refresh'`, and contracts are rechecked immediately before forwarding. An upstream behavior change after that check remains an unavoidable residual TOCTOU race without an upstream atomic version/call contract.

## 7. Subscription, cancellation and reconnect evidence

Persistent resource subscriptions are **unsupported and removed**, as permitted by the task. HTTP and stdio advertise neither resource subscribe nor tool/resource/prompt list-change relay. Legacy subscribe/unsubscribe and raw reconnect requests cannot create upstream subscription effects. SDK-owned modern `subscriptions/listen` is explicitly limited to zero; real HTTP and stdio clients pinned to protocol `2026-07-28` receive the asserted server rejection. This prevents an SDK-owned unscoped stream from bypassing removed application handlers.

Dispatched tool/resource/prompt operations receive downstream cancellation signals. Resource/prompt sessions are rechecked before forwarding. Tests and probes demonstrate recovery and unsupported-capability rejection; they do not prove cessation of work already executing remotely or a complete persistent notification lifecycle. Full subscription authorization, relay, cancellation and reconnect support remains future work.

## 8. Authentication assumptions

The listener defaults to loopback; non-loopback configuration is rejected. HTTP peer/Host guards also protect against accidental programmatic rebinding, and hostile browser Origins are denied even with forged identity/session labels. Native no-Origin local MCP clients remain supported. `x-veylith-client-id` is untrusted correlation data and Veylith sessions remain local bearer capabilities. A local process with a stolen session and matching label can impersonate the holder.

The future deployment design requires TLS and verification of signed issuer/audience/expiry/scopes before session creation, verified principal binding and stripping untrusted forwarding/identity labels. A proxy to loopback does not establish identity. No remote authentication service, endpoint or cloud resource was implemented. See the minimal design in [BOUNDARY-DESIGN.md](BOUNDARY-DESIGN.md).

## 9. Audit durability, retention and resource investigation

Memory retains at most 2,048 audit records by default, with global sequence continuation and an explicit evicted-prefix checkpoint. Verification of the retained tail is scoped to that checkpoint. Durable restart streams and verifies the complete archive before writing, rather than loading all records. Records are defensively copied. Disk storage is capped at 64 MiB by default, each JSONL line at 64 KiB, and capacity/write failure fails closed. Persistent history is not silently truncated by retention.

**13/15 inherited reliability probes passed; two failed and remain failures in the archive.** The paused-consumer probe expects a 2 MiB prose response and reports 'Large response truncated'; the six-cycle disabled-mode MCP probe reports 'Method not found'. This inherited harness disables inference without approving its metadata, so discovery quarantine can prevent normal execution. Its byte-count-only response probe does not capture the rejection body and cannot distinguish policy rejection from transport truncation. Independently, the new 16 KiB inspection bound would quarantine that 2 MiB prose even after metadata approval; a focused regression verifies over-budget quarantine without inference. These are material compatibility/availability losses; the old backpressure result is not re-established. Neither expected outcome was changed to make the probe pass. The separate explicitly approved mixed lifecycle provides transport/cleanup evidence but does not erase these failures.

Passing probes cover abrupt process death after fsync acknowledgement/restart, torn final JSONL rejection, competing processes/stale writers, live truncation, simulated partial-write/ENOSPC with sticky failure, closed sinks, custom TTL, component cleanup, actual-default HTTP 413, malformed JSON 400, early-disconnect recovery and upload admission 429. No real disk exhaustion was used. The actual default body limit is still **1,048,576 bytes**; Phase 2D tests use 262,144 bytes and the development lab 8,192 bytes.

Current audit timing (200 appends per arm): memory 58954.3 appends/sec; durable lock + JSON + synchronous fsync 271.0 appends/sec; measured incremental overhead 3.673 ms/append. This is not isolated fsync latency. Development/lifecycle gateway timings use in-memory audit and exclude this durable overhead.

External anchoring is still absent. Valid-prefix suffix truncation after restart or an attacker rewriting a complete local chain/checkpoint cannot be authenticated. Locks and fsync are not a power-loss guarantee. Manual secure rotation requires stop/flush, complete-archive verification/preservation and an authenticated external archive index if continuity is required. Capacity failures trade availability for evidence preservation. Rotation automation is deferred.

Actual host metadata: **Apple M5, 10 logical CPUs, 34,359,738,368 bytes RAM (32 GiB), Node v24.21.0**, reported by the local runtime rather than hardcoded benchmark claims.

The extended measurement ran **1,000 cycles, 1,000,000 session/audit component operations and 20,000 actual HTTP MCP calls**, with GC samples each cycle. Component phase: 15.88 s, retained growth after ten warmup cycles **+332,456 bytes**. HTTP phase: 81.11 s, **0 observed response failures**, 246.58 calls/sec, p50/p95/p99 **3.17/4.22/5.70 ms**.

HTTP heap after warmup rose from 39,306,896 to 49,196,824 bytes (**+9,889,928 bytes**). Samples at cycles 100/500/999 were 41,808,688/45,570,072/49,196,824; no convincing plateau is established. The earlier 100-cycle run is separately preserved (growth +2,490,432 bytes). Final active sessions/history scopes were zero; retained audit stayed at 2,048 of 126,000 events and verified against its checkpoint. Component audit stayed at 128 of 1,000,000 events.

This single process includes the gateway, upstream fixture, SDK and intentionally retained measurement arrays. Growth cannot be attributed solely to the gateway; attribution/profiling and longer repeated process runs remain required. An 81-second HTTP exercise is stronger than the prior brief cleanup test but is not a production soak or absence-of-leaks proof.

| Mode (72 cases)    | p50 / p95 / p99 ms     | Cases/sec |
| ------------------ | ---------------------- | --------: |
| deterministic-only | 9.93 / 41.21 / 86.98   |     24.93 |
| direct             | 4.63 / 17.60 / 38.93   |     30.33 |
| mock-semantic      | 12.22 / 44.65 / 101.78 |     23.31 |

Case timing includes protocol setup, discovery and teardown, and throughput includes the lab's intentional recovery cooldown. It is not gateway capacity. The lifecycle rate uses fixed local metadata approvals and mock inference; neither rate predicts real-provider latency.

## 10. Remaining vulnerabilities and limitations

- Real-model semantic robustness is unknown; mock false negatives remain. Routing a case for review does not ensure detection or enforcement. Aggregation/history are deliberately bounded and cannot retain arbitrary long attack chains.
- Local bearer theft/forged labels remain possible. No production principal authentication or remote deployment assurance exists.
- Upstream configured URL identity is not attestation; behavior may change after schema preflight. Capability bindings are operator trust assertions.
- Persistent notifications remain unavailable. Cancellation propagation does not guarantee remote computation stops; all discovery/connection work is not covered by one end-to-end deadline.
- Fail-closed unknown content can block legitimate workflows and metadata. Unsupported schema exclusions reduce MCP compatibility. Broader semantic routing can be expensive; production-wide provider spending controls remain separate work.
- Audit anchoring and automatic verified rotation are absent. Positive retained heap growth remains unattributed; finite local runs cannot establish leak freedom.
- Existing circuit-breaker half-open concurrency and broader resource/failure schedules still need further investigation. No comprehensive DoS or production security certification is claimed.

## 11. Provenance and Git state

Evaluated source commit: `36fa675051f85437db55a5ccfff6ce18b7791392`, branch `dev/phase-2f-boundary-remediation`, with a clean working tree when measurement began. Earlier implementation commits are `748f5bff19e9a78259b2687b7f690381e6205494` and `90e989a41a05b0b4d9e889adbf7122e0c96945af`. The subsequent delivery commit adds only reports and archived evidence; its exact hash is reported in the final handoff and local Git log. No push, remote pull request, deployment, dashboard or external attack target was used.

The evidence [PROVENANCE.json](../../../security-lab/phase-2f/evidence/PROVENANCE.json) records base/source revisions, protected-file digests, original evidence tree, gates and archive hashes. The unchanged frozen manifest SHA-256 is `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. Reproduction commands must retain their source commit and manifest; post-remediation holdout reuse must not be called first-look independence.

## 12. MANUAL ACTIONS REQUIRED FROM FOUNDER

The existing six-case Muse runner is **ready for a separately authorized, bounded compatibility evaluation**, not proven to work against the real provider. A new, nonreserved HTTP fixture verifies its exact response-only review shape with one mock invocation. Only fixed local metadata is operator-approved. No reserved response was executed, no credentials requested and no paid request sent. No live attempt marker was created by Phase 2F.

Review [LIVE-COMPATIBILITY.md](LIVE-COMPATIBILITY.md) and the original [safe key-entry instructions](../phase-2e/LIVE-META.md). Separately approve any live run, confirm provider model/API compatibility and current rates/limits, then enter a dedicated limited key only through the hidden local terminal prompt. Do not put a key in chat, a source file, command argument or `.env`. Use at most six requests, no retries, bounded tokens/cost, preserve the one-attempt marker and usage even for incomplete responses. Confirm provider billing independently. Real detection metrics and real provider availability remain pending.

## 13. Phase 3 verdict

**Conditional go for a narrowly scoped, local, read-only research dashboard.** It must escape untrusted MCP text, show policy mode/routing reasons and provenance, distinguish unknown/quarantine from detected attacks, mask bearer/session identifiers, and expose neither secrets, execution controls, live inference triggers nor remote/public access. The unresolved findings above must remain visible. No dashboard has been implemented. Remote deployment, production security claims and a dashboard that can authorize tool execution remain no-go until their own security work is completed.
