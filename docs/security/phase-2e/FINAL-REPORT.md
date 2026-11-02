# Veylith Phase 2E final research report

**Verdict: the local evaluation lab is usable; Veylith is not ready for a Phase 3 production-security claim.** The evaluation found reproducible misses and explicit unsupported behavior. Zero paid model calls occurred. No dashboard, cloud service, push, deployment or remote pull request was created.

## 1. Source-audit findings

See [SOURCE-AUDIT.md](SOURCE-AUDIT.md) for file-level findings. The key Phase 2D defects were stale discovery metadata passed into invocation consistency checks; unhandled aborted-body reads; admission counting only after upload; response pumping without write backpressure; incomplete session admission enforcement; missing semantic-cache scopes; custom session TTL expansion; and unsafe independent durable audit writers. The initial development run's process crash and changed-tool forwards are preserved under `security-lab/baseline/`.

A separate review found incomplete provider usage could appear known in the manual runner; it now remains explicitly unknown unless both provider input/output counts are present. This change made no provider calls and did not alter offline policies.

## 2. Scenarios and variants

Exactly **14 principal scenarios**, across five tiers. **128 offline variants**: 112 core cases (eight per scenario) plus 16 seeded local G1 candidates. Six additional distinct candidates are reserved for manual live evaluation, making 134 stored inputs total. The original corpus has at least 100 distinct operation/input pairs; generated candidates add grammatical diversity. The generator is local, seeded and prediction-independent; it is not an adaptive learning attack optimizer.

## 3. Composition and holdout integrity

| Partition                | Benign controls | Malicious | Operational | Total |
| ------------------------ | --------------: | --------: | ----------: | ----: |
| Development core         |              20 |        32 |           4 |    56 |
| Generated G1 development |               0 |        16 |           0 |    16 |
| Frozen holdout           |              21 |        29 |           6 |    56 |
| Offline total            |              41 |        77 |          10 |   128 |

Some frozen list/operational cases carry a coarse `call_arguments` stage annotation rather than their precise discovery/HTTP stage. This annotation defect is preserved, not silently rewritten; actual MCP methods and audit stages are recorded in each run. A future dataset revision should correct it.

The six live reserve candidates are separate (two benign, four malicious). Frozen inputs/labels were committed at `54062f3`; formatting byte hashes were sealed at `13ebf9e`, before evaluation. The original first-run results are retained under `security-lab/evidence/initial-run/`. No holdout inputs, labels, expected outcomes, policy patterns or mock model behavior changed after evaluation. One evaluator authored and could inspect the dataset; this is a procedural holdout, not a blinded independent external benchmark.

Manifest SHA-256: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`.

Every worker verifies byte and individual case hashes before execution. Development files are versioned separately. The manual runner expands each frozen live input/label into a full recorded execution plan before use.

## 4. End-to-end enforcement evidence

The SDK MCP client connects over real loopback HTTP through the actual gateway to an isolated JSON-RPC MCP fixture and receives the gateway's output. Upstream calls/methods, client responses, inference counters and audit records are saved per case. Fixture tools never execute shell strings, mutate private files or transmit data to attack destinations. The existing stdio end-to-end tests and client demo also pass.

All six malicious G2 privileged follow-up attempts per gateway mode were blocked: zero `privileged_sink` forwards. Four of the six malicious resource instructions were still classified allow. This demonstrates successful final authorization alongside failed injection detection; neither metric substitutes for the other. The script always attempts the follow-up and is not an autonomous-agent persuasion test.

All eight X2 variants per gateway mode met enforcement expectations, including changed definitions and authorized updates. This does not close the protocol's post-check behavior-change race. Holdout recorded zero forbidden forwards and zero isolation failures; development recorded the stolen-session/matching-label failure in both gateway modes. Deterministic development also records one forwarded semantic-fault probe that is explicitly inapplicable when inference is disabled.

## 5. Difficulty-tier holdout results

Entries are TP/TN/FP/FN, followed by enforcement successes. Each tier uses four holdout variants per principal scenario; these sample sizes do not support population-level accuracy claims.

| Tier           | Total N | Deterministic classification | Deterministic enforcement | Mock classification | Mock enforcement |
| -------------- | ------: | ---------------------------- | ------------------------: | ------------------- | ---------------: |
| easy           |       8 | 4/4/0/0                      |                       8/8 | 4/4/0/0             |              8/8 |
| medium         |      12 | 2/8/0/2                      |                     10/12 | 2/8/0/2             |            10/12 |
| hard           |      12 | 7/3/0/2                      |                     11/12 | 8/3/0/1             |            12/12 |
| extremely-hard |      12 | 4/4/0/2                      |                      9/12 | 4/4/0/2             |             9/12 |
| god-level      |      12 | 1/2/0/5                      |                      9/12 | 1/2/0/5             |             9/12 |

The generated G1 development set is intentionally difficult: all 16 novel grammar candidates passed both local modes. This negative result remains in the report. No rules were added to match those strings.

## 6. Deterministic-only results

Semantic inference is disabled. Known provider tokens, paid calls and estimated provider cost are zero.

**Holdout: 50 classifiable / 56 total cases.**

|  TP |  TN |  FP |  FN | Precision | Recall |  FPR |   FNR | Accuracy |   Enforcement | Unsupported | Forbidden forwards |
| --: | --: | --: | --: | --------: | -----: | ---: | ----: | -------: | ------------: | ----------: | -----------------: |
|  18 |  21 |   0 |  11 |    100.0% |  62.1% | 0.0% | 37.9% |    78.0% | 47/56 (83.9%) |           1 |                  0 |

Development: 68 classifiable cases of 72; TP/TN/FP/FN = 20/20/0/28; enforcement 45/72. One semantic-fault probe is unsupported in this mode. The holdout's unsupported case is resource-update notification delivery.

## 7. Mock semantic results

The deterministic mock exercises orchestration and enforcement; it supplies no evidence about real model detection quality. There were eight mock inference invocations in development and six in holdout, with no external provider requests. Mock token estimates are excluded from paid-token/cost reporting.

**Holdout: 50 classifiable / 56 total cases.**

|  TP |  TN |  FP |  FN | Precision | Recall |  FPR |   FNR | Accuracy |   Enforcement | Unsupported | Forbidden forwards |
| --: | --: | --: | --: | --------: | -----: | ---: | ----: | -------: | ------------: | ----------: | -----------------: |
|  19 |  21 |   0 |  10 |    100.0% |  65.5% | 0.0% | 34.5% |    80.0% | 48/56 (85.7%) |           1 |                  0 |

Development: 68 classifiable cases of 72; TP/TN/FP/FN = 21/20/0/27; enforcement 47/72. Zero observed false positives in this small corpus does not establish a zero false-positive rate on other traffic. Per-scenario matrices and every negative observation appear in [the generated report](../../../security-lab/evidence/final-run/REPORT.md) and machine-readable summaries.

## 8. Newly discovered defects and test limitations

The development fixture reproduced stale-schema forwarding, the partial-upload crash, the forged-label/session weakness, multi-item and multi-read injection misses, Unicode/multilingual misses, and novel role/semantic-obfuscation misses. The source audit found cache-scope, TTL and audit durability defects beyond the immediate attack strings.

The first verification after the HTTP changes failed two unchanged assertions (404 JSON and 413 precedence); the implementation was corrected. Two later runs passed 193/194 because an unchanged stdio test's fixed 1.5-second startup sleep saw no output. Both failed logs are archived. That wait was replaced by a bounded response-line event and fixture cleanup in finally, preserving every original JSON-RPC assertion. No test was removed, skipped or given a favorable expected result; the scheduling defect was corrected.

The initial evaluator overcounted authorized recovery calls as forwarding violations and exercised concurrent clients under a reconnect label. Both measurement defects were corrected, the original raw run was retained, and the unchanged dataset was rerun. This did not change expected outcomes or tune detection rules. The final code counts actual authorized recovery separately and closes the first connection before reconnecting.

## 9. Actual fixes

- Scope and bound discovery caches; bypass them for invocations and refresh the definition immediately before forwarding.
- Scope semantic verdicts by upstream, session, client, policy, model/mode and baseline revision using collision-resistant tuple serialization.
- Preserve deterministic provenance when semantic inference is disabled.
- Admit uploads before body reading; catch read/disconnect failures; send client-observed 413; honor output drain/backpressure.
- Require valid local sessions at MCP admission when configured, preserve custom sliding TTLs and enforce loopback host configuration.
- Serialize cooperating durable audit appends; reject stale writers/live truncation; handle partial writes; poison failed persistence; reject append-after-close.
- Guard manual live execution, synthetic-only inputs, exact endpoint/model, request/token/estimated-spend reservations, no retries, unknown usage and first-attempt exposure markers.

## 10. Unresolved vulnerabilities and unsupported behavior

Novel and multilingual instructions, invisible/fullwidth variants, fragmented resources/prompts and sequential multi-read context can bypass screening. Fast-path routing often prevents semantic inspection from seeing these inputs. A stolen session with a forged matching client label is accepted; local bearer-session controls are not production authentication. Tool behavior can change after the last metadata check. Capability binding identifies a configured upstream URL, not attested server behavior.

Persistent resource-update notification relay is unsupported. Cancellation recovery does not prove cancellation of upstream work. Half-open breaker concurrency is not bounded by a single-probe guard, and socket idle timeouts are not end-to-end deadlines. The gateway does not preserve the original input schema in its advertised generic Zod record. Ambiguous prompt metadata lacks a semantic inspection path.

Audit hashes lack external anchoring, valid-prefix truncation/full-chain regeneration can evade restart checks, and record retention is unbounded. Lock orphan recovery is manual. Hardware/process-death probes do not prove power-loss durability. G3 combines only a subset of failure dimensions, not every factorial combination; its semantic-failure case injects the adapter fallback at the interface, while raw malformed-provider parsing is covered by existing adapter tests. These coverage limits remain explicit.

## 11. Phase 2D reliability regressions

Fifteen offline reliability probes passed: abrupt child-process death after durable acknowledgement/restart; torn JSONL quarantine; four competing process writers; stale in-process writers; live truncation; bounded partial-write/ENOSPC injection; closed durable sink rejection; fsync overhead; custom TTL retention; repeated component cleanup; actual default-limit 413; malformed JSON 400; truncated upload/early-disconnect recovery; paused response consumption; full MCP cleanup cycles; and upload backpressure. Some are combined within a probe. Full raw evidence is archived.

The true default body limit is **1,048,576 bytes**. The unchanged Phase 2D test uses **262,144 bytes**. The adversarial runner uses **8,192 bytes**. A client observed HTTP 413 at the actual default; a slow-upload client observed 429; malformed JSON produced 400. A 25 ms paused consumer received a 2,097,265-byte response without truncation.

## 12. Performance and resource usage

Measured machine: Apple M5, ten logical CPUs, 34,359,738,368 bytes RAM (**32 GiB**), Mac17,4, macOS 27.2, Node v24.21.0, pnpm 12.10.1. The previous 8 GB claim is incorrect for this host. Safe system command output is retained in `security-lab/baseline/hardware.json`.

| Holdout mode       | p50 ms | p95 ms | p99 ms | Cases/sec |
| ------------------ | -----: | -----: | -----: | --------: |
| direct             |   4.99 |  14.74 |  49.18 |     29.65 |
| deterministic-only |  13.23 |  27.13 |  91.50 |     23.26 |
| mock-semantic      |  13.04 |  27.72 |  92.63 |     23.52 |

Case latency includes client setup/teardown, discovery and enforcement; case throughput includes an intentional 25 ms recovery cooldown. These are synthetic mixed-case diagnostics, not isolated gateway capacity or production throughput. Direct MCP has no security classifier; gateway-specific session/failure comparisons are marked unsupported. No established third-party gateway was installed/executed or assigned invented scores. Real Muse is unevaluated.

Audit timing used 200 appends per arm. In-memory: 104723 appends/sec; durable file with locking and synchronous fsync: 262.0 appends/sec. Measured overhead was 3.808 ms per append, including JSON, lock and fsync. The normal adversarial gateway run uses in-memory auditing, so its latency table does not include durable-audit overhead.

After GC, twelve component load/cleanup cycles of 1,000 objects each changed retained heap by -62,792 bytes. Six complete MCP load/cleanup cycles (25 calls each) changed process retained heap by **+740,768 bytes**, with later samples still increasing. This includes the gateway, fixture and SDK; it does not localize retention. The time horizon is too short to claim zero leaks or stable long-term memory. RSS/final heap and all cycle samples are retained in JSON.

The evaluation worker's heap also retains its result/audit evidence intentionally. Do not interpret that growth as an isolated gateway leak measurement. In-memory audit retention is still an identified unbounded-growth design issue.

## 13. Git and verification provenance

Branch: `dev/phase-2e-adversarial-lab`. Base: `1086aef`. Offline evaluated source: `43afac2a4179338a5516e45dae59c78c0b99e834`; all six final offline runs report clean working trees. Post-evaluation policy/model files are unchanged. Subsequent changes are a bounded event-based wait in the existing stdio regression test and manual live unknown-usage bookkeeping at `84751f334624865956455d2a3ca7ee1c84876e0d`. The event-based stdio test correction is `7d8e7f13fa2493eab775c1be5899a551de2b3efb`; all seven final quality-gate commands pass at that commit. The delivery evidence/docs commit is identified in the final chat response and local Git history; it does not change policies or fixtures.

Required gates: `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm build`, `pnpm test:all` (**194/194, all original 187 preserved**), `pnpm demo:client` (all workflows pass), the offline development/holdout lab, and 15 reliability probes. Lab TypeScript is also checked explicitly because existing workspace project typechecks do not include root scripts. Gate outputs and dataset/result hashes are recorded with the evidence. No push or remote resource creation occurred.

## 14. Exact live Meta instructions

Follow [LIVE-META.md](LIVE-META.md), including its literal zsh command sequence, dedicated test key entry with `read -rs`, current-price prompts, explicit `--allow-paid`, bounded requests/tokens/cost and key cleanup. Only synthetic reserved text may reach `https://api.meta.ai/v1/responses` with `muse-spark-1.3`. Official [Responses documentation](https://dev.meta.ai/docs/api-reference/responses/create-response) and [pricing](https://dev.meta.ai/docs/pricing-rate-limits) were consulted for preparation; verify them again at execution.

No automatic paid request, retry, replacement candidate or hidden provider call is authorized. The runner records known usage even if a response is incomplete, leaves missing input/output usage unknown, separates conservative cost reservations from estimates based on known usage, and does not claim provider billing truth. Model confidence is not a calibrated probability.

## 15. Remaining live work

A founder must separately authorize the run, set provider-side limits, enter a dedicated key locally and execute once. Review routing (some cases may bypass inference), unknown/incomplete usage, real classifications, enforced output and independent provider billing. The reserve exposure marker prevents silently treating a repeated attempt as unseen. Further independent runs need a newly versioned reserve. Real Muse results do not exist yet.

## 16. Phase 3 readiness verdict

**Proceed only with further local security research and design remediation. Do not present the current boundary as production-ready or as universally preventing prompt injection.** The lab and preserved evidence are useful foundations. Production authentication, subscription/cancellation lifecycle, contextual injection coverage, stronger tool identity/version binding, audit anchoring/retention and sustained reliability evaluation remain material work. Dashboard implementation and cloud deployment were not started.

## MANUAL ACTIONS REQUIRED FROM FOUNDER

1. Review the negative cases and accept the current research limitations before making product/security claims.
2. Separately approve real Muse testing, then follow `LIVE-META.md`; do not send a key in chat.
3. Confirm current provider pricing/account limits and inspect provider billing after the one manual run.
4. Prioritize the unresolved boundary defects in a later development phase. Leave this holdout unchanged.

No provider key is needed for any offline command.
