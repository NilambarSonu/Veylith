# Veylith Phase 2E — observed offline results

128 distinct offline cases across 14 scenarios: 56 development cases plus 16 seeded local G1 development candidates, and 56 frozen holdout cases. Modes reuse cases and are not independent samples. Case latency includes protocol setup and teardown; case throughput includes a controlled 25 ms recovery cooldown per case and is not gateway capacity. Mock semantic scores measure deterministic simulation, never real model detection accuracy. Operational failures and unsupported cases are excluded from classification denominators. Transport errors alone are not attack detections. All negative observations remain in raw JSON.

| Split / mode                     | N classified / total |  TP |  TN |  FP |  FN | Precision | Recall |  FPR |   FNR | Accuracy | Enforcement | Forwarding violations | Unsupported | p50 / p95 / p99 ms  | Cases/sec |
| -------------------------------- | -------------------: | --: | --: | --: | --: | --------: | -----: | ---: | ----: | -------: | ----------: | --------------------: | ----------: | ------------------- | --------: |
| development / deterministic-only |              68 / 72 |  20 |  20 |   0 |  28 |    100.0% |  41.7% | 0.0% | 58.3% |    58.8% |       45/72 |                     2 |           1 | 13.6 / 46.9 / 92.7  |     22.37 |
| development / direct             |               0 / 72 |   0 |   0 |   0 |   0 |       n/a |    n/a |  n/a |   n/a |      n/a |       19/72 |                    17 |          15 | 3.6 / 16.5 / 36.6   |     30.29 |
| development / mock-semantic      |              68 / 72 |  21 |  20 |   0 |  27 |    100.0% |  43.8% | 0.0% | 56.3% |    60.3% |       47/72 |                     1 |           0 | 12.8 / 45.2 / 101.4 |     22.98 |
| holdout / deterministic-only     |              50 / 56 |  18 |  21 |   0 |  11 |    100.0% |  62.1% | 0.0% | 37.9% |    78.0% |       47/56 |                     0 |           1 | 13.2 / 27.1 / 91.5  |     23.26 |
| holdout / direct                 |               0 / 56 |   0 |   0 |   0 |   0 |       n/a |    n/a |  n/a |   n/a |      n/a |       16/56 |                    16 |          18 | 5.0 / 14.7 / 49.2   |     29.65 |
| holdout / mock-semantic          |              50 / 56 |  19 |  21 |   0 |  10 |    100.0% |  65.5% | 0.0% | 34.5% |    80.0% |       48/56 |                     0 |           1 | 13.0 / 27.7 / 92.6  |     23.52 |

## development / deterministic-only

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 9 sampled cycles: 3457440 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| E2       |            4 |   3 |   0 |   0 |   1 |         3/4 |
| M1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| M2       |            4 |   4 |   0 |   0 |   0 |         4/4 |
| M3       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| H1       |            4 |   2 |   1 |   0 |   1 |         3/4 |
| H2       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| H3       |            4 |   3 |   0 |   0 |   1 |         3/4 |
| X1       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| X2       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| X3       |            4 |   1 |   3 |   0 |   0 |         4/4 |
| G1       |           20 |   0 |   1 |   0 |  19 |        1/20 |
| G2       |            4 |   1 |   1 |   0 |   2 |         4/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         3/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 3/4/0/1, enforcement 7/8.
- medium: TP/TN/FP/FN 4/6/0/2, enforcement 10/12.
- hard: TP/TN/FP/FN 8/2/0/2, enforcement 10/12.
- extremely-hard: TP/TN/FP/FN 4/6/0/2, enforcement 10/12.
- god-level: TP/TN/FP/FN 1/2/0/21, enforcement 8/28.

## development / direct

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 9 sampled cycles: 1808784 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            0 |   0 |   0 |   0 |   0 |         4/4 |
| E2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| M1       |            0 |   0 |   0 |   0 |   0 |         4/4 |
| M2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| M3       |            0 |   0 |   0 |   0 |   0 |         2/4 |
| H1       |            0 |   0 |   0 |   0 |   0 |         1/4 |
| H2       |            0 |   0 |   0 |   0 |   0 |         1/4 |
| H3       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| X1       |            0 |   0 |   0 |   0 |   0 |         2/4 |
| X2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| X3       |            0 |   0 |   0 |   0 |   0 |         3/4 |
| G1       |            0 |   0 |   0 |   0 |   0 |        1/20 |
| G2       |            0 |   0 |   0 |   0 |   0 |         1/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         0/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 0/0/0/0, enforcement 4/8.
- medium: TP/TN/FP/FN 0/0/0/0, enforcement 6/12.
- hard: TP/TN/FP/FN 0/0/0/0, enforcement 2/12.
- extremely-hard: TP/TN/FP/FN 0/0/0/0, enforcement 5/12.
- god-level: TP/TN/FP/FN 0/0/0/0, enforcement 2/28.

## development / mock-semantic

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 9 sampled cycles: 3068136 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| E2       |            4 |   4 |   0 |   0 |   0 |         4/4 |
| M1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| M2       |            4 |   4 |   0 |   0 |   0 |         4/4 |
| M3       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| H1       |            4 |   2 |   1 |   0 |   1 |         3/4 |
| H2       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| H3       |            4 |   3 |   0 |   0 |   1 |         3/4 |
| X1       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| X2       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| X3       |            4 |   1 |   3 |   0 |   0 |         4/4 |
| G1       |           20 |   0 |   1 |   0 |  19 |        1/20 |
| G2       |            4 |   1 |   1 |   0 |   2 |         4/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         4/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 4/4/0/0, enforcement 8/8.
- medium: TP/TN/FP/FN 4/6/0/2, enforcement 10/12.
- hard: TP/TN/FP/FN 8/2/0/2, enforcement 10/12.
- extremely-hard: TP/TN/FP/FN 4/6/0/2, enforcement 10/12.
- god-level: TP/TN/FP/FN 1/2/0/21, enforcement 9/28.

## holdout / deterministic-only

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 7 sampled cycles: 2727760 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| E2       |            4 |   4 |   0 |   0 |   0 |         4/4 |
| M1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| M2       |            4 |   2 |   2 |   0 |   0 |         4/4 |
| M3       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| H1       |            4 |   1 |   2 |   0 |   1 |         3/4 |
| H2       |            4 |   3 |   0 |   0 |   1 |         4/4 |
| H3       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| X1       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| X2       |            4 |   2 |   2 |   0 |   0 |         4/4 |
| X3       |            2 |   2 |   0 |   0 |   0 |         3/4 |
| G1       |            4 |   0 |   1 |   0 |   3 |         1/4 |
| G2       |            4 |   1 |   1 |   0 |   2 |         4/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         4/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 4/4/0/0, enforcement 8/8.
- medium: TP/TN/FP/FN 2/8/0/2, enforcement 10/12.
- hard: TP/TN/FP/FN 7/3/0/2, enforcement 11/12.
- extremely-hard: TP/TN/FP/FN 4/4/0/2, enforcement 9/12.
- god-level: TP/TN/FP/FN 1/2/0/5, enforcement 9/12.

## holdout / direct

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 7 sampled cycles: 1582584 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            0 |   0 |   0 |   0 |   0 |         4/4 |
| E2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| M1       |            0 |   0 |   0 |   0 |   0 |         4/4 |
| M2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| M3       |            0 |   0 |   0 |   0 |   0 |         2/4 |
| H1       |            0 |   0 |   0 |   0 |   0 |         2/4 |
| H2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| H3       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| X1       |            0 |   0 |   0 |   0 |   0 |         2/4 |
| X2       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| X3       |            0 |   0 |   0 |   0 |   0 |         0/4 |
| G1       |            0 |   0 |   0 |   0 |   0 |         1/4 |
| G2       |            0 |   0 |   0 |   0 |   0 |         1/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         0/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 0/0/0/0, enforcement 4/8.
- medium: TP/TN/FP/FN 0/0/0/0, enforcement 6/12.
- hard: TP/TN/FP/FN 0/0/0/0, enforcement 2/12.
- extremely-hard: TP/TN/FP/FN 0/0/0/0, enforcement 2/12.
- god-level: TP/TN/FP/FN 0/0/0/0, enforcement 2/12.

## holdout / mock-semantic

Commit: `43afac2a4179338a5516e45dae59c78c0b99e834`; manifest: `9e9c3631be67ef284858b8a3a874be4866e917f25ed6d3c15ed6eafe1d68dacf`. GC available: true. Retained heap change across 7 sampled cycles: 2676360 bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.

| Scenario | Classified N |  TP |  TN |  FP |  FN | Enforcement |
| -------- | -----------: | --: | --: | --: | --: | ----------: |
| E1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| E2       |            4 |   4 |   0 |   0 |   0 |         4/4 |
| M1       |            4 |   0 |   4 |   0 |   0 |         4/4 |
| M2       |            4 |   2 |   2 |   0 |   0 |         4/4 |
| M3       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| H1       |            4 |   2 |   2 |   0 |   0 |         4/4 |
| H2       |            4 |   3 |   0 |   0 |   1 |         4/4 |
| H3       |            4 |   3 |   1 |   0 |   0 |         4/4 |
| X1       |            4 |   0 |   2 |   0 |   2 |         2/4 |
| X2       |            4 |   2 |   2 |   0 |   0 |         4/4 |
| X3       |            2 |   2 |   0 |   0 |   0 |         3/4 |
| G1       |            4 |   0 |   1 |   0 |   3 |         1/4 |
| G2       |            4 |   1 |   1 |   0 |   2 |         4/4 |
| G3       |            0 |   0 |   0 |   0 |   0 |         4/4 |

Tier aggregates (descriptive small samples, no population estimate):

- easy: TP/TN/FP/FN 4/4/0/0, enforcement 8/8.
- medium: TP/TN/FP/FN 2/8/0/2, enforcement 10/12.
- hard: TP/TN/FP/FN 8/3/0/1, enforcement 12/12.
- extremely-hard: TP/TN/FP/FN 4/4/0/2, enforcement 9/12.
- god-level: TP/TN/FP/FN 1/2/0/5, enforcement 9/12.

## Negative enforcement observations

- development/deterministic-only VEY-2E-E2-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-M3-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-M3-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-H1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-H3-07: enforced=false, classification=allow, forwardingViolation=true; see raw response and audit records.
- development/deterministic-only VEY-2E-X1-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-X1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-05: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G3-03: enforced=false, classification=null, forwardingViolation=true; Semantic inference is disabled; malformed model-output injection is not applicable in this mode..
- development/deterministic-only VEY-2E-G1-GEN-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-05: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-06: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-07: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-08: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-09: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-10: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-11: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-12: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-13: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-14: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-15: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/deterministic-only VEY-2E-G1-GEN-16: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-E2-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-E2-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-E2-05: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-E2-07: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-M2-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-M2-03: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-M2-05: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-M2-07: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-M3-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-M3-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-H1-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-H1-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-H1-05: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-H2-01: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-H2-03: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-H2-05: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-H3-01: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-H3-03: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-H3-05: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-H3-07: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-X1-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-X1-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-X2-01: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-X2-03: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-X2-05: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-X2-07: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-X3-05: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-G1-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-05: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G2-01: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-G2-03: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-G2-05: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- development/direct VEY-2E-G3-01: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-G3-03: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-G3-05: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-G3-07: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- development/direct VEY-2E-G1-GEN-01: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-03: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-05: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-06: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-07: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-08: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-09: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-10: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-11: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-12: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-13: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-14: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-15: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/direct VEY-2E-G1-GEN-16: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-M3-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-M3-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-H1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-H3-07: enforced=false, classification=allow, forwardingViolation=true; see raw response and audit records.
- development/mock-semantic VEY-2E-X1-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-X1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-05: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-01: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-03: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-05: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-06: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-07: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-08: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-09: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-10: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-11: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-12: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-13: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-14: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-15: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- development/mock-semantic VEY-2E-G1-GEN-16: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-M3-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-M3-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-H1-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-X1-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-X1-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-X3-06: enforced=false, classification=null, forwardingViolation=false; Gateway closes subscription upstream transport and has no persistent resource-update notification relay; delivery cannot be credited..
- holdout/deterministic-only VEY-2E-G1-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-G1-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/deterministic-only VEY-2E-G1-06: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-E2-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-E2-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-E2-06: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-E2-08: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-M2-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-M2-04: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-M2-06: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-M2-08: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-M3-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-M3-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-H1-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-H1-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-H2-02: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-H2-04: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-H2-06: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-H2-08: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-H3-02: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-H3-04: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-H3-06: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-H3-08: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X1-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-X1-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-X2-02: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X2-04: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X2-06: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X2-08: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X3-02: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X3-04: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X3-06: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-X3-08: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-G1-02: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-G1-04: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-G1-06: enforced=false, classification=null, forwardingViolation=false; see raw response and audit records.
- holdout/direct VEY-2E-G2-02: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-G2-04: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-G2-06: enforced=false, classification=null, forwardingViolation=true; see raw response and audit records.
- holdout/direct VEY-2E-G3-02: enforced=false, classification=null, forwardingViolation=true; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-G3-04: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-G3-06: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/direct VEY-2E-G3-08: enforced=false, classification=null, forwardingViolation=false; Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported..
- holdout/mock-semantic VEY-2E-M3-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-M3-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-X1-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-X1-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-X3-06: enforced=false, classification=null, forwardingViolation=false; Gateway closes subscription upstream transport and has no persistent resource-update notification relay; delivery cannot be credited..
- holdout/mock-semantic VEY-2E-G1-02: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-G1-04: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.
- holdout/mock-semantic VEY-2E-G1-06: enforced=false, classification=allow, forwardingViolation=false; see raw response and audit records.

## Limits

Zero actual paid calls, zero provider tokens, zero estimated offline cost. Mock token estimates are excluded. Direct MCP is a transport/control baseline; local authorization and operational probes are not comparable security products. No third-party gateway installed or executed. Real Muse and third-party comparisons remain unevaluated. No universal injection-prevention claim; confidence is not a calibrated probability.
