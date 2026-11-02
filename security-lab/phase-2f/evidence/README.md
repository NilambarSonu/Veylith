# Phase 2F final evidence

Source: `36fa675051f85437db55a5ccfff6ce18b7791392`; clean before measurement. See [final report](../../../docs/security/phase-2f/FINAL-REPORT.md).

252/252 unit/integration/protocol tests passed. All eight quality gates passed. Development comparisons retain 22/72 negative enforced outcomes in each gateway mode. The additional inherited reliability run passed 13/15 probes; its two failures are preserved. `lifecycle-1000.json.gz` contains 1,000 cleanup cycles and 20,000 calls; `lifecycle-100.json.gz` preserves the earlier short measurement at source `90e989a41a05b0b4d9e889adbf7122e0c96945af`. Positive heap growth remains unresolved.

The inherited report generator calls all binary enforced blocks detections; unknown-content quarantine must be interpreted using routing traces as explained in the final report. Mock classifications are not real model detection evidence. No frozen holdout prediction, reserved live case or paid request was run. Original evidence is unchanged.

Archive byte hashes and uncompressed content hashes are in `PROVENANCE.json`. `.gz` payloads are ordinary UTF-8 JSON or logs and can be inspected with `gzip -cd`. `development-comparison.json` includes before and after results separately, with per-scenario/tier matrices and source revisions. No evidence digest is a signature or external anchor.
