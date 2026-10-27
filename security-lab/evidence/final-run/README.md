# Final offline evidence

- `REPORT.md`: generated per-mode, per-tier, per-scenario tables and retained failures.
- `summary.json`: readable metric aggregates.
- `reliability.json`: 15 reliability probes, including raw memory/throughput samples.
- `*.json.gz`: complete machine-readable raw results at the evaluated source commit, with client responses, audit events and upstream counters. Inspect with `gzip -dc PATH`.
- `gates.json` and `*.log.gz`: command exit codes and full verification logs.
- `PROVENANCE.json`: source commits, manifest digest and compressed-file hashes.

All six final evaluation runs recorded clean working trees at `43afac2`. The later live-runner bookkeeping and stdio test-wait changes do not alter gateway/policy/model behavior. Final quality gates pass at `7d8e7f1`. The initial evidence and failed verification attempts remain separately archived under `../initial-run/` and `../../baseline/`.

No actual provider call, provider token or provider cost is present in this evidence. Model mock invocation counts are separate. Reports do not claim real model accuracy or production protection.
