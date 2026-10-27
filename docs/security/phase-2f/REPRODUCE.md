# Reproducing Phase 2F evidence

Run in the repository on the local remediation branch. Evaluated code is commit `36fa675051f85437db55a5ccfff6ce18b7791392`; the final delivery commit only adds documentation/evidence. Dependencies must already be installed. These commands use local synthetic fixtures; no provider key is required.

```sh
cd /Users/nilambarbehera/Documents/Projects/veylith
git status --short
git rev-parse HEAD
pnpm format:check
pnpm lint
pnpm typecheck
pnpm build
pnpm test:all
META_AI_MODE=mock pnpm demo:client
pnpm security:eval:typecheck
pnpm security:remediation:typecheck
pnpm security:remediation:test
SECURITY_EVAL_OUTPUT=security-lab/phase-2f/after/development pnpm security:eval
VEYLITH_LIFECYCLE_CYCLES=1000 pnpm security:remediation:lifecycle
pnpm security:eval:reliability
```

The development evaluation preserves negative findings and exits successfully when the runner completes. Inspect its JSON and enforcement counts, not only its exit code. The lifecycle runner fails on observed response mismatches; its default is 100 cycles, with the extended run explicitly selecting 1,000. Allowed cycle counts are 20–2,000. It writes `security-lab/phase-2f/after/lifecycle.json`. The inherited reliability runner writes `security-lab/results/reliability.json`; it does not honor the development output environment variable. Do not overwrite the committed evidence when rerunning.

The full suite includes the repository's older holdout unit tests and the Phase 2E manifest-integrity test. Phase 2F does not invoke `security:eval:holdout`, predict the frozen Phase 2E inputs, or invoke reserved live candidates. Future offline holdout predictions are previously-seen regression results. Do not relabel inputs or claim independent first-look testing.

The new fixtures are the reproduction/protocol test files, `packages/policy-engine/tests/phase-2f-boundary.test.ts` and `apps/gateway/tests/local-boundary.test.ts`. Before logs show the same initial new assertions failing on the Phase 2E base. Inspect those compressed logs without changing branch state. The final protocol suite asserts actual HTTP/stdio advertised schemas and exact upstream arguments, invalid-argument nonforwarding, removed subscription advertisements/effects, modern stream rejection and manual-runner orchestration with wholly new text.

`security-lab/phase-2f/before/` preserves intermediate failures and fixture corrections as well as the baseline. `security-lab/phase-2f/evidence/` preserves source-identified final JSON and logs. SHA-256 digests for archive bytes and uncompressed payloads are in its provenance file. These are reproducibility digests, not signatures or external authenticity anchors.

No paid live command is part of this reproduction. The separately authorized manual procedure is in `LIVE-COMPATIBILITY.md`. No push, deployment or dashboard implementation belongs to this phase.
