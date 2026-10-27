# Reserved manual Muse evaluation compatibility

No reserved live candidate was executed during Phase 2F. No credentials were requested or used, and no paid provider call was made. The six original input/label records and their manifest digest remain unchanged.

The existing `pnpm security:eval:live` entry point retains its explicit `--allow-paid`, bounded requests, token/cost reservations, exact provider endpoint/model, no-retry policy, usage capture and one-attempt marker. The original [safe manual instructions](../phase-2e/LIVE-META.md) still apply after separate founder authorization. Never enter a key into chat.

The runner now approves **only its own fixed local fixture metadata** using the same canonical `toolMetadataText` helper as the gateway. It also pins its fixed resource/prompt descriptors. It never approves the reserved response content. This prevents newly required discovery review from spending the response-only evaluation budget or tripping the synthetic-input guard. Schema-validation and hard-invariant checks remain active.

A genuine HTTP MCP compatibility test uses a wholly new Phase 2F input and a deterministic mock adapter, and asserts exactly one semantic inspection of that returned text, with no metadata inference. The schema-key-order failure found by this test is preserved in the evidence and fixed by canonical metadata construction. This verifies orchestration, not Meta availability or model quality. Real API behavior, classification accuracy and billing remain untested.

A later authorized six-case run is the first real-model exposure of those reserved candidates. Any later rerun of the Phase 2E offline holdout is only a previously-seen regression evaluation, never a first-look independent result. Phase 2F does not run that offline holdout either; existing integrity tests hash-check it without performing predictions.
