# Reserved manual Muse evaluation compatibility

No reserved live candidate was executed during Phase 2F. No credentials were requested or used, and no paid provider call was made. The six original input/label records and their manifest digest remain unchanged.

The existing `pnpm security:eval:live` entry point retains its explicit `--allow-paid`, bounded requests, token/cost reservations, exact provider endpoint/model, no-retry policy, usage capture and one-attempt marker. The original [safe manual instructions](../phase-2e/LIVE-META.md) still apply after separate founder authorization. Never enter a key into chat.

The runner now approves **only its own fixed local fixture metadata** using the same canonical `toolMetadataText` helper as the gateway. It also pins its fixed resource/prompt descriptors. It never approves the reserved response content. This prevents newly required discovery review from spending the response-only evaluation budget or tripping the synthetic-input guard. Schema-validation and hard-invariant checks remain active.

A genuine HTTP MCP compatibility test uses a wholly new Phase 2F input and a deterministic mock adapter, and asserts exactly one semantic inspection of that returned text, with no metadata inference. The schema-key-order failure found by this test is preserved in the evidence and fixed by canonical metadata construction. This verifies orchestration, not Meta availability or model quality. Real API behavior, classification accuracy and billing remain untested.

A later authorized six-case run is the first real-model exposure of those reserved candidates. Any later rerun of the Phase 2E offline holdout is only a previously-seen regression evaluation, never a first-look independent result. Phase 2F does not run that offline holdout either; existing integrity tests hash-check it without performing predictions.

## MANUAL ACTIONS REQUIRED FROM FOUNDER

After separate live authorization, review current provider model/API support, rates and independent account spending limits as described in the original instructions. To permit all six cases in one attempt, use the following in a private **zsh terminal**. Do not execute this as part of offline development. The subshell limits the lifetime of the entered key, and the exit trap clears it even on interruption.

```sh
cd /Users/nilambarbehera/Documents/Projects/veylith
pnpm build
(
  set +x
  trap 'unset META_MODEL_API_KEY VEY_INPUT_RATE VEY_OUTPUT_RATE VEY_CACHED_RATE' EXIT
  read "VEY_INPUT_RATE?Current standard input USD per million tokens: "
  read "VEY_OUTPUT_RATE?Current output USD per million tokens: "
  read "VEY_CACHED_RATE?Current cached input USD per million tokens: "
  read -rs "META_MODEL_API_KEY?Paste the dedicated test key (hidden): "
  printf '\n'
  export META_MODEL_API_KEY
  pnpm security:eval:live --allow-paid --max-requests=6 --max-total-tokens=32768 --max-cost-usd=0.10 --input-rate="$VEY_INPUT_RATE" --output-rate="$VEY_OUTPUT_RATE" --cached-rate="$VEY_CACHED_RATE"
)
```

The run may stop before six actual calls because of a hard invariant, cumulative reservation, model failure or incomplete response. Preserve that outcome; never delete the attempt marker or retry the reserve to obtain a favorable result. Token reservations are conservative application estimates, not known provider usage, and `$0.10` is a local estimated-spending cap rather than provider billing enforcement. Record provider usage even for incomplete results, and verify billing separately. The exact allowed external endpoint is `https://api.meta.ai/v1/responses`, with model `muse-spark-1.3`; real availability has not been tested in Phase 2F. Never enter a key into chat, source, `.env` or a command argument.
