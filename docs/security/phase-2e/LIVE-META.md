# MANUAL ACTIONS REQUIRED FROM FOUNDER

No provider calls were authorized or made during offline work. Do not paste a key into this chat, source files, command arguments or `.env`. Use a dedicated restricted testing key and an independent provider-side spending limit. All transmitted content must remain the synthetic reserved text; no source code or private files are sent.

1. Review the frozen reserve and local runner, then explicitly authorize a live run separately. Confirm `muse-spark-1.3`, structured Responses API support, current pricing and account limits in [Meta's Responses API reference](https://dev.meta.ai/docs/api-reference/responses/create-response) and [pricing documentation](https://dev.meta.ai/docs/pricing-rate-limits). Checked for runner preparation on 2026-10-27; recheck before executing.
2. Build and run offline gates first. The runner does not install dependencies, retry or select replacement candidates.
3. In a private **zsh terminal**, disable shell tracing, enter current rates without a secret, then enter the key with hidden input. The placeholders below intentionally prevent accidental execution with unreviewed rates.

```sh
cd /Users/nilambarbehera/Documents/Projects/veylith
pnpm build
set +x
read "VEY_INPUT_RATE?Current standard input USD per million tokens: "
read "VEY_OUTPUT_RATE?Current output USD per million tokens: "
read "VEY_CACHED_RATE?Current cached input USD per million tokens: "
read -rs "META_MODEL_API_KEY?Paste the dedicated test key (hidden): "
printf '\n'
export META_MODEL_API_KEY
pnpm security:eval:live --allow-paid --max-requests=3 --max-total-tokens=16384 --max-cost-usd=0.05 --input-rate="$VEY_INPUT_RATE" --output-rate="$VEY_OUTPUT_RATE" --cached-rate="$VEY_CACHED_RATE"
unset META_MODEL_API_KEY VEY_INPUT_RATE VEY_OUTPUT_RATE VEY_CACHED_RATE
```

`--allow-paid` is a manual authorization gate, not proof of prior conversational approval. Stop before running it until approval is given. The key enters only the child process environment and HTTPS Authorization header; it is never deliberately logged. Use `unset` even if execution fails or is interrupted.

The runner caps six requests absolutely; the example permits at most three, 512 output tokens per request, at most 12,000 input characters and 16,384 conservatively reserved total tokens. Input reservations use UTF-8 byte length, not a provider tokenizer. Each request reserves its worst-case estimated cost before dispatch; reservations are not released during the run. Only `https://api.meta.ai/v1/responses` is allowed externally, with model `muse-spark-1.3`; alternate inherited endpoint/model settings are overridden. The model input must exactly match a reserved synthetic response. A clean heuristic route can produce **zero real calls** for a case; record that routing result instead of claiming the model evaluated it.

The first attempt creates `security-lab/live-results/attempt.json` before any paid call. Subsequent attempts refuse to reuse this reserve. Do not delete the marker to claim repeated cases are unseen. Prepare a new versioned reserve for another independent run. Requests are serial, with no automatic retries, even on timeouts or incomplete model output. Known provider usage is captured before classification parsing, including incomplete responses; unknown usage remains unknown. Request-attempt count, provider usage, conservative cost reservations, estimated known-usage cost and provider billing are distinct. Verify the provider's billing console independently; local estimates are not billing truth. No real model metrics exist until the founder completes this work.

Remaining work: authorize execution; enter a dedicated key locally; run once; review usage/billing and incomplete responses; score real classification separately from final gateway enforcement; investigate misses in a new development dataset, without relabeling this holdout. Do not deploy, publish or implement a dashboard as part of this step.
