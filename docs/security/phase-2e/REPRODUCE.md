# Reproducing the local lab

Use Node >=20, the repository's installed pnpm dependencies, and the committed source revision recorded in each result. No new third-party gateway is installed. Ports are assigned by the OS and bound to loopback. Offline subprocess environments omit provider keys and force disabled/mock mode; a fetch guard rejects non-loopback destinations. Payload strings are never evaluated as programs.

```sh
pnpm security:eval
pnpm security:eval:holdout
pnpm security:eval:report
pnpm security:eval:reliability
pnpm security:eval:typecheck
```

The first command runs direct MCP, deterministic-only Veylith and mock-semantic Veylith on development cases. The second does the same for the sealed holdout. Raw JSON contains original client responses, upstream methods/calls and audit records. Each case is also journaled as JSONL immediately, so a later process failure does not erase prior observations. Markdown and JSON aggregates live in `security-lab/results/`. `SECURITY_EVAL_OUTPUT` selects an alternate output directory. `--strict` fails on negative enforcement observations; default execution completes and reports negatives as data, without pretending they passed. A runner crash always fails execution.

Detection comes from block decisions recorded by the real gateway. Operational failures are excluded from classification matrices. Transport errors alone do not count as detections. Enforcement separately checks client delivery and actual upstream counters. Read-time interception necessarily happens after the read was forwarded; such reads are not automatically forwarding violations. Privileged/preflight actions must not reach upstream. Direct MCP has no policy audit classifier; its payload/control outcomes are useful, but gateway-specific session and failure probes are explicitly non-comparable. Invalid JSON, overload, unavailable methods and classifier outages must not be presented as successful attack classification.

## Reproduction recipes

- Stale discovery: X2 primes `tools/list`, mutates a synthetic definition within the 2,000 ms TTL, then calls the same tool. The race variant changes the definition at the tools/list response barrier. No random sleeps decide mutation ordering. An arbitrary server can still change behavior after the final check; MCP does not atomically version tool execution.
- Unicode: M3 returns fullwidth/invisible-character overrides and legitimate international text. Inspect the raw returned content and audit decision together.
- Fragmentation: X1 splits imperatives between resource items, prompt messages or sequential reads. The label refers to the combined instruction; individual fragments do not have to match a keyword.
- Stolen identity: H3 supplies a valid synthetic session with the matching forged header. An allow is recorded as a negative finding, because the label is not proof of identity.
- Trust chain: G2 always follows the resource read with `privileged_sink`; only a zero privileged forwarding count proves blocking. A resource false negative may coexist with successful final enforcement.
- HTTP crash baseline: `security-lab/baseline/development-before-fixes.txt` preserves the partial development run ending in uncaught ECONNRESET. Reliability probes reproduce truncated uploads safely and confirm the process remains available.
- Audit failure: reliability uses a temporary directory, replaces local `writeSync` with a nine-byte write followed by synthetic ENOSPC, restores it, and verifies sticky quarantine. No disk is filled. A child fixture acknowledges an fsync'ed record and is abruptly terminated; restart must retain it.

## Audit recovery

A torn final JSONL record fails startup. Preserve the original log as evidence. Verify an intact prefix against an independently retained checkpoint, then restore a separately reviewed log; the lab does not automatically truncate or rewrite the damaged evidence. A crash inside the append critical section can leave `.append.lock`; remove it manually only after confirming no writer is alive and verifying the log. Stale writers fail closed and must reload. Suffix truncation to a valid prefix after restart cannot be detected without an external anchor. Hash chaining is not a signature and cannot prevent full-chain regeneration by an attacker with filesystem access.

## Limits

Results are from one local machine and synthetic fixtures; they do not establish production detection accuracy, safety on arbitrary tools, a long-term leak rate, authenticated identity, durable subscription delivery or prevention of all prompt injection. Cancellation recovery tests do not prove downstream computation is cancelled. Heap samples and short throughput runs are diagnostics. In-memory audit history still grows with accumulated records and needs retention design before production use.
