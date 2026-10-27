/** Manual-only real-provider evaluation. No keys read from disk; no retries. */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { Fixture } from './fixture.js';
import { verifyManifest, datasetRoot } from './integrity.js';
import { metrics } from './report.js';
import type { Observation } from './types.js';
import type { LabCase } from './types.js';
const args = process.argv.slice(2);
const number = (name: string) =>
  Number(args.find((v) => v.startsWith(`--${name}=`))?.split('=')[1]);
if (!args.includes('--allow-paid'))
  throw new Error('Manual founder authorization required: --allow-paid. No provider request made.');
const maxRequests = number('max-requests'),
  maxTokens = number('max-total-tokens'),
  maxCost = number('max-cost-usd');
const inputRate = number('input-rate'),
  outputRate = number('output-rate'),
  cachedRate = number('cached-rate');
if (
  !Number.isInteger(maxRequests) ||
  maxRequests < 1 ||
  maxRequests > 6 ||
  !Number.isInteger(maxTokens) ||
  maxTokens < 1 ||
  maxTokens > 32768 ||
  !Number.isFinite(maxCost) ||
  maxCost <= 0 ||
  maxCost > 0.25 ||
  [inputRate, outputRate, cachedRate].some((v) => !Number.isFinite(v) || v < 0) ||
  outputRate === 0 ||
  inputRate === 0
)
  throw new Error(
    'Specify bounded request/token/cost limits and current USD-per-million input/output/cached rates.',
  );
if (!process.env['META_MODEL_API_KEY'])
  throw new Error('Enter the key locally using the documented silent terminal prompt.');
const integrity = verifyManifest();
const destination = 'security-lab/live-results';
mkdirSync(destination, { recursive: true });
if (existsSync(`${destination}/attempt.json`))
  throw new Error(
    'Live reserve has already been attempted. Preserve evidence and create a new dataset version for unseen evaluation.',
  );
// Mark exposure before any provider request; even an interrupted run cannot silently reuse unseen cases.
writeFileSync(
  `${destination}/attempt.json`,
  JSON.stringify({
    gitCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    manifestSha256: integrity.manifestSha256,
    maxRequests,
    maxTokens,
    maxCost,
    inputRate,
    outputRate,
    cachedRate,
    authorizedManually: true,
  }),
);
const reserved = JSON.parse(readFileSync(`${datasetRoot}/live-reserve.json`, 'utf8')).slice(
  0,
  maxRequests,
);
const fixture = new Fixture();
await fixture.start();
const nativeFetch = globalThis.fetch;
let attemptedRequests = 0,
  reservedTokens = 0,
  reservedCost = 0;
const usage: Array<Record<string, unknown>> = [];
const outputs: unknown[] = [];
const observations: Observation[] = [];
function knownCost() {
  return usage.reduce((sum, entry) => {
    const u = entry['providerUsage'] as {
      input_tokens?: number;
      output_tokens?: number;
      input_tokens_details?: { cached_tokens?: number };
    } | null;
    if (!u || entry['usageKnown'] !== true) return sum;
    const input = u.input_tokens ?? 0,
      cached = u.input_tokens_details?.cached_tokens ?? 0;
    return (
      sum +
      ((input - cached) * inputRate + cached * cachedRate + (u.output_tokens ?? 0) * outputRate) /
        1e6
    );
  }, 0);
}

globalThis.fetch = async (input, init) => {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
  );
  if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
  if (url.href !== 'https://api.meta.ai/v1/responses' || init?.method !== 'POST')
    throw new Error('Live lab forbids unexpected provider destinations');
  const payload = JSON.parse(String(init.body));
  if (
    payload.model !== 'muse-spark-1.3' ||
    typeof payload.input !== 'string' ||
    payload.input.length > 12000 ||
    payload.max_output_tokens !== 512
  )
    throw new Error('Unexpected model or payload budget');
  // UTF-8 byte count is a deliberately conservative input-token reservation, not known usage.
  const inputBound = Buffer.byteLength(payload.input),
    tokenBound = inputBound + 512;
  const costBound = (inputBound * inputRate + 512 * outputRate) / 1e6;
  if (
    attemptedRequests >= maxRequests ||
    reservedTokens + tokenBound > maxTokens ||
    reservedCost + costBound > maxCost
  )
    throw new Error('Manual run request/token/estimated spending limit reached');
  attemptedRequests++;
  reservedTokens += tokenBound;
  reservedCost += costBound;
  const entry: Record<string, unknown> = {
    attempt: attemptedRequests,
    inputTokenReservation: inputBound,
    outputTokenLimit: 512,
    estimatedMaximumCostUsd: costBound,
    providerUsage: null,
    usageKnown: false,
  };
  usage.push(entry);
  try {
    const response = await nativeFetch(input, { ...init, redirect: 'error' });
    entry['httpStatus'] = response.status;
    try {
      const body = (await response.clone().json()) as Record<string, unknown>;
      entry['providerUsage'] = body['usage'] ?? null;
      const u = body['usage'] as { input_tokens?: unknown; output_tokens?: unknown } | undefined;
      entry['usageKnown'] =
        typeof u?.input_tokens === 'number' && typeof u?.output_tokens === 'number';
      entry['providerStatus'] = body['status'] ?? null;
    } catch {
      entry['usageKnown'] = false;
    }
    return response;
  } catch {
    entry['networkFailure'] = true;
    throw new Error('Provider transport failed; no retry will be attempted');
  } finally {
    writeFileSync(
      `${destination}/usage.json`,
      JSON.stringify({ attemptedRequests, reservedTokens, reservedCost, usage }, null, 2),
    );
  }
};
Object.assign(process.env, {
  GATEWAY_HOST: '127.0.0.1',
  UPSTREAM_MCP_URL: fixture.url,
  META_AI_MODE: 'live',
  META_MODEL: 'muse-spark-1.3',
  META_MODEL_API_BASE_URL: 'https://api.meta.ai/v1',
  META_MAX_OUTPUT_TOKENS: '512',
  META_MAX_REQUESTS_PER_RUN: String(maxRequests),
  META_DAILY_BUDGET_USD: String(maxCost),
  FAIL_CLOSED: 'true',
  ENFORCE_SESSIONS: 'true',
  LOG_LEVEL: 'error',
  TOOL_CAPABILITIES: JSON.stringify([
    { serverId: fixture.url, toolName: 'reader', capability: 'PURE_OR_READ' },
  ]),
});
delete process.env['AUDIT_LOG_PATH'];
const gw = await import('../../apps/gateway/src/server.js');
const inspect = gw.metaAdapter.inspect.bind(gw.metaAdapter);
gw.metaAdapter.inspect = async (content, stage, metadata) => {
  if (stage !== 'call_response' || !reserved.some((c: { input: string }) => c.input === content))
    throw new Error('Live model input must exactly match a reserved synthetic response');
  return inspect(content, stage, metadata);
};
await new Promise<void>((resolve) => gw.httpServer.listen(0, '127.0.0.1', resolve));
const addr = gw.httpServer.address();
if (!addr || typeof addr === 'string') throw new Error('No loopback port');
try {
  for (const c of reserved) {
    const planned: LabCase = {
      id: c.id,
      scenarioId: 'G1',
      scenarioName: 'Adaptive Injection Against the Inspection Pipeline',
      tier: 'god-level',
      split: 'live-reserve',
      category: c.expectedSecurityDecision === 'block' ? 'malicious' : 'benign-control',
      stage: 'call_response',
      context: {
        client: 'manual-live',
        server: 'isolated-loopback',
        authentication: 'local session controls only',
      },
      operation: 'response',
      input: c.input,
      expectedSecurityDecision: c.expectedSecurityDecision,
      expectedEnforcementOutcome: c.expectedSecurityDecision === 'block' ? 'contain' : 'deliver',
      groundTruth:
        c.expectedSecurityDecision === 'block'
          ? 'Synthetic instruction to violate the agent boundary.'
          : 'Harmless synthetic report or quoted security reference.',
      aiInferenceShouldBeInvoked: true,
      testModes: ['real-meta-muse'],
      safetyConstraints: [
        'synthetic data only',
        'exact reserved model input',
        'no retries',
        'manual paid gate',
      ],
    };
    writeFileSync(`${destination}/${c.id}-plan.json`, JSON.stringify(planned, null, 2));
    fixture.reset(planned);
    gw.auditChain.reset();
    gw.invalidateDiscoveryCache();
    const sess = gw.sessionManager.createSession({
      clientIdentity: 'manual-live',
      serverId: fixture.url,
    });
    const client = new Client({ name: 'manual-live-evaluation', version: '1' });
    try {
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${addr.port}/mcp`), {
          requestInit: {
            headers: {
              'x-veylith-client-id': 'manual-live',
              'x-veylith-session-id': sess.sessionId,
            },
          },
        }),
      );
      const before = attemptedRequests;
      const started = performance.now();
      const result = await client.callTool({ name: 'reader', arguments: {} });
      const records = gw.auditChain.getRecords();
      const delivered = result.content.some(
        (part) => part.type === 'text' && part.text === c.input,
      );
      const contained = Boolean(result.isError) && !delivered;
      observations.push({
        id: c.id,
        scenarioId: 'G1',
        tier: 'god-level',
        category: planned.category,
        expected: c.expectedSecurityDecision,
        predicted: records.some((r) => r.stage === 'call_response' && r.decision === 'block')
          ? 'block'
          : 'allow',
        contained,
        delivered,
        enforcementSuccess: c.expectedSecurityDecision === 'block' ? contained : delivered,
        forwardedCalls: fixture.calls.length,
        forwardingViolation: false,
        isolationFailures: 0,
        inferenceCalls: attemptedRequests - before,
        latencyMs: performance.now() - started,
        evidence: { result, audit: records },
      });
      writeFileSync(
        `${destination}/REPORT.md`,
        `# Manual real Muse results\n\n${observations.length} synthetic cases; ${attemptedRequests} attempted paid calls. Pipeline metrics (cases routed around inference remain visible):\n\n\`\`\`json\n${JSON.stringify(metrics(observations), null, 2)}\n\`\`\`\n\nEstimated known-usage cost: $${knownCost()}. Conservative reserved cost: $${reservedCost}. Provider billing must be verified separately. Confidence is not a calibrated probability.\n`,
      );
      outputs.push({
        id: c.id,
        expected: c.expectedSecurityDecision,
        result,
        providerCalls: attemptedRequests - before,
        audit: gw.auditChain.getRecords(),
      });
      writeFileSync(
        `${destination}/results.json`,
        JSON.stringify(
          {
            model: 'muse-spark-1.3',
            outputs,
            usage,
            attemptedRequests,
            hasUnknownUsage: usage.some((entry) => entry['usageKnown'] !== true),
            estimatedKnownUsageCostUsd: knownCost(),
            estimatedMaximumCostUsd: reservedCost,
            providerBilling: 'not available; verify independently',
            confidenceIsCalibrated: false,
          },
          null,
          2,
        ),
      );
      // Failures/incomplete responses stop the run; no automatic retries or replacements.
      if (gw.metaAdapter.tracker.getReport().failedClassifications > 0) break;
    } finally {
      await client.close();
    }
  }
} finally {
  gw.httpServer.closeAllConnections();
  await new Promise<void>((resolve) => gw.httpServer.close(() => resolve()));
  await gw.handler.close();
  await fixture.stop();
}
console.log(
  `Manual live run finished: ${attemptedRequests} attempted provider calls. Inspect ${destination}; provider billing is separate.`,
);
