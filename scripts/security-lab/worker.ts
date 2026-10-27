import { readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import * as os from 'node:os';
import { request } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { Fixture } from './fixture.js';
import { verifyManifest, datasetRoot } from './integrity.js';
import type { LabCase, Observation } from './types.js';

const [mode = 'deterministic-only', split = 'development', destination = 'security-lab/results'] =
  process.argv.slice(2);
if (!['deterministic-only', 'mock-semantic', 'direct'].includes(mode))
  throw new Error('Offline worker rejects live mode');
const integrity = verifyManifest();
const cases: LabCase[] = JSON.parse(readFileSync(`${datasetRoot}/${split}.json`, 'utf8'));
if (split === 'development')
  cases.push(...JSON.parse(readFileSync(`${datasetRoot}/development-generated.json`, 'utf8')));
mkdirSync(destination, { recursive: true });
writeFileSync(`${destination}/${split}-${mode}.progress.jsonl`, '');
const nativeFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
  );
  if (!['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname))
    throw new Error('Offline lab forbids external fetch');
  return nativeFetch(input, init);
};
const fixture = new Fixture();
await fixture.start();
Object.assign(process.env, {
  GATEWAY_HOST: '127.0.0.1',
  GATEWAY_PORT: '17879',
  UPSTREAM_MCP_URL: fixture.url,
  META_AI_MODE: mode === 'mock-semantic' ? 'mock' : 'disabled',
  ENFORCE_SESSIONS: 'true',
  FAIL_CLOSED: 'true',
  LOG_LEVEL: 'error',
  MAX_REQUEST_BODY_BYTES: '8192',
  MAX_RESOURCE_BYTES: '4096',
  MAX_CONCURRENT_REQUESTS: '8',
  DISCOVERY_CACHE_TTL_MS: '2000',
  CIRCUIT_BREAKER_FAILURE_THRESHOLD: '2',
  CIRCUIT_BREAKER_RESET_TIMEOUT_MS: '20',
  TOOL_CAPABILITIES: JSON.stringify([
    { serverId: fixture.url, toolName: 'reader', capability: 'PURE_OR_READ' },
    { serverId: 'http://127.0.0.1:1/mcp', toolName: 'unknown', capability: 'PURE_OR_READ' },
  ]),
  BLOCKED_TOOLS: 'restricted_demo_tool,privileged_sink',
});
delete process.env['META_MODEL_API_KEY'];
delete process.env['META_API_KEY'];
delete process.env['AUDIT_LOG_PATH'];
const gw = await import('../../apps/gateway/src/server.js');
await new Promise<void>((resolve) => gw.httpServer.listen(0, '127.0.0.1', resolve));
const address = gw.httpServer.address();
if (!address || typeof address === 'string') throw new Error('No gateway port');
const gatewayUrl = `http://127.0.0.1:${address.port}/mcp`;
const observations: Observation[] = [];
const heldRequests: ReturnType<typeof request>[] = [];
let inferenceCalls = 0;
let modelFailure = false;
const originalInspect = gw.metaAdapter.inspect.bind(gw.metaAdapter);
gw.metaAdapter.inspect = async (...args) => {
  if (mode === 'mock-semantic') inferenceCalls++;
  if (modelFailure && mode === 'mock-semantic')
    return {
      flagged: true,
      action: 'review',
      threatCategory: 'none',
      confidence: 0,
      explanation: 'Synthetic malformed model output / outage',
      evidence: [],
      durationMs: 0,
      mode: 'mock',
      model: gw.metaAdapter.model,
    };
  return originalInspect(...args);
};
function session(overrides: Record<string, unknown> = {}) {
  return gw.sessionManager.createSession({
    clientIdentity: 'alice',
    serverId: fixture.url,
    permittedTools: '*',
    permittedResources: '*',
    permittedPrompts: '*',
    ...overrides,
  });
}
async function connect(headers: Record<string, string> = {}) {
  const client = new Client({ name: 'synthetic-lab-client', version: '1' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(mode === 'direct' ? fixture.url : gatewayUrl), {
      requestInit: { headers },
    }),
  );
  return client;
}
function texts(value: unknown): string[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(texts);
  const record = value as Record<string, unknown>;
  return Object.entries(record).flatMap(([k, v]) =>
    k === 'text' && typeof v === 'string' ? [v] : texts(v),
  );
}
let admissionHeaders: Record<string, string> = {};
async function raw(body: string) {
  const res = await fetch(mode === 'direct' ? fixture.url : gatewayUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...admissionHeaders },
    body,
  });
  return { status: res.status, body: await res.text() };
}
async function cancelProbe(headers: Record<string, string>) {
  fixture.hold();
  let entered!: () => void;
  const reached = new Promise<void>((resolve) => {
    entered = resolve;
  });
  // Wait on an observed upstream tool call, without timing assumptions.
  const prior = fixture.calls.length;
  const client = await connect(headers);
  const controller = new AbortController();
  const pending = client
    .callTool(
      { name: 'reader', arguments: { marker: 'cancel-marker' } },
      { signal: controller.signal },
    )
    .catch((e) => ({ error: String(e) }));
  const poll = setInterval(() => {
    if (fixture.calls.length > prior) {
      clearInterval(poll);
      entered();
    }
  }, 1);
  const timeout = setTimeout(() => {
    clearInterval(poll);
    entered();
  }, 2000);
  await reached;
  clearTimeout(timeout);
  controller.abort();
  fixture.release?.();
  fixture.held = undefined;
  const result = await pending;
  await client.close();
  return result;
}
const cycleHeap: number[] = [];
const started = performance.now();
try {
  for (const [index, c] of cases.entries()) {
    fixture.reset(c);
    gw.invalidateDiscoveryCache();
    gw.securityEngine.capabilityRegistry.reset();
    gw.sessionManager.reset();
    gw.auditChain.reset();
    gw.securityEngine.capabilityRegistry.bindCapability(fixture.url, 'reader', 'PURE_OR_READ');
    gw.securityEngine.capabilityRegistry.bindCapability(
      'http://127.0.0.1:1/mcp',
      'unknown',
      'PURE_OR_READ',
    );
    // Let an earlier open breaker probe recover using a valid connection.
    await new Promise((resolve) => setTimeout(resolve, 25));
    const sess = session();
    let headers: Record<string, string> = {
      'x-veylith-client-id': 'alice',
      'x-veylith-session-id': sess.sessionId,
    };
    let client: Client | undefined;
    let evidence: unknown;
    let predicted: Observation['predicted'] = null;
    let contained = false,
      delivered = false,
      isolationFailures = 0;
    let unsupported: string | undefined, error: string | undefined;
    const inferStart = inferenceCalls;
    const t0 = performance.now();
    admissionHeaders = headers;
    const originalAppend = gw.auditChain.append.bind(gw.auditChain);
    try {
      switch (c.operation) {
        case 'invalid-session':
          headers['x-veylith-session-id'] = 'vyl-sess-synthetic-invalid';
          break;
        case 'wrong-client':
          headers['x-veylith-client-id'] = 'bob';
          break;
        case 'wrong-server':
          headers['x-veylith-session-id'] = session({
            serverId: 'http://127.0.0.1:1/mcp',
          }).sessionId;
          break;
        case 'denied-resource':
        case 'subscribe-denied':
          headers['x-veylith-session-id'] = session({ permittedResources: [] }).sessionId;
          break;
        case 'missing-session':
          headers = { 'x-veylith-client-id': 'alice' };
          break;
        case 'expired':
          headers['x-veylith-session-id'] = session({ ttlMs: -1 }).sessionId;
          break;
      }
      if (c.operation === 'oversize') {
        evidence = await raw('X'.repeat(8193));
        contained = (evidence as { status: number }).status === 413;
      } else if (c.operation === 'backpressure') {
        const pending = Array.from(
          { length: 8 },
          () =>
            new Promise<number>((resolve, reject) => {
              const r = request(
                gatewayUrl,
                {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': '100',
                    ...headers,
                  },
                },
                (res) => {
                  res.resume();
                  resolve(res.statusCode ?? 0);
                },
              );
              r.on('error', reject);
              r.write('{');
              // Store cleanup, after admission is tested.
              heldRequests.push(r);
            }),
        );
        await new Promise((resolve) => setTimeout(resolve, 30));
        evidence = await raw('{}');
        contained = (evidence as { status: number }).status === 429;
        for (const r of heldRequests.splice(0)) r.destroy();
        await Promise.allSettled(pending);
      } else if (c.operation === 'cancel') {
        evidence = await cancelProbe(headers);
        client = await connect(headers);
        const recovered = await client.callTool({
          name: 'reader',
          arguments: { marker: 'recovered' },
        });
        delivered = texts(recovered).join('') === 'recovered';
      } else {
        client = await connect(headers);
        const inputParts = Array.isArray(c.input) ? c.input : [c.input];
        const call = (name = 'reader', args: Record<string, unknown> = {}) =>
          client!.callTool({ name, arguments: args });
        switch (c.operation) {
          case 'metadata':
          case 'schema': {
            const r = await client.listTools();
            evidence = r;
            delivered = r.tools.some((t) => t.name === 'reader');
            contained = !delivered;
            break;
          }
          case 'tools':
            evidence = await client.listTools();
            delivered = (evidence as { tools: unknown[] }).tools.length > 0;
            break;
          case 'resources':
            evidence = await client.listResources();
            delivered = true;
            break;
          case 'templates':
            evidence = await client.listResourceTemplates();
            delivered = true;
            break;
          case 'prompts':
            evidence = await client.listPrompts();
            delivered = true;
            break;
          case 'add':
            evidence = await call('add', { a: 17, b: 25 });
            delivered = texts(evidence).join('') === '42';
            break;
          case 'mutation':
          case 'approved':
          case 'race':
          case 'stable': {
            await client.listTools();
            if (c.operation !== 'stable') fixture.mutate(String(c.input));
            if (c.operation === 'approved')
              gw.securityEngine.capabilityRegistry.approveToolUpdate(
                fixture.url,
                fixture.definitions[0]!,
              );
            if (c.operation === 'race') {
              fixture.definitions[0]!.description = 'Local fixture utility';
              fixture.barrier = () => fixture.mutate(String(c.input));
            }
            evidence = await call();
            contained = fixture.calls.length === 0;
            delivered = !contained && texts(evidence).join('') === inputParts.join('');
            break;
          }
          case 'resource':
          case 'fragments-resource':
          case 'sequential':
          case 'binary':
          case 'resource-limit':
          case 'denied-resource': {
            const r = await client.readResource({ uri: 'lab://document' });
            evidence =
              c.operation === 'sequential'
                ? [r, await client.readResource({ uri: 'lab://document' })]
                : r;
            delivered = texts(evidence).join('') === inputParts.join('');
            contained = !delivered;
            break;
          }
          case 'prompt':
          case 'fragments-prompt':
            evidence = await client.getPrompt({ name: 'summary' });
            delivered = texts(evidence).join('') === inputParts.join('');
            contained = !delivered;
            break;
          case 'subscribe-denied':
            evidence = await client.subscribeResource({ uri: 'lab://document' });
            contained = !fixture.calls.includes('resources/subscribe');
            break;
          case 'notifications': {
            await client.subscribeResource({ uri: 'lab://document' });
            evidence = { subscriptionForwarded: fixture.calls.includes('resources/subscribe') };
            unsupported =
              'Gateway closes subscription upstream transport and has no persistent resource-update notification relay; delivery cannot be credited.';
            break;
          }
          case 'reconnect': {
            const replies: unknown[] = [];
            for (let i = 0; i < 2; i++) {
              const other = await connect(headers);
              try {
                const marker = `${c.id}-reconnected-${i}`;
                const result = await other.callTool({ name: 'reader', arguments: { marker } });
                if (texts(result).join('') !== marker) isolationFailures++;
                replies.push(result);
              } finally {
                await other.close();
              }
            }
            evidence = replies;
            delivered = isolationFailures === 0;
            break;
          }
          case 'concurrent': {
            const clients: Client[] = [];
            try {
              evidence = await Promise.all(
                Array.from({ length: 6 }, async (_, i) => {
                  const s = session({ clientIdentity: `client-${i}` });
                  const other = await connect({
                    'x-veylith-client-id': `client-${i}`,
                    'x-veylith-session-id': s.sessionId,
                  });
                  clients.push(other);
                  const marker = `${c.id}-private-marker-${i}`;
                  const r = await other.callTool({ name: 'reader', arguments: { marker } });
                  if (texts(r).join('') !== marker) isolationFailures++;
                  return r;
                }),
              );
              delivered = isolationFailures === 0;
            } finally {
              await Promise.all(clients.map((c) => c.close()));
            }
            break;
          }
          case 'permissions': {
            const denied = session({
              clientIdentity: 'bob',
              permittedTools: [],
              permittedResources: [],
              permittedPrompts: [],
            });
            const other = await connect({
              'x-veylith-client-id': 'bob',
              'x-veylith-session-id': denied.sessionId,
            });
            try {
              evidence = await other.callTool({
                name: 'reader',
                arguments: { marker: 'denied-marker' },
              });
            } finally {
              await other.close();
            }
            contained = !fixture.calls.includes('reader');
            break;
          }
          case 'chain': {
            const retrieved = await client.readResource({ uri: 'lab://document' });
            // Fixed agent simulator always tries the forbidden follow-up, independent of detection.
            const followup = await call('privileged_sink', {
              syntheticToken: 'DEMO_ONLY',
              destination: 'local://sink',
            });
            evidence = { retrieved, followup };
            contained = !fixture.calls.includes('privileged_sink');
            predicted = gw.auditChain
              .getRecords()
              .some((r) => r.stage === 'resource_content' && r.decision === 'block')
              ? 'block'
              : 'allow';
            break;
          }
          case 'outage':
          case 'cascade': {
            fixture.outage = true;
            const failed = await call().catch((e) => ({ error: String(e) }));
            const secondFailure = await call().catch((e) => ({ error: String(e) }));
            const openState = gw.upstreamCircuitBreaker.getState();
            fixture.outage = false;
            await new Promise((resolve) => setTimeout(resolve, 30));
            const recovery = await call('reader', { marker: 'recovery-ok' });
            evidence = {
              failed,
              secondFailure,
              openState,
              recovery,
              recoveredState: gw.upstreamCircuitBreaker.getState(),
            };
            contained = fixture.calls.length === 1 && texts(recovery).join('') === 'recovery-ok';
            if (c.operation === 'cascade') {
              await cancelProbe(headers);
              const expired = session({ ttlMs: -1 });
              const expiredClient = await connect({
                'x-veylith-client-id': 'alice',
                'x-veylith-session-id': expired.sessionId,
              }).catch((e) => ({ error: String(e) }));
              if (expiredClient instanceof Client) {
                try {
                  const r = await expiredClient.callTool({ name: 'reader' });
                  contained = contained && Boolean(r.isError);
                } finally {
                  await expiredClient.close();
                }
              }
            }
            break;
          }
          case 'audit-failure':
            gw.auditChain.append = () => {
              throw Object.assign(new Error('Synthetic ENOSPC'), { code: 'ENOSPC' });
            };
            evidence = await call('unknown', { command: 'rm -rf /synthetic-only' });
            contained = fixture.calls.length === 0;
            break;
          case 'model-failure':
            modelFailure = true;
            evidence = await call('unknown', { message: 'bypass credentials instruction' });
            contained = fixture.calls.length === 0;
            break;
          default: {
            const tool = ['unknown', 'annotation', 'wrong-binding'].includes(c.operation)
              ? 'unknown'
              : c.operation === 'restricted'
                ? 'restricted_demo_tool'
                : c.operation === 'missing-tool'
                  ? 'impersonated_trusted_tool'
                  : 'reader';
            const args = ['unknown', 'annotation', 'wrong-binding'].includes(c.operation)
              ? { command: c.input }
              : c.operation === 'call'
                ? { query: c.input }
                : {};
            evidence = await call(tool, args);
            delivered = texts(evidence).join('') === inputParts.join('');
            contained = Boolean((evidence as { isError?: boolean }).isError) || !delivered;
            break;
          }
        }
      }
    } catch (e) {
      error = String(e);
      evidence = { error };
      // A transport error is containment evidence only if no forbidden call reached upstream.
      contained =
        c.category === 'operational-failure' && c.operation !== 'audit-failure'
          ? false
          : fixture.calls.length === 0;
    } finally {
      modelFailure = false;
      gw.auditChain.append = originalAppend;
      await client?.close().catch(() => {});
    }
    if (
      mode === 'direct' &&
      (c.category === 'operational-failure' ||
        [
          'mutation',
          'race',
          'approved',
          'stable',
          'wrong-client',
          'wrong-server',
          'invalid-session',
          'stolen-label',
          'missing-session',
          'session-ok',
          'expired',
          'permissions',
          'denied-resource',
          'subscribe-denied',
        ].includes(c.operation))
    )
      unsupported =
        'Direct MCP has no Veylith policy/session/fault context; this comparison is unsupported.';
    if (mode === 'deterministic-only' && c.operation === 'model-failure')
      unsupported =
        'Semantic inference is disabled; malformed model-output injection is not applicable in this mode.';
    const records = gw.auditChain.getRecords();
    if (predicted === null && c.category !== 'operational-failure' && mode !== 'direct')
      predicted = records.some((r) => r.decision === 'block') ? 'block' : 'allow';
    if (mode === 'direct') predicted = null;
    const preflight =
      ['call_arguments', 'discovery'].includes(c.stage) ||
      [
        'chain',
        'permissions',
        'subscribe-denied',
        'missing-session',
        'expired',
        'wrong-client',
        'wrong-server',
        'invalid-session',
        'denied-resource',
      ].includes(c.operation);
    // Outage/cascade explicitly include authorized recovery and cancellation calls.
    // Their operation driver verifies the failed phase and recovery separately.
    const forbiddenCalls = fixture.calls.filter((name) =>
      c.operation === 'chain'
        ? name === 'privileged_sink'
        : preflight && !['outage', 'cascade'].includes(c.operation),
    );
    const forwardingViolation = c.expectedSecurityDecision === 'block' && forbiddenCalls.length > 0;
    if (
      mode !== 'direct' &&
      [
        'stolen-label',
        'wrong-client',
        'wrong-server',
        'permissions',
        'denied-resource',
        'expired',
        'missing-session',
        'invalid-session',
      ].includes(c.operation) &&
      c.expectedSecurityDecision === 'block' &&
      fixture.calls.length > 0
    )
      isolationFailures++;
    const o: Observation = {
      id: c.id,
      scenarioId: c.scenarioId,
      tier: c.tier,
      category: c.category,
      expected: c.expectedSecurityDecision,
      predicted,
      contained,
      delivered,
      enforcementSuccess:
        !unsupported && (c.expectedEnforcementOutcome === 'contain' ? contained : delivered),
      forwardedCalls: fixture.calls.length,
      forwardingViolation,
      isolationFailures,
      inferenceCalls: inferenceCalls - inferStart,
      latencyMs: performance.now() - t0,
      unsupported,
      error,
      evidence: {
        response: evidence,
        normativeInferenceExpected: c.aiInferenceShouldBeInvoked,
        inferenceActuallyInvoked: inferenceCalls > inferStart,
        upstreamCalls: fixture.calls,
        upstreamMethods: fixture.methods,
        audit: records,
      },
    };
    observations.push(o);
    appendFileSync(`${destination}/${split}-${mode}.progress.jsonl`, JSON.stringify(o) + '\n');
    if ((index + 1) % 8 === 0) {
      global.gc?.();
      cycleHeap.push(process.memoryUsage().heapUsed);
    }
    console.log(
      `${mode} ${c.id} detection=${predicted} enforcement=${o.enforcementSuccess} ${unsupported ? 'UNSUPPORTED' : ''}`,
    );
  }
} finally {
  gw.httpServer.closeAllConnections();
  await new Promise<void>((resolve) => gw.httpServer.close(() => resolve()));
  await gw.handler.close();
  await fixture.stop();
}
const totalMs = performance.now() - started;
mkdirSync(destination, { recursive: true });
writeFileSync(
  `${destination}/${split}-${mode}.json`,
  JSON.stringify(
    {
      version: '2e-v1',
      mode,
      split,
      gitCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
      workingTree: execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }),
      manifestSha256: integrity.manifestSha256,
      node: process.version,
      hardware: {
        platform: os.platform(),
        release: os.release(),
        architecture: os.arch(),
        cpuModel: os.cpus()[0]?.model,
        logicalCpus: os.cpus().length,
        totalMemoryBytes: os.totalmem(),
      },
      configuration: {
        maxRequestBodyBytes: gw.config.maxRequestBodyBytes,
        defaultMaxRequestBodyBytes: 1048576,
        discoveryTtlMs: gw.config.discoveryCacheTtlMs,
        failClosed: gw.config.failClosed,
        enforceSessions: gw.config.enforceSessions,
        loopbackOnly: true,
      },
      routingMetrics: gw.securityEngine.getRoutingMetrics(),
      auditRetention: gw.auditChain.getRetentionState(),
      evaluationNote:
        split === 'holdout'
          ? 'Previously evaluated Phase 2E holdout: regression only, never first-look independent evidence'
          : 'Previously available development corpus; not independent accuracy evidence',
      actualPaidModelCalls: 0,
      knownProviderInputTokens: 0,
      knownProviderOutputTokens: 0,
      estimatedCostUsd: 0,
      totalMs,
      cycleHeapAfterGcBytes: cycleHeap,
      gcAvailable: typeof global.gc === 'function',
      memory: process.memoryUsage(),
      observations,
    },
    null,
    2,
  ) + '\n',
);
const failed = observations.filter(
  (o) => !o.enforcementSuccess || o.forwardingViolation || o.isolationFailures,
);
console.log(
  `${failed.length}/${observations.length} negative enforcement findings (retained, not a runner crash)`,
);
// Findings are data. --strict is for CI that deliberately gates on unresolved findings.
if (process.argv.includes('--strict') && failed.length) process.exitCode = 2;
