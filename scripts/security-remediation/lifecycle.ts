/** Extended, bounded local lifecycle measurement; no leak-free assertion. */
import { mkdirSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import {
  ClientSessionManager,
  AuditLogChain,
  toolMetadataText,
} from '../../packages/policy-engine/src/index.js';
import { Fixture } from '../security-lab/fixture.js';
import type { LabCase } from '../security-lab/types.js';
const output = 'security-lab/phase-2f/after';
mkdirSync(output, { recursive: true });
const cycles = 100,
  callsPerCycle = 20;
const nativeFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
  );
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))
    throw new Error('Offline lifecycle rejects external requests');
  return nativeFetch(input, init);
};
const component: Array<Record<string, unknown>> = [];
const sessions = new ClientSessionManager();
const audit = new AuditLogChain({ maxRetainedRecords: 128 });
const started = performance.now();
for (let cycle = 0; cycle < cycles; cycle++) {
  for (let i = 0; i < 1000; i++) {
    const session = sessions.createSession({ clientIdentity: 'synthetic', serverId: 'local' });
    audit.append({
      serverId: 'local',
      sessionId: session.sessionId,
      mcpMethod: 'tools/call',
      stage: 'call_arguments',
      decision: 'allow',
      reasonCode: 'fixture',
      policyVersion: '2f',
      latencyMs: 0,
    });
    sessions.destroySession(session.sessionId);
  }
  global.gc?.();
  component.push({
    cycle,
    heapBytes: process.memoryUsage().heapUsed,
    rssBytes: process.memoryUsage().rss,
    activeSessions: sessions.getActiveSessionsCount(),
    retention: audit.getRetentionState(),
  });
}
const componentMs = performance.now() - started;
const fixture = new Fixture();
await fixture.start();
fixture.reset({
  id: '2f-lifecycle',
  operation: 'response',
  input: 'new local lifecycle text',
} as LabCase);
fixture.definitions = fixture.definitions.filter((t) => t.name === 'reader');
Object.assign(process.env, {
  GATEWAY_HOST: '127.0.0.1',
  UPSTREAM_MCP_URL: fixture.url,
  META_AI_MODE: 'mock',
  ENFORCE_SESSIONS: 'true',
  FAIL_CLOSED: 'true',
  LOG_LEVEL: 'error',
  TOOL_CAPABILITIES: JSON.stringify([
    { serverId: fixture.url, toolName: 'reader', capability: 'PURE_OR_READ' },
  ]),
});
delete process.env['META_MODEL_API_KEY'];
delete process.env['META_API_KEY'];
delete process.env['AUDIT_LOG_PATH'];
const gw = await import('../../apps/gateway/src/server.js');
// The fixture metadata is explicitly approved by the local operator. Output is never pinned.
for (const t of fixture.definitions)
  gw.securityEngine.approveTrustedContent(fixture.url, 'discovery', t.name, toolMetadataText(t));
gw.securityEngine.approveTrustedContent(
  fixture.url,
  'resource_discovery',
  'lab://document',
  'document Local public document lab://document',
);
gw.securityEngine.approveTrustedContent(
  fixture.url,
  'prompt_discovery',
  'summary',
  'summary Local summary prompt []',
);
await new Promise<void>((r) => gw.httpServer.listen(0, '127.0.0.1', r));
const address = gw.httpServer.address();
if (!address || typeof address === 'string') throw new Error('No loopback port');
const http: Array<Record<string, unknown>> = [];
const latency: number[] = [];
let failures = 0;
const httpStart = performance.now();
try {
  for (let cycle = 0; cycle < cycles; cycle++) {
    const session = gw.sessionManager.createSession({
      clientIdentity: 'synthetic',
      serverId: fixture.url,
      permittedTools: ['reader'],
    });
    const c = new Client({ name: '2f-lifecycle', version: '1' });
    try {
      await c.connect(
        new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`), {
          requestInit: {
            headers: {
              'x-veylith-session-id': session.sessionId,
              'x-veylith-client-id': 'synthetic',
            },
          },
        }),
      );
      for (let i = 0; i < callsPerCycle; i++) {
        const marker = `cycle-${cycle}-call-${i}`;
        const t = performance.now();
        const r = await c.callTool({ name: 'reader', arguments: i % 5 === 0 ? {} : { marker } });
        latency.push(performance.now() - t);
        if (
          r.isError ||
          r.content[0]?.type !== 'text' ||
          r.content[0].text !== (i % 5 === 0 ? fixture.current.input : marker)
        )
          failures++;
      }
    } catch {
      failures++;
    } finally {
      await c.close();
      gw.sessionManager.destroySession(session.sessionId);
      gw.invalidateDiscoveryCache();
    }
    // Do not reset audit history: exercise eviction and chain continuity throughout the run.
    gw.securityEngine.getRoutingMetrics();
    global.gc?.();
    http.push({
      cycle,
      heapBytes: process.memoryUsage().heapUsed,
      rssBytes: process.memoryUsage().rss,
      activeSessions: gw.sessionManager.getActiveSessionsCount(),
      audit: gw.auditChain.getRetentionState(),
      context: gw.securityEngine.getRoutingMetrics(),
    });
    if (cycle % 20 === 0)
      console.log(`MCP lifecycle ${cycle}/${cycles}: ${failures} observed failures`);
  }
} finally {
  gw.httpServer.closeAllConnections();
  await new Promise<void>((r) => gw.httpServer.close(() => r()));
  await gw.handler.close();
  await fixture.stop();
}
const httpMs = performance.now() - httpStart;
latency.sort((a, b) => a - b);
const percentile = (p: number) => latency[Math.max(0, Math.ceil(latency.length * p) - 1)];
const growth = (rows: Array<Record<string, unknown>>, warmup: number) => ({
  warmupCycles: warmup,
  firstMeasuredHeap: rows[warmup]?.['heapBytes'],
  finalHeap: rows.at(-1)?.['heapBytes'],
  retainedGrowthBytes: Number(rows.at(-1)?.['heapBytes']) - Number(rows[warmup]?.['heapBytes']),
});
const result = {
  sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  cycles,
  callsPerCycle,
  actualPaidCalls: 0,
  gcAvailable: Boolean(global.gc),
  hardware: {
    cpu: os.cpus()[0]?.model,
    cpus: os.cpus().length,
    memoryBytes: os.totalmem(),
    node: process.version,
  },
  componentMs,
  componentOperations: 100000,
  componentGrowth: growth(component, 10),
  httpMs,
  mcpCalls: latency.length,
  failures,
  callLatency: { p50Ms: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99) },
  callsPerSecond: (latency.length * 1000) / httpMs,
  httpGrowth: growth(http, 10),
  auditTailVerified: gw.auditChain.verifyChain(),
  component,
  http,
  limits:
    'One local process containing gateway, SDK, fixture and metric arrays; retained growth cannot be attributed to the gateway alone. No zero-leak claim. Process lifetime and cycles are finite.',
};
writeFileSync(`${output}/lifecycle.json`, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify({ ...result, component: undefined, http: undefined }, null, 2));
if (failures) process.exitCode = 1;
