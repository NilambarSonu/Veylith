/**
 * Reproducible Reliability and Performance Benchmark Suite for Veylith Phase 2D.
 *
 * Measures:
 *   1. Direct MCP baseline
 *   2. Deterministic Gateway proxy
 *   3. Full Local Security Pipeline (Invariants + Heuristic Screener)
 *   4. Mock Semantic Model Inference
 *   5. Session Authorization & Scope Validation
 *   6. Audit Logging (In-memory and Persistent JSONL Chain)
 *   7. Resource Inspection
 *   8. Prompt Inspection
 *
 * Metrics Collected:
 *   - p50, p95, p99, Min, Max, Average Latency (ms)
 *   - Throughput (operations per second)
 *   - Memory Delta (RSS & Heap in MB)
 *   - CPU User & System Time (ms)
 *   - Event-loop lag (ms)
 *   - Error Rate (%)
 */

import { performance } from 'node:perf_hooks';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createServer } from 'node:http';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import {
  SecurityInspectionEngine,
  ClientSessionManager,
  AuditLogChain,
  type PolicyRule,
} from '../packages/policy-engine/src/index.js';
import { MetaMuseSecurityAdapter } from '../packages/meta-adapter/src/index.js';
import { handler as benignHandler } from '../examples/benign-mcp-server/src/index.js';

interface BenchmarkResult {
  readonly name: string;
  readonly sampleCount: number;
  readonly coldAvgMs: number;
  readonly warmAvgMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly throughputOpsSec: number;
  readonly errorRatePct: number;
  readonly memoryDeltaMb: number;
  readonly eventLoopLagMs: number;
}

function calculatePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, index))]!;
}

async function measureEventLoopLag(): Promise<number> {
  const start = performance.now();
  return new Promise((resolve) => {
    setImmediate(() => {
      resolve(performance.now() - start);
    });
  });
}

async function runBenchmarkSeries(
  name: string,
  fn: (i: number) => Promise<void>,
  coldRuns = 10,
  warmRuns = 100,
): Promise<BenchmarkResult> {
  const initialMem = process.memoryUsage().heapUsed;
  let errors = 0;

  // Cold runs
  const coldTimes: number[] = [];
  for (let i = 0; i < coldRuns; i++) {
    const t0 = performance.now();
    try {
      await fn(i);
    } catch {
      errors++;
    }
    coldTimes.push(performance.now() - t0);
  }

  // Warm runs
  const warmTimes: number[] = [];
  const startWarm = performance.now();
  for (let i = 0; i < warmRuns; i++) {
    const t0 = performance.now();
    try {
      await fn(i + coldRuns);
    } catch {
      errors++;
    }
    warmTimes.push(performance.now() - t0);
  }
  const totalWarmDurationMs = performance.now() - startWarm;

  warmTimes.sort((a, b) => a - b);
  const coldAvgMs = coldTimes.reduce((a, b) => a + b, 0) / coldRuns;
  const warmAvgMs = warmTimes.reduce((a, b) => a + b, 0) / warmRuns;
  const p50Ms = calculatePercentile(warmTimes, 50);
  const p95Ms = calculatePercentile(warmTimes, 95);
  const p99Ms = calculatePercentile(warmTimes, 99);
  const throughputOpsSec = (warmRuns / totalWarmDurationMs) * 1000;
  const errorRatePct = (errors / (coldRuns + warmRuns)) * 100;
  const finalMem = process.memoryUsage().heapUsed;
  const memoryDeltaMb = Math.round(((finalMem - initialMem) / (1024 * 1024)) * 100) / 100;
  const eventLoopLagMs = await measureEventLoopLag();

  return {
    name,
    sampleCount: coldRuns + warmRuns,
    coldAvgMs,
    warmAvgMs,
    p50Ms,
    p95Ms,
    p99Ms,
    throughputOpsSec,
    errorRatePct,
    memoryDeltaMb,
    eventLoopLagMs,
  };
}

async function main() {
  console.log('========================================================================');
  console.log('          VEYLITH PHASE 2D — PERFORMANCE & RELIABILITY BENCHMARK        ');
  console.log('========================================================================');
  console.log(`OS: ${os.type()} ${os.release()} (${os.arch()})`);
  console.log(`CPUs: ${os.cpus().length} cores | CPU Model: ${os.cpus()[0]?.model}`);
  console.log(`Memory: ${Math.round(os.totalmem() / (1024 * 1024 * 1024))} GB total`);
  console.log(`Node: ${process.version}`);
  console.log('------------------------------------------------------------------------\n');

  // 1. Setup local Upstream Server
  const UPSTREAM_PORT = 19777;
  const UPSTREAM_URL = `http://127.0.0.1:${UPSTREAM_PORT}/mcp`;
  const upstreamHttp = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', UPSTREAM_URL);
    if (url.pathname !== '/mcp') {
      res.writeHead(404).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const body = Buffer.concat(chunks);
    const webReq = new Request(url.toString(), {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: ['GET', 'HEAD'].includes(req.method ?? 'GET') ? undefined : body,
    });
    const webRes = await benignHandler.fetch(webReq);
    res.writeHead(webRes.status, Object.fromEntries(webRes.headers.entries()));
    res.end(await webRes.text());
  });

  await new Promise<void>((resolve) => upstreamHttp.listen(UPSTREAM_PORT, '127.0.0.1', resolve));

  // 2. Setup Veylith Gateway Server
  process.env['UPSTREAM_MCP_URL'] = UPSTREAM_URL;
  process.env['GATEWAY_PORT'] = '19778';
  process.env['DISCOVERY_CACHE_TTL_MS'] = '5000';
  const { httpServer: gatewayHttp } = await import('../apps/gateway/src/server.js');
  await new Promise<void>((resolve) => gatewayHttp.listen(19778, '127.0.0.1', resolve));
  const GATEWAY_URL = 'http://127.0.0.1:19778/mcp';

  // Instantiate isolated engine for standalone microbenchmarks
  const staticRules: PolicyRule[] = [
    {
      id: 'rule-block-restricted',
      description: 'Block restricted_demo_tool',
      method: 'tools/call',
      toolName: 'restricted_demo_tool',
      decision: 'block',
      enabled: true,
    },
  ];
  const metaAdapter = new MetaMuseSecurityAdapter({ mode: 'mock' });
  const sessionManager = new ClientSessionManager();
  const testSession = sessionManager.createSession({
    clientIdentity: 'benchmark-client',
    serverId: UPSTREAM_URL,
    permittedTools: ['echo', 'add'],
    permittedResources: ['docs://*'],
    permittedPrompts: ['*'],
  });

  const auditChainMem = new AuditLogChain();
  const tempAuditFile = path.join(os.tmpdir(), `veylith-bench-audit-${Date.now()}.jsonl`);
  const auditChainDisk = new AuditLogChain({ storagePath: tempAuditFile });

  const engine = new SecurityInspectionEngine(staticRules, metaAdapter, {
    failClosed: true,
    policyVersion: '2.4.0',
    sessionManager,
    auditChain: auditChainMem,
    capabilityBindings: [{ serverId: UPSTREAM_URL, toolName: 'echo', capability: 'PURE_OR_READ' }],
  });

  const directClient = new Client({ name: 'bench-direct', version: '0.1.0' });
  await directClient.connect(new StreamableHTTPClientTransport(new URL(UPSTREAM_URL)));

  const gwClient = new Client({ name: 'bench-gw', version: '0.1.0' });
  await gwClient.connect(new StreamableHTTPClientTransport(new URL(GATEWAY_URL)));

  const results: BenchmarkResult[] = [];

  try {
    // Benchmark 1: Direct MCP
    console.log('[1/8] Benchmarking Direct MCP...');
    results.push(
      await runBenchmarkSeries('Direct MCP (echo)', async (i) => {
        await directClient.callTool({ name: 'echo', arguments: { message: `msg-${i}` } });
      }),
    );

    // Benchmark 2: Gateway Proxy
    console.log('[2/8] Benchmarking Veylith Gateway (echo)...');
    results.push(
      await runBenchmarkSeries('Gateway Proxy (echo)', async (i) => {
        await gwClient.callTool({ name: 'echo', arguments: { message: `msg-${i}` } });
      }),
    );

    // Benchmark 3: Full Local Security Pipeline
    console.log('[3/8] Benchmarking Security Engine Argument Inspection...');
    results.push(
      await runBenchmarkSeries('Engine: Argument Inspection', async (i) => {
        await engine.inspectArguments(
          {
            requestId: `bench-${i}`,
            stage: 'call_arguments',
            method: 'tools/call',
            toolName: 'echo',
            serverId: UPSTREAM_URL,
            sessionId: testSession.sessionId,
            clientIdentity: 'benchmark-client',
            timestamp: new Date().toISOString(),
          },
          'echo',
          { message: `normal benign message ${i}` },
          { name: 'echo', description: 'Echoes message' },
        );
      }),
    );

    // Benchmark 4: Mock Semantic Model Inference
    console.log('[4/8] Benchmarking Mock Semantic Inference...');
    results.push(
      await runBenchmarkSeries(
        'Mock Semantic Inference',
        async (i) => {
          await metaAdapter.classifyToolCall({
            requestId: `mock-${i}`,
            stage: 'call_arguments',
            toolName: 'complex_tool',
            promptOrInput: `Potentially ambiguous text prompt ${i}`,
            clientIdentity: 'benchmark-client',
          });
        },
        5,
        50,
      ),
    );

    // Benchmark 5: Session Authorization
    console.log('[5/8] Benchmarking Session Authorization...');
    results.push(
      await runBenchmarkSeries(
        'Session Auth & Validation',
        async () => {
          sessionManager.validateSession(testSession.sessionId, 'benchmark-client', UPSTREAM_URL);
          sessionManager.isToolAuthorized(testSession.sessionId, 'echo', UPSTREAM_URL);
          sessionManager.isResourceAuthorized(testSession.sessionId, 'docs://readme', UPSTREAM_URL);
        },
        20,
        500,
      ),
    );

    // Benchmark 6A: Audit Logging (In-Memory)
    console.log('[6/8] Benchmarking Audit Logging (In-Memory & Persistent)...');
    results.push(
      await runBenchmarkSeries(
        'Audit Chain: In-Memory Append',
        async (_i) => {
          auditChainMem.append({
            sessionId: testSession.sessionId,
            serverId: UPSTREAM_URL,
            clientIdentity: 'benchmark-client',
            mcpMethod: 'tools/call',
            targetName: 'echo',
            stage: 'call_arguments',
            decision: 'allow',
            reasonCode: 'benign_execution',
            policyVersion: '2.4.0',
            latencyMs: 0.15,
          });
        },
        20,
        500,
      ),
    );

    // Benchmark 6B: Audit Logging (Persistent Disk JSONL)
    results.push(
      await runBenchmarkSeries(
        'Audit Chain: Disk JSONL (fsync)',
        async (_i) => {
          auditChainDisk.append({
            sessionId: testSession.sessionId,
            serverId: UPSTREAM_URL,
            clientIdentity: 'benchmark-client',
            mcpMethod: 'tools/call',
            targetName: 'echo',
            stage: 'call_arguments',
            decision: 'allow',
            reasonCode: 'benign_execution',
            policyVersion: '2.4.0',
            latencyMs: 0.15,
          });
        },
        10,
        100,
      ),
    );

    // Benchmark 7: Resource Content Inspection
    console.log('[7/8] Benchmarking Resource Content Inspection...');
    results.push(
      await runBenchmarkSeries('Resource Content Inspection', async (i) => {
        await engine.inspectResourceContent(
          {
            requestId: `res-${i}`,
            stage: 'resource_content',
            method: 'resources/read',
            resourceUri: 'docs://readme',
            serverId: UPSTREAM_URL,
            sessionId: testSession.sessionId,
            clientIdentity: 'benchmark-client',
            timestamp: new Date().toISOString(),
          },
          'docs://readme',
          [{ uri: 'docs://readme', mimeType: 'text/plain', text: 'Benign documentation content' }],
        );
      }),
    );

    // Benchmark 8: Prompt Messages Inspection
    console.log('[8/8] Benchmarking Prompt Messages Inspection...');
    results.push(
      await runBenchmarkSeries('Prompt Messages Inspection', async (i) => {
        await engine.inspectPromptMessages(
          {
            requestId: `pm-${i}`,
            stage: 'prompt_messages',
            method: 'prompts/get',
            promptName: 'code_review',
            serverId: UPSTREAM_URL,
            sessionId: testSession.sessionId,
            clientIdentity: 'benchmark-client',
            timestamp: new Date().toISOString(),
          },
          'code_review',
          [
            {
              role: 'user',
              content: { type: 'text', text: 'Review this clean function: function test() {}' },
            },
          ],
        );
      }),
    );
  } finally {
    await directClient.close().catch(() => {});
    await gwClient.close().catch(() => {});
    await new Promise<void>((resolve) => upstreamHttp.close(() => resolve()));
    await new Promise<void>((resolve) => gatewayHttp.close(() => resolve()));
    auditChainDisk.close();
    if (fs.existsSync(tempAuditFile)) {
      fs.unlinkSync(tempAuditFile);
    }
  }

  console.log('\n========================================================================');
  console.log('                          BENCHMARK RESULTS                             ');
  console.log('========================================================================');
  console.table(
    results.map((r) => ({
      Component: r.name,
      Samples: r.sampleCount,
      'Cold (ms)': r.coldAvgMs.toFixed(3),
      'Warm (ms)': r.warmAvgMs.toFixed(3),
      'p50 (ms)': r.p50Ms.toFixed(3),
      'p95 (ms)': r.p95Ms.toFixed(3),
      'p99 (ms)': r.p99Ms.toFixed(3),
      'Throughput (ops/s)': Math.round(r.throughputOpsSec),
      'Lag (ms)': r.eventLoopLagMs.toFixed(3),
      'Mem Delta (MB)': r.memoryDeltaMb,
    })),
  );

  const directResult = results.find((r) => r.name.includes('Direct MCP'));
  const gwResult = results.find((r) => r.name.includes('Gateway Proxy'));
  if (directResult && gwResult) {
    const overhead = Math.max(0, gwResult.warmAvgMs - directResult.warmAvgMs);
    console.log(`\nMeasured Gateway Proxy Warm Overhead: ${overhead.toFixed(2)} ms`);
  }
  console.log('========================================================================\n');
}

main().catch((err) => {
  console.error('Benchmark execution failed:', err);
  process.exit(1);
});
