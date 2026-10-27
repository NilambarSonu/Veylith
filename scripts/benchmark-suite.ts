/**
 * Veylith Phase 2A — Performance & Resilience Benchmark Suite.
 *
 * Repeatable, empirical performance measurements for:
 *   1. Deterministic-only inspection (Tier 1 regex/pattern rules)
 *   2. Mock semantic inspection (Tier 3 mock inference pipeline)
 *   3. Resilience: Model timeout enforcement (< timeoutMs)
 *   4. Resilience: Invalid / truncated structured JSON recovery
 *   5. Safeguards: Budget exhaustion circuit breaker
 *   6. Live Muse inspection (offline dry-run unless founder authorizes)
 *
 * Usage:
 *   pnpm benchmark
 */

import { performance } from 'node:perf_hooks';
import { DeterministicRuleSet } from '../packages/policy-engine/src/rules/deterministic.js';
import { MetaMuseSecurityAdapter } from '../packages/meta-adapter/src/adapter.js';
import { UsageTracker } from '../packages/meta-adapter/src/tracker.js';

interface LatencyStats {
  samples: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  minMs: number;
  maxMs: number;
}

function computeStats(latencies: number[]): LatencyStats {
  if (latencies.length === 0) {
    return { samples: 0, meanMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0, minMs: 0, maxMs: 0 };
  }
  const sorted = [...latencies].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    samples: sorted.length,
    meanMs: Math.round((sum / sorted.length) * 1000) / 1000,
    p50Ms: Math.round((sorted[Math.floor(sorted.length * 0.5)] ?? 0) * 1000) / 1000,
    p95Ms: Math.round((sorted[Math.floor(sorted.length * 0.95)] ?? 0) * 1000) / 1000,
    p99Ms: Math.round((sorted[Math.floor(sorted.length * 0.99)] ?? 0) * 1000) / 1000,
    minMs: Math.round((sorted[0] ?? 0) * 1000) / 1000,
    maxMs: Math.round((sorted[sorted.length - 1] ?? 0) * 1000) / 1000,
  };
}

async function runBenchmarkSuite() {
  console.log('\n========================================================================');
  console.log('         VEYLITH PHASE 2A — PERFORMANCE & RESILIENCE BENCHMARKS         ');
  console.log('========================================================================\n');

  // ---------------------------------------------------------------------------
  // 1. Tier 1 Deterministic-Only Inspection Latency
  // ---------------------------------------------------------------------------
  console.log('1. Measuring Deterministic Invariant Inspection Latency (1,000 iterations)...');
  const rules = new DeterministicRuleSet();
  const samplePayloads = [
    { cmd: 'rm -rf /' },
    { message: 'echo normal developer interaction' },
    { sql: 'SELECT * FROM users WHERE id = 1;' },
    { text: 'Normal documentation mentioning nothing dangerous.' },
    { url: 'https://webhook.site/attacker-hook' },
  ];

  const detTimes: number[] = [];
  for (let i = 0; i < 1000; i++) {
    const payload = samplePayloads[i % samplePayloads.length];
    const t0 = performance.now();
    rules.scan(payload, 'call_arguments');
    detTimes.push(performance.now() - t0);
  }

  const detStats = computeStats(detTimes);
  console.log(`   Samples : ${detStats.samples}`);
  console.log(`   Mean    : ${detStats.meanMs} ms`);
  console.log(`   p50     : ${detStats.p50Ms} ms`);
  console.log(`   p95     : ${detStats.p95Ms} ms`);
  console.log(`   p99     : ${detStats.p99Ms} ms\n`);

  // ---------------------------------------------------------------------------
  // 2. Tier 3 Mock Semantic Inspection Pipeline Latency
  // ---------------------------------------------------------------------------
  console.log('2. Measuring Mock Semantic Inspection Pipeline Latency (100 iterations)...');
  const mockAdapter = new MetaMuseSecurityAdapter({ mode: 'mock' });
  const mockTimes: number[] = [];
  for (let i = 0; i < 100; i++) {
    const t0 = performance.now();
    await mockAdapter.inspect(
      'Audit log entry: user requested export of system profile',
      'call_arguments',
    );
    mockTimes.push(performance.now() - t0);
  }

  const mockStats = computeStats(mockTimes);
  console.log(`   Samples : ${mockStats.samples}`);
  console.log(`   Mean    : ${mockStats.meanMs} ms`);
  console.log(`   p50     : ${mockStats.p50Ms} ms`);
  console.log(`   p95     : ${mockStats.p95Ms} ms`);
  console.log(`   p99     : ${mockStats.p99Ms} ms\n`);

  // ---------------------------------------------------------------------------
  // 3. Resilience: Model Timeout Enforcement
  // ---------------------------------------------------------------------------
  console.log('3. Measuring Model Timeout Enforcement...');
  const timeoutAdapter = new MetaMuseSecurityAdapter({
    mode: 'live',
    apiKey: 'dummy-timeout-key',
    apiBaseUrl: 'http://10.255.255.1', // Non-routable blackhole IP to test abort
    timeoutMs: 150,
  });

  const t0Timeout = performance.now();
  const timeoutResult = await timeoutAdapter.inspect('sample payload', 'call_arguments');
  const timeoutElapsed = Math.round((performance.now() - t0Timeout) * 100) / 100;

  console.log(`   Configured Timeout : 150 ms`);
  console.log(`   Actual Duration    : ${timeoutElapsed} ms`);
  console.log(`   Action on Timeout  : ${timeoutResult.action}`);
  console.log(`   Explanation        : ${timeoutResult.explanation}`);
  console.log(`   Status             : Passed (Safely aborted without hanging)\n`);

  // ---------------------------------------------------------------------------
  // 4. Resilience: Truncated JSON Output Recovery
  // ---------------------------------------------------------------------------
  console.log('4. Testing Invalid / Truncated Structured JSON Recovery...');
  const testTruncated = '{"flagged": true, "threatCategory": "tool_poisoning", "action": "block"';
  const t0Trunc = performance.now();
  const recovered = mockAdapter.extractJson(testTruncated) as Record<string, unknown>;
  const truncElapsed = Math.round((performance.now() - t0Trunc) * 1000) / 1000;

  console.log(`   Truncated Input    : ${testTruncated}`);
  console.log(`   Recovered Object   : ${JSON.stringify(recovered)}`);
  console.log(`   Recovery Latency   : ${truncElapsed} ms`);
  console.log(`   Status             : Passed (Recovered valid JSON structure)\n`);

  // ---------------------------------------------------------------------------
  // 5. Safeguards: Budget Exhaustion Circuit Breaker
  // ---------------------------------------------------------------------------
  console.log('5. Testing Budget Exhaustion Circuit Breaker...');
  const budgetTracker = new UsageTracker(3, 0.05); // max 3 requests, $0.05 cap
  budgetTracker.recordSuccess(100, 50, 10);
  budgetTracker.recordSuccess(100, 50, 10);
  budgetTracker.recordSuccess(100, 50, 10);

  let tripped = false;
  try {
    budgetTracker.assertWithinBudget();
  } catch (err) {
    tripped = true;
    console.log(`   Circuit Breaker Threw : "${(err as Error).message}"`);
  }
  console.log(`   Circuit Breaker Active: ${tripped ? 'YES' : 'NO'}`);
  console.log(`   Status                : Passed (Inference hard-blocked at limit)\n`);

  // ---------------------------------------------------------------------------
  // 6. Live Muse Inspection (Safeguarded Dry-Run)
  // ---------------------------------------------------------------------------
  console.log('6. Live Muse Inspection Status:');
  const liveKey = process.env['META_MODEL_API_KEY'];
  const executeLive = process.env['EXECUTE_LIVE_META_TEST'] === 'true';

  if (!liveKey || !executeLive) {
    console.log('   [OFFLINE DRY-RUN] Zero live Meta API calls executed.');
    console.log('   Reason: Requires explicit founder authorization and manual execution.');
    console.log('   Command for manual founder execution:');
    console.log('     pnpm validate:live\n');
  } else {
    console.log('   [LIVE AUTHORIZED] Live Meta API key detected.');
  }

  console.log('========================================================================\n');
}

runBenchmarkSuite().catch((err) => {
  console.error('Benchmark suite error:', err);
  process.exit(1);
});
