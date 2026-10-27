import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { Observation } from './types.js';
export function metrics(rows: Observation[]) {
  const classified = rows.filter(
    (r) => r.predicted !== null && !r.unsupported && r.category !== 'operational-failure',
  );
  const count = (expected: string, predicted: string) =>
    classified.filter((r) => r.expected === expected && r.predicted === predicted).length;
  const tp = count('block', 'block'),
    tn = count('allow', 'allow'),
    fp = count('allow', 'block'),
    fn = count('block', 'allow');
  const ratio = (n: number, d: number) => (d ? n / d : null);
  const latency = rows.map((r) => r.latencyMs).sort((a, b) => a - b);
  const p = (q: number) => latency[Math.max(0, Math.ceil(latency.length * q) - 1)] ?? null;
  return {
    samples: rows.length,
    classificationSamples: classified.length,
    tp,
    tn,
    fp,
    fn,
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    falsePositiveRate: ratio(fp, fp + tn),
    falseNegativeRate: ratio(fn, fn + tp),
    accuracy: ratio(tp + tn, classified.length),
    enforcementSuccesses: rows.filter((r) => r.enforcementSuccess).length,
    enforcementSuccessRate: ratio(rows.filter((r) => r.enforcementSuccess).length, rows.length),
    unsupported: rows.filter((r) => r.unsupported).length,
    forwardingViolations: rows.filter((r) => r.forwardingViolation).length,
    isolationFailures: rows.reduce((n, r) => n + r.isolationFailures, 0),
    p50Ms: p(0.5),
    p95Ms: p(0.95),
    p99Ms: p(0.99),
  };
}
export function report(directory = 'security-lab/results') {
  const runs = readdirSync(directory)
    .filter((f) =>
      /^(development|holdout)-(direct|deterministic-only|mock-semantic)\.json$/.test(f),
    )
    .map((f) => JSON.parse(readFileSync(`${directory}/${f}`, 'utf8')));
  const summaries = runs.map((r) => ({
    mode: r.mode,
    split: r.split,
    gitCommit: r.gitCommit,
    manifestSha256: r.manifestSha256,
    hardware: r.hardware,
    gcAvailable: r.gcAvailable,
    cycleHeapAfterGcBytes: r.cycleHeapAfterGcBytes,
    actualPaidModelCalls: r.actualPaidModelCalls,
    estimatedCostUsd: r.estimatedCostUsd,
    metrics: metrics(r.observations),
    mockInferenceCalls:
      r.mode === 'mock-semantic'
        ? r.observations.reduce((n: number, o: Observation) => n + o.inferenceCalls, 0)
        : 0,
    throughputCasesPerSecond: r.observations.length / (r.totalMs / 1000),
    heapGrowthBytes:
      r.cycleHeapAfterGcBytes.length > 1
        ? r.cycleHeapAfterGcBytes.at(-1) - r.cycleHeapAfterGcBytes[0]
        : null,
    byScenario: Object.fromEntries(
      [...new Set<string>(r.observations.map((o: Observation) => o.scenarioId))].map((s) => [
        s,
        metrics(r.observations.filter((o: Observation) => o.scenarioId === s)),
      ]),
    ),
    byTier: Object.fromEntries(
      [...new Set<string>(r.observations.map((o: Observation) => o.tier))].map((s) => [
        s,
        metrics(r.observations.filter((o: Observation) => o.tier === s)),
      ]),
    ),
  }));
  writeFileSync(`${directory}/summary.json`, JSON.stringify(summaries, null, 2) + '\n');
  let md =
    '# Veylith Phase 2E — observed offline results\n\n128 distinct offline cases across 14 scenarios: 56 development cases plus 16 seeded local G1 development candidates, and 56 frozen holdout cases. Modes reuse cases and are not independent samples. Case latency includes protocol setup and teardown; case throughput includes a controlled 25 ms recovery cooldown per case and is not gateway capacity. Mock semantic scores measure deterministic simulation, never real model detection accuracy. Operational failures and unsupported cases are excluded from classification denominators. Transport errors alone are not attack detections. All negative observations remain in raw JSON.\n\n';
  md +=
    '| Split / mode | N classified / total | TP | TN | FP | FN | Precision | Recall | FPR | FNR | Accuracy | Enforcement | Forwarding violations | Unsupported | p50 / p95 / p99 ms | Cases/sec |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|\n';
  const pct = (v: number | null) => (v === null ? 'n/a' : (100 * v).toFixed(1) + '%');
  for (const s of summaries) {
    const m = s.metrics;
    md += `| ${s.split} / ${s.mode} | ${m.classificationSamples} / ${m.samples} | ${m.tp} | ${m.tn} | ${m.fp} | ${m.fn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.falsePositiveRate)} | ${pct(m.falseNegativeRate)} | ${pct(m.accuracy)} | ${m.enforcementSuccesses}/${m.samples} | ${m.forwardingViolations} | ${m.unsupported} | ${m.p50Ms?.toFixed(1)} / ${m.p95Ms?.toFixed(1)} / ${m.p99Ms?.toFixed(1)} | ${s.throughputCasesPerSecond.toFixed(2)} |\n`;
  }
  for (const s of summaries) {
    md += `\n## ${s.split} / ${s.mode}\n\nCommit: \`${s.gitCommit}\`; manifest: \`${s.manifestSha256}\`. GC available: ${s.gcAvailable}. Retained heap change across ${s.cycleHeapAfterGcBytes.length} sampled cycles: ${s.heapGrowthBytes} bytes. Worker heap includes intentionally retained observations and audit evidence; this is not isolated gateway heap. Separate cleanup-cycle measurements are in reliability.json. No absence-of-leaks conclusion is supported.\n\n| Scenario | Classified N | TP | TN | FP | FN | Enforcement |\n|---|---:|---:|---:|---:|---:|---:|\n`;
    for (const [id, m] of Object.entries(s.byScenario)) {
      md += `| ${id} | ${m.classificationSamples} | ${m.tp} | ${m.tn} | ${m.fp} | ${m.fn} | ${m.enforcementSuccesses}/${m.samples} |\n`;
    }
    md += '\nTier aggregates (descriptive small samples, no population estimate):\n\n';
    for (const [id, m] of Object.entries(s.byTier))
      md += `- ${id}: TP/TN/FP/FN ${m.tp}/${m.tn}/${m.fp}/${m.fn}, enforcement ${m.enforcementSuccesses}/${m.samples}.\n`;
  }
  md += '\n## Negative enforcement observations\n\n';
  for (const r of runs)
    for (const o of r.observations as Observation[])
      if (!o.enforcementSuccess || o.forwardingViolation || o.unsupported)
        md += `- ${r.split}/${r.mode} ${o.id}: enforced=${o.enforcementSuccess}, classification=${o.predicted}, forwardingViolation=${o.forwardingViolation}; ${o.unsupported ?? o.error ?? 'see raw response and audit records'}.\n`;
  md +=
    '\n## Limits\n\nZero actual paid calls, zero provider tokens, zero estimated offline cost. Mock token estimates are excluded. Direct MCP is a transport/control baseline; local authorization and operational probes are not comparable security products. No third-party gateway installed or executed. Real Muse and third-party comparisons remain unevaluated. No universal injection-prevention claim; confidence is not a calibrated probability.\n';
  writeFileSync(`${directory}/REPORT.md`, md);
  console.log(`${directory}/REPORT.md`);
  return summaries;
}
