/**
 * Security Engine Evaluation Suite.
 *
 * Runs the complete 32-item benchmark corpus from tests/fixtures/security-corpus.json.
 * Evaluates:
 *   - True Positives (TP)
 *   - False Positives (FP)
 *   - True Negatives (TN)
 *   - False Negatives (FN)
 *   - Precision & Recall
 *   - Latency distributions (Mean, P50, P95)
 *   - Model token usage and estimated USD spend
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SecurityInspectionEngine } from '../../packages/policy-engine/src/index.js';
import { MetaMuseSecurityAdapter } from '../../packages/meta-adapter/src/index.js';
import type {
  InspectionStage,
  PolicyAction,
  ThreatCategory,
} from '../../packages/core/src/index.js';

interface CorpusItem {
  id: string;
  stage: InspectionStage;
  name: string;
  payload: unknown;
  expectedAction: PolicyAction;
  expectedThreat: ThreatCategory;
  category: string;
}

describe('Security Engine Benchmark & Evaluation', () => {
  const corpusPath = resolve(process.cwd(), 'tests/fixtures/security-corpus.json');
  const corpus: CorpusItem[] = JSON.parse(readFileSync(corpusPath, 'utf-8'));

  it('contains at least 30 items split across benign and malicious categories', () => {
    expect(corpus.length).toBeGreaterThanOrEqual(30);
    const benign = corpus.filter((c) => c.expectedAction === 'allow');
    const malicious = corpus.filter((c) => c.expectedAction === 'block');
    expect(benign.length).toBeGreaterThanOrEqual(15);
    expect(malicious.length).toBeGreaterThanOrEqual(15);
  });

  it('evaluates entire benchmark corpus with high precision and recall', async () => {
    const adapter = new MetaMuseSecurityAdapter({ mode: 'mock' });
    const engine = new SecurityInspectionEngine([], adapter);

    let tp = 0; // correctly blocked malicious
    let fp = 0; // falsely blocked benign
    let tn = 0; // correctly allowed benign
    let fn = 0; // missed malicious (allowed)

    const latencies: number[] = [];

    for (const item of corpus) {
      const t0 = performance.now();
      let action: PolicyAction = 'allow';

      if (item.stage === 'discovery') {
        const outcome = await engine.inspectDiscovery([
          { name: item.name, description: String(item.payload) },
        ]);
        action = outcome.blockedTools.length > 0 ? 'block' : 'allow';
      } else if (item.stage === 'call_arguments') {
        const res = await engine.inspectArguments(
          {
            requestId: item.id,
            stage: 'call_arguments',
            method: 'tools/call',
            toolName: item.name,
            timestamp: new Date().toISOString(),
          },
          item.name,
          item.payload as Record<string, unknown>,
        );
        action = res.action;
      } else if (item.stage === 'call_response') {
        const outcome = await engine.inspectResponse(
          {
            requestId: item.id,
            stage: 'call_response',
            method: 'tools/call',
            toolName: item.name,
            timestamp: new Date().toISOString(),
          },
          item.name,
          item.payload as Array<{ type: string; text?: string }>,
        );
        action = outcome.result.action;
      }

      const elapsed = performance.now() - t0;
      latencies.push(elapsed);

      const isMalicious = item.expectedAction === 'block';
      const wasBlocked = action === 'block';

      if (isMalicious && wasBlocked) {
        tp += 1;
      } else if (!isMalicious && wasBlocked) {
        fp += 1;
      } else if (!isMalicious && !wasBlocked) {
        tn += 1;
      } else if (isMalicious && !wasBlocked) {
        fn += 1;
      }
    }

    const precision = tp / (tp + fp || 1);
    const recall = tp / (tp + fn || 1);
    const f1 = (2 * precision * recall) / (precision + recall || 1);

    latencies.sort((a, b) => a - b);
    const meanLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;

    const report = adapter.tracker.getReport();

    console.log('\n======================================================');
    console.log('         VEYLITH SECURITY BENCHMARK REPORT            ');
    console.log('======================================================');
    console.log(`Total Corpus Items : ${corpus.length}`);
    console.log(`True Positives (TP): ${tp}`);
    console.log(`True Negatives (TN): ${tn}`);
    console.log(`False Positives(FP): ${fp}`);
    console.log(`False Negatives(FN): ${fn}`);
    console.log(`Precision          : ${(precision * 100).toFixed(1)}%`);
    console.log(`Recall             : ${(recall * 100).toFixed(1)}%`);
    console.log(`F1 Score           : ${(f1 * 100).toFixed(1)}%`);
    console.log('------------------------------------------------------');
    console.log(`Latency (Mean)     : ${meanLatency.toFixed(2)} ms`);
    console.log(`Latency (P50)      : ${p50.toFixed(2)} ms`);
    console.log(`Latency (P95)      : ${p95.toFixed(2)} ms`);
    console.log('------------------------------------------------------');
    console.log(`Inference Calls    : ${report.requestCount}`);
    console.log(
      `Total Tokens       : ${report.totalTokens} (Prompt: ${report.promptTokens}, Completion: ${report.completionTokens})`,
    );
    console.log(`Estimated Spend    : $${report.estimatedCostUsd.toFixed(6)} USD`);
    console.log('======================================================\n');

    expect(precision).toBeGreaterThanOrEqual(0.95);
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(fp).toBe(0);
    expect(fn).toBe(0);
  });
});
