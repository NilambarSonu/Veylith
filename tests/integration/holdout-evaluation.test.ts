/**
 * Phase 2A: Fixed Internal Validation Fixture Evaluation Suite.
 *
 * Evaluates the 68-item validation corpus (tests/fixtures/holdout-corpus.json)
 * spanning multilingual injections, role spoofing, encoded payloads,
 * benign security documentation, and legitimate admin operations.
 *
 * Note on Dataset Provenance:
 *   Phase 2A fixed internal validation fixture: 68 curated samples, comprising
 *   32 malicious and 36 benign cases. This dataset is distinct from the earlier
 *   Phase 1 corpus but was publicly present in the repository and available
 *   during subsequent development; it should not be described as a blind or
 *   external holdout.
 *
 * Calculates:
 *   - Per-stage confusion matrices (discovery, call_arguments, call_response)
 *   - Attack-class metrics (precision 93.8%, recall 46.9%, F1 62.5%)
 *   - Benign-class metrics (precision 67.3%, recall 97.2%, F1 79.5%)
 *   - Macro-averaged metrics (precision 80.5%, recall 72.0%, F1 71.0%)
 *   - Overall accuracy (73.5%)
 *   - Latency distributions
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

interface HoldoutItem {
  id: string;
  stage: InspectionStage;
  name: string;
  payload: unknown;
  expectedAction: PolicyAction;
  expectedThreat: ThreatCategory;
  category: string;
}

interface StageMetrics {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  deterministicCatches: number;
  tier3Evaluations: number;
}

function calculateMetrics(m: StageMetrics) {
  const precision = m.tp / (m.tp + m.fp || 1);
  const recall = m.tp / (m.tp + m.fn || 1);
  const f1 = (2 * precision * recall) / (precision + recall || 1);
  return { precision, recall, f1 };
}

describe('Phase 2A: Independent Holdout Evaluation', () => {
  const corpusPath = resolve(process.cwd(), 'tests/fixtures/holdout-corpus.json');
  const corpus: HoldoutItem[] = JSON.parse(readFileSync(corpusPath, 'utf-8'));

  it('validates holdout corpus contains >= 60 items with stage balance', () => {
    expect(corpus.length).toBeGreaterThanOrEqual(60);

    const stages: Record<InspectionStage, { benign: number; malicious: number }> = {
      discovery: { benign: 0, malicious: 0 },
      call_arguments: { benign: 0, malicious: 0 },
      call_response: { benign: 0, malicious: 0 },
    };

    for (const item of corpus) {
      if (item.expectedAction === 'allow') {
        stages[item.stage].benign++;
      } else {
        stages[item.stage].malicious++;
      }
    }

    expect(stages.discovery.benign).toBeGreaterThanOrEqual(8);
    expect(stages.discovery.malicious).toBeGreaterThanOrEqual(8);
    expect(stages.call_arguments.benign).toBeGreaterThanOrEqual(10);
    expect(stages.call_arguments.malicious).toBeGreaterThanOrEqual(10);
    expect(stages.call_response.benign).toBeGreaterThanOrEqual(10);
    expect(stages.call_response.malicious).toBeGreaterThanOrEqual(10);
  });

  it('evaluates holdout corpus across deterministic and hybrid tiers with per-stage confusion matrices', async () => {
    const adapter = new MetaMuseSecurityAdapter({ mode: 'mock' });
    const engine = new SecurityInspectionEngine([], adapter);

    const stageResults: Record<InspectionStage, StageMetrics> = {
      discovery: { tp: 0, fp: 0, tn: 0, fn: 0, deterministicCatches: 0, tier3Evaluations: 0 },
      call_arguments: { tp: 0, fp: 0, tn: 0, fn: 0, deterministicCatches: 0, tier3Evaluations: 0 },
      call_response: { tp: 0, fp: 0, tn: 0, fn: 0, deterministicCatches: 0, tier3Evaluations: 0 },
    };

    const latencies: number[] = [];
    const missedAttacks: { id: string; stage: string; category: string }[] = [];
    const falsePositives: { id: string; stage: string; category: string }[] = [];

    for (const item of corpus) {
      const t0 = performance.now();
      let action: PolicyAction = 'allow';
      let origin = 'deterministic';

      if (item.stage === 'discovery') {
        const outcome = await engine.inspectDiscovery([
          { name: item.name, description: String(item.payload) },
        ]);
        action = outcome.blockedTools.length > 0 ? 'block' : 'allow';
        origin = outcome.results[0]?.origin ?? 'deterministic';
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
        origin = res.origin;
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
        origin = outcome.result.origin;
      }

      const elapsed = performance.now() - t0;
      latencies.push(elapsed);

      const st = stageResults[item.stage];
      if (origin === 'deterministic' && action === 'block') {
        st.deterministicCatches++;
      } else if (origin === 'mock' || origin === 'live') {
        st.tier3Evaluations++;
      }

      const isMalicious = item.expectedAction === 'block';
      const wasBlocked = action === 'block';

      if (isMalicious && wasBlocked) {
        st.tp++;
      } else if (!isMalicious && wasBlocked) {
        st.fp++;
        falsePositives.push({ id: item.id, stage: item.stage, category: item.category });
      } else if (!isMalicious && !wasBlocked) {
        st.tn++;
      } else if (isMalicious && !wasBlocked) {
        st.fn++;
        missedAttacks.push({ id: item.id, stage: item.stage, category: item.category });
      }
    }

    latencies.sort((a, b) => a - b);
    const meanLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50 = latencies[Math.floor(latencies.length * 0.5)] ?? 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;
    const p99 = latencies[Math.floor(latencies.length * 0.99)] ?? 0;

    const totalTP =
      stageResults.discovery.tp + stageResults.call_arguments.tp + stageResults.call_response.tp;
    const totalFP =
      stageResults.discovery.fp + stageResults.call_arguments.fp + stageResults.call_response.fp;
    const totalTN =
      stageResults.discovery.tn + stageResults.call_arguments.tn + stageResults.call_response.tn;
    const totalFN =
      stageResults.discovery.fn + stageResults.call_arguments.fn + stageResults.call_response.fn;

    // Attack-class (positive) metrics
    const attackPrecision = totalTP / (totalTP + totalFP || 1);
    const attackRecall = totalTP / (totalTP + totalFN || 1);
    const attackF1 = (2 * attackPrecision * attackRecall) / (attackPrecision + attackRecall || 1);

    // Benign-class (negative) metrics
    const benignPrecision = totalTN / (totalTN + totalFN || 1);
    const benignRecall = totalTN / (totalTN + totalFP || 1);
    const benignF1 = (2 * benignPrecision * benignRecall) / (benignPrecision + benignRecall || 1);

    // Macro-averaged metrics (unweighted mean across both classes)
    const macroPrecision = (attackPrecision + benignPrecision) / 2;
    const macroRecall = (attackRecall + benignRecall) / 2;
    const macroF1 = (attackF1 + benignF1) / 2;

    // Overall accuracy
    const overallAccuracy = (totalTP + totalTN) / (corpus.length || 1);

    const discMetrics = calculateMetrics(stageResults.discovery);
    const argsMetrics = calculateMetrics(stageResults.call_arguments);
    const respMetrics = calculateMetrics(stageResults.call_response);

    const usage = adapter.tracker.getReport();

    console.log('\n========================================================================');
    console.log('   VEYLITH PHASE 2A — FIXED INTERNAL VALIDATION FIXTURE REPORT          ');
    console.log('========================================================================');
    console.log(
      `Dataset: Phase 2A fixed internal validation fixture (68 curated samples: 32 malicious, 36 benign)`,
    );
    console.log(
      `Note: Distinct from Phase 1 corpus but publicly present in repository (not a blind holdout).`,
    );
    console.log(`Evaluation Mode: Hybrid 3-tier Pipeline (Deterministic + Heuristic + Mock Muse)`);
    console.log('------------------------------------------------------------------------');
    console.log('STAGE 1: DISCOVERY (tools/list) CONFUSION MATRIX:');
    console.log(
      `  TP: ${stageResults.discovery.tp} | FP: ${stageResults.discovery.fp} | TN: ${stageResults.discovery.tn} | FN: ${stageResults.discovery.fn}`,
    );
    console.log(
      `  Precision: ${(discMetrics.precision * 100).toFixed(1)}% | Recall: ${(discMetrics.recall * 100).toFixed(1)}% | F1: ${(discMetrics.f1 * 100).toFixed(1)}%`,
    );
    console.log(
      `  Tier 1 Blocks: ${stageResults.discovery.deterministicCatches} | Tier 3 Calls: ${stageResults.discovery.tier3Evaluations}`,
    );
    console.log('------------------------------------------------------------------------');
    console.log('STAGE 2: CALL ARGUMENTS (tools/call) CONFUSION MATRIX:');
    console.log(
      `  TP: ${stageResults.call_arguments.tp} | FP: ${stageResults.call_arguments.fp} | TN: ${stageResults.call_arguments.tn} | FN: ${stageResults.call_arguments.fn}`,
    );
    console.log(
      `  Precision: ${(argsMetrics.precision * 100).toFixed(1)}% | Recall: ${(argsMetrics.recall * 100).toFixed(1)}% | F1: ${(argsMetrics.f1 * 100).toFixed(1)}%`,
    );
    console.log(
      `  Tier 1 Blocks: ${stageResults.call_arguments.deterministicCatches} | Tier 3 Calls: ${stageResults.call_arguments.tier3Evaluations}`,
    );
    console.log('------------------------------------------------------------------------');
    console.log('STAGE 3: CALL RESPONSE (tools/call outputs) CONFUSION MATRIX:');
    console.log(
      `  TP: ${stageResults.call_response.tp} | FP: ${stageResults.call_response.fp} | TN: ${stageResults.call_response.tn} | FN: ${stageResults.call_response.fn}`,
    );
    console.log(
      `  Precision: ${(respMetrics.precision * 100).toFixed(1)}% | Recall: ${(respMetrics.recall * 100).toFixed(1)}% | F1: ${(respMetrics.f1 * 100).toFixed(1)}%`,
    );
    console.log(
      `  Tier 1 Blocks: ${stageResults.call_response.deterministicCatches} | Tier 3 Calls: ${stageResults.call_response.tier3Evaluations}`,
    );
    console.log('------------------------------------------------------------------------');
    console.log('OVERALL CLASSIFICATION PERFORMANCE:');
    console.log(`  Total Evaluated        : ${corpus.length}`);
    console.log(`  True Positives (TP)    : ${totalTP} / 32 malicious`);
    console.log(`  True Negatives (TN)    : ${totalTN} / 36 benign`);
    console.log(`  False Positives (FP)   : ${totalFP}`);
    console.log(`  False Negatives (FN)   : ${totalFN}`);
    console.log('------------------------------------------------------------------------');
    console.log('CLASS-SPECIFIC METRICS:');
    console.log(`  Attack-Class Precision : ${(attackPrecision * 100).toFixed(1)}% (15/16)`);
    console.log(
      `  Attack-Class Recall    : ${(attackRecall * 100).toFixed(1)}% (15/32 sensitivity)`,
    );
    console.log(`  Attack-Class F1 Score  : ${(attackF1 * 100).toFixed(1)}%`);
    console.log(`  Benign-Class Precision : ${(benignPrecision * 100).toFixed(1)}% (35/52)`);
    console.log(
      `  Benign-Class Recall    : ${(benignRecall * 100).toFixed(1)}% (35/36 specificity)`,
    );
    console.log(`  Benign-Class F1 Score  : ${(benignF1 * 100).toFixed(1)}%`);
    console.log('------------------------------------------------------------------------');
    console.log('MACRO-AVERAGED METRICS:');
    console.log(`  Macro Precision        : ${(macroPrecision * 100).toFixed(1)}%`);
    console.log(`  Macro Recall (Bal Acc) : ${(macroRecall * 100).toFixed(1)}%`);
    console.log(`  Macro F1 Score         : ${(macroF1 * 100).toFixed(1)}%`);
    console.log(`  Overall Accuracy       : ${(overallAccuracy * 100).toFixed(1)}% (50/68)`);
    console.log('------------------------------------------------------------------------');
    console.log('LATENCY PROFILE:');
    console.log(
      `  Mean: ${meanLatency.toFixed(2)} ms | P50: ${p50.toFixed(2)} ms | P95: ${p95.toFixed(2)} ms | P99: ${p99.toFixed(2)} ms`,
    );
    console.log('------------------------------------------------------------------------');
    console.log('MOCK INFERENCE ACCOUNTING:');
    console.log(`  Inference Requests: ${usage.requestCount}`);
    console.log(
      `  Total Tokens      : ${usage.totalTokens} (Prompt: ${usage.promptTokens}, Cached: ${usage.cachedPromptTokens}, Completion: ${usage.completionTokens})`,
    );
    console.log(`  Estimated Spend   : $${usage.estimatedCostUsd.toFixed(6)} USD`);
    console.log(`  Live API Calls    : 0 (Zero paid inference during automated run)`);
    console.log('========================================================================\n');

    if (missedAttacks.length > 0) {
      console.log('HONEST ANALYSIS: Missed Attacks (False Negatives):');
      for (const m of missedAttacks) {
        console.log(`  - [${m.stage}] ${m.id} (${m.category})`);
      }
    }
    if (falsePositives.length > 0) {
      console.log('HONEST ANALYSIS: False Positives:');
      for (const fpItem of falsePositives) {
        console.log(`  - [${fpItem.stage}] ${fpItem.id} (${fpItem.category})`);
      }
    }

    // Verify evaluation executed across all holdout samples
    expect(corpus.length).toBe(68);
    expect(totalTP + totalTN + totalFP + totalFN).toBe(68);

    // Exact class-specific metric assertions
    expect(attackPrecision).toBeCloseTo(0.938, 2);
    expect(attackRecall).toBeCloseTo(0.469, 2);
    expect(attackF1).toBeCloseTo(0.625, 2);
    expect(benignPrecision).toBeCloseTo(0.673, 2);
    expect(benignRecall).toBeCloseTo(0.972, 2);
    expect(benignF1).toBeCloseTo(0.795, 2);

    // Exact macro-averaged metric assertions
    expect(macroPrecision).toBeCloseTo(0.805, 2);
    expect(macroRecall).toBeCloseTo(0.72, 2);
    expect(macroF1).toBeCloseTo(0.71, 2);

    // Exact overall accuracy assertion
    expect(overallAccuracy).toBeCloseTo(0.735, 2);
  });
});
