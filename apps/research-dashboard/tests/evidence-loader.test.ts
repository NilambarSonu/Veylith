import { describe, it, expect } from 'vitest';
import { EvidenceLoader } from '../src/server/evidence-loader.js';
import { loadDashboardConfig } from '../src/server/config.js';

describe('Veylith Research Dashboard — Evidence Loader & Schema Verification', () => {
  const config = loadDashboardConfig();
  const loader = new EvidenceLoader(config);

  it('loads the 14 principal security scenarios across 5 difficulty tiers', () => {
    const scenarios = loader.getScenarios();
    expect(scenarios).toHaveLength(14);

    const ids = scenarios.map((s) => s.id);
    expect(ids).toEqual([
      'E1',
      'E2',
      'M1',
      'M2',
      'M3',
      'H1',
      'H2',
      'H3',
      'X1',
      'X2',
      'X3',
      'G1',
      'G2',
      'G3',
    ]);

    const totalVariants = scenarios.reduce((sum, s) => sum + s.variants, 0);
    expect(totalVariants).toBe(112); // 14 * 8 variants

    const tiers = new Set(scenarios.map((s) => s.tier));
    expect(tiers).toEqual(new Set(['easy', 'medium', 'hard', 'extremely-hard', 'god-level']));
  });

  it('loads the dataset manifest and validates hashes and split counts', () => {
    const manifest = loader.getManifest();
    expect(manifest.version).toBe('2e-v1');
    expect(manifest.frozenBeforeEvaluation).toBe(true);
    expect(manifest.principalScenarios).toBe(14);
    expect(manifest.offlineVariants).toBe(112);
    expect(manifest.developmentCount).toBe(56);
    expect(manifest.holdoutCount).toBe(56);
    expect(manifest.liveReservedCount).toBe(6);
    expect(manifest.files['holdout.json']).toBeDefined();
    expect(manifest.files['live-reserve.json']).toBeDefined();
  });

  it('loads the 6 reserved live candidates with reservedUnseen=true', () => {
    const liveReserve = loader.getLiveCandidates();
    expect(liveReserve).toHaveLength(6);

    for (const candidate of liveReserve) {
      expect(candidate.id).toMatch(/^VEY-2E-LIVE-0[1-6]$/);
      expect(candidate.reservedUnseen).toBe(true);
      expect(['allow', 'block']).toContain(candidate.expectedSecurityDecision);
    }
  });

  it('loads Phase 2F Development Comparison and validates deterministic-only 100% FPR and mock recall', () => {
    const devComparison = loader.getPhase2fDevelopmentComparison();
    expect(devComparison.afterRuns).toBeDefined();

    const detRun = devComparison.afterRuns.find((r) => r.mode === 'deterministic-only');
    expect(detRun).toBeDefined();
    // Deterministic-only blocked all 20 benign cases (100% FPR, 100% Recall)
    expect(detRun!.metrics.tp).toBe(48);
    expect(detRun!.metrics.tn).toBe(0);
    expect(detRun!.metrics.fp).toBe(20);
    expect(detRun!.metrics.fn).toBe(0);
    expect(detRun!.metrics.recall).toBe(1);
    expect(detRun!.metrics.falsePositiveRate).toBe(1);
    expect(detRun!.metrics.accuracy).toBeCloseTo(0.706, 2);

    const mockRun = devComparison.afterRuns.find((r) => r.mode === 'mock-semantic');
    expect(mockRun).toBeDefined();
    // Mock-semantic recall was 52.1% (25 TP out of 48)
    expect(mockRun!.metrics.tp).toBe(25);
    expect(mockRun!.metrics.tn).toBe(20);
    expect(mockRun!.metrics.fp).toBe(0);
    expect(mockRun!.metrics.fn).toBe(23);
    expect(mockRun!.metrics.recall).toBeCloseTo(0.521, 2);
    expect(mockRun!.metrics.accuracy).toBeCloseTo(0.662, 2);
  });

  it('strictly isolates Phase 2E frozen holdout runs from Phase 2F dev runs', () => {
    const holdoutRuns = loader.getPhase2eHoldoutRuns();
    expect(holdoutRuns.length).toBeGreaterThanOrEqual(3);

    for (const r of holdoutRuns) {
      expect(r.split).toBe('holdout');
      expect(r.metrics.samples).toBe(56);
    }

    const detHoldout = holdoutRuns.find((r) => r.mode === 'deterministic-only');
    expect(detHoldout!.metrics.tp).toBe(18);
    expect(detHoldout!.metrics.tn).toBe(21);
    expect(detHoldout!.metrics.fn).toBe(11);
    expect(detHoldout!.metrics.fp).toBe(0);
  });

  it('loads inherited reliability probes and verifies 13 passed and 2 failed', () => {
    const rel = loader.getReliabilityProbes();
    expect(rel.totalCount).toBe(15);
    expect(rel.passedCount).toBe(13);
    expect(rel.failedCount).toBe(2);

    const failedProbes = rel.probes.filter((p) => !p.passed);
    expect(failedProbes).toHaveLength(2);
    expect(failedProbes[0]!.name).toContain(
      'slow response consumer drains a large harmless response',
    );
    expect(failedProbes[1]!.name).toContain('six full MCP load and cleanup cycles');
  });

  it('loads audit records from evidence files with pagination and filtering', () => {
    const res = loader.getAuditRecords({
      source: 'phase-2f-mock-semantic',
      limit: 10,
      page: 1,
    });

    expect(res.records.length).toBeGreaterThan(0);
    expect(res.records.length).toBeLessThanOrEqual(10);
    expect(res.total).toBeGreaterThan(0);
    expect(res.chainVerified).toBe(true);
    expect(res.chainVerification).toBeDefined();
    expect(res.chainVerification.totalChainsEvaluated).toBe(72);
    expect(res.chainVerification.validChains).toBe(72);

    const first = res.records[0]!;
    expect(first.sequenceNumber).toBeDefined();
    expect(first.currentEventHash).toBeDefined();
    expect(first.previousEventHash).toBeDefined();
    expect(first.caseId).toBeDefined();
  });

  describe('Cryptographic SHA-256 Audit Chain Verification', () => {
    it('guarantees public getCaseAuditTrail always redacts session IDs and sensitive fields', () => {
      const publicRecords = loader.getCaseAuditTrail('VEY-2E-E1-01');
      expect(publicRecords.length).toBeGreaterThan(0);
      for (const rec of publicRecords) {
        if (rec.sessionId) {
          expect(rec.sessionId).toContain('***');
        }
      }
    });

    it('cryptographically verifies valid in-memory audit chains using internal raw access', () => {
      // Get the continuous chronological audit trail for the first case (VEY-2E-E1-01) with raw data strictly for verification
      const caseRecords = loader.getRawCaseAuditTrailForVerification('VEY-2E-E1-01');
      expect(caseRecords.length).toBeGreaterThan(0);
      expect(caseRecords[0]!.sequenceNumber).toBe(0);

      const check = loader.verifyAuditChain(caseRecords);
      expect(check.valid).toBe(true);
      expect(check.totalRecords).toBe(caseRecords.length);
    });

    it('cryptographically detects tampered audit event payload', () => {
      const caseRecords = loader.getRawCaseAuditTrailForVerification('VEY-2E-E1-01');

      // Clone and tamper with payload
      const tampered = structuredClone(caseRecords);
      tampered[0]!.decision = 'block'; // modify decision payload without recomputing hash

      const check = loader.verifyAuditChain(tampered);
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(0);
      expect(check.error).toContain('Hash mismatch');
    });

    it('cryptographically detects broken previousEventHash link', () => {
      const caseRecords = loader.getRawCaseAuditTrailForVerification('VEY-2E-E1-01');
      expect(caseRecords.length).toBeGreaterThanOrEqual(2);

      const broken = structuredClone(caseRecords);
      broken[1]!.previousEventHash = '1'.repeat(64);

      const check = loader.verifyAuditChain(broken);
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(1);
      expect(check.error).toContain('Broken chain link');
    });

    it('cryptographically detects skipped sequence numbers', () => {
      const caseRecords = loader.getRawCaseAuditTrailForVerification('VEY-2E-E1-01');
      expect(caseRecords.length).toBeGreaterThanOrEqual(2);

      const skipped = structuredClone(caseRecords);
      skipped[1]!.sequenceNumber = 999;

      const check = loader.verifyAuditChain(skipped);
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(1);
      expect(check.error).toContain('Sequence number mismatch');
    });
  });

  it('loads Phase 2A fixed internal validation fixture data with exact class and macro metrics', () => {
    const p2a = loader.getPhase2aValidationData();
    expect(p2a.totalSamples).toBe(68);
    expect(p2a.fixturePath).toBe('tests/fixtures/holdout-corpus.json');
    expect(p2a.confusionMatrix.tp).toBe(15);
    expect(p2a.confusionMatrix.tn).toBe(35);
    expect(p2a.confusionMatrix.fp).toBe(1);
    expect(p2a.confusionMatrix.fn).toBe(17);
    expect(p2a.classSpecificMetrics.attackPrecision).toBeCloseTo(0.938, 2);
    expect(p2a.classSpecificMetrics.attackRecall).toBeCloseTo(0.469, 2);
    expect(p2a.classSpecificMetrics.attackF1).toBeCloseTo(0.625, 2);
    expect(p2a.classSpecificMetrics.benignPrecision).toBeCloseTo(0.673, 2);
    expect(p2a.classSpecificMetrics.benignRecall).toBeCloseTo(0.972, 2);
    expect(p2a.classSpecificMetrics.benignF1).toBeCloseTo(0.795, 2);
    expect(p2a.macroMetrics.macroPrecision).toBeCloseTo(0.805, 2);
    expect(p2a.macroMetrics.macroRecall).toBeCloseTo(0.72, 2);
    expect(p2a.macroMetrics.macroF1).toBeCloseTo(0.71, 2);
    expect(p2a.macroMetrics.overallAccuracy).toBeCloseTo(0.735, 2);
  });

  it('loads the 8 documented unresolved security findings', () => {
    const findings = loader.getSecurityFindings();
    expect(findings).toHaveLength(8);

    const ids = findings.map((f) => f.id);
    expect(ids).toEqual([
      'FINDING-01',
      'FINDING-02',
      'FINDING-03',
      'FINDING-04',
      'FINDING-05',
      'FINDING-06',
      'FINDING-07',
      'FINDING-08',
    ]);

    expect(findings[0]!.title).toContain('Real Muse Detection Quality Untested');
    expect(findings[2]!.title).toContain('Production Authentication Not Implemented');
    expect(findings[4]!.title).toContain('External Audit Log Anchoring Absent');
    expect(findings[5]!.title).toContain('Two Inherited Reliability Probes Unresolved');
  });
});
