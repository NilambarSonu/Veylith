import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifyManifest } from '../../scripts/security-lab/integrity.js';
import { metrics } from '../../scripts/security-lab/report.js';
import {
  AuditLogChain,
  InspectionCache,
  ClientSessionManager,
} from '../../packages/policy-engine/src/index.js';
import type { LabCase, Observation } from '../../scripts/security-lab/types.js';
const event = {
  serverId: 'local',
  stage: 'call_arguments' as const,
  mcpMethod: 'tools/call',
  decision: 'allow' as const,
  reasonCode: 'fixture',
  policyVersion: '2e',
  latencyMs: 0,
};
describe('Phase 2E evaluation integrity and development regressions', () => {
  it('verifies sealed byte hashes and per-case ground-truth hashes', () => {
    expect(verifyManifest().manifest.holdoutCount).toBe(56);
  });
  it('has exactly 14 principal scenarios and 112 unique offline variants', () => {
    const rows: LabCase[] = ['development', 'holdout'].flatMap((s) =>
      JSON.parse(readFileSync(`security-lab/v1/${s}.json`, 'utf8')),
    );
    expect(new Set(rows.map((r) => r.id)).size).toBe(112);
    expect(new Set(rows.map((r) => r.scenarioId)).size).toBe(14);
    expect(
      new Set(rows.map((r) => JSON.stringify([r.operation, r.input]))).size,
    ).toBeGreaterThanOrEqual(100);
    expect(
      rows.every(
        (r) => r.groundTruth && r.safetyConstraints.length && r.expectedEnforcementOutcome,
      ),
    ).toBe(true);
  });
  it('keeps operational outcomes out of classification counts and distinguishes enforcement', () => {
    const rows = [
      {
        expected: 'block',
        predicted: 'allow',
        category: 'malicious',
        enforcementSuccess: true,
        latencyMs: 1,
        isolationFailures: 0,
      },
      {
        expected: 'block',
        predicted: null,
        category: 'operational-failure',
        enforcementSuccess: false,
        latencyMs: 2,
        isolationFailures: 0,
      },
    ] as Observation[];
    const m = metrics(rows);
    expect(m.fn).toBe(1);
    expect(m.classificationSamples).toBe(1);
    expect(m.enforcementSuccessRate).toBe(0.5);
    expect(m.precision).toBeNull();
  });
  it('partitions verdict-cache keys by server, session, baseline and delimiter boundaries', () => {
    const cache = new InspectionCache();
    const base = {
      payload: 'same',
      stage: 'call_response',
      policyVersion: 'v1',
      modelVersion: 'mock',
      serverId: 'local',
      clientId: 'a',
      sessionId: 'one',
      baselineRevision: 1,
    };
    const keys = [
      cache.generateKey(base),
      cache.generateKey({ ...base, sessionId: 'two' }),
      cache.generateKey({ ...base, serverId: 'other' }),
      cache.generateKey({ ...base, baselineRevision: 2 }),
      cache.generateKey({ ...base, serverId: 'a:b', clientId: 'c' }),
      cache.generateKey({ ...base, serverId: 'a', clientId: 'b:c' }),
    ];
    expect(new Set(keys).size).toBe(keys.length);
  });
  it('rejects stale concurrent audit writers and closed durable sinks', () => {
    const dir = mkdtempSync(join(tmpdir(), 'veylith-2e-test-'));
    const file = join(dir, 'audit.jsonl');
    const a = new AuditLogChain({ storagePath: file }),
      b = new AuditLogChain({ storagePath: file });
    try {
      a.append(event);
      expect(() => b.append(event)).toThrow();
      a.close();
      expect(() => a.append(event)).toThrow();
      b.close();
      const restarted = new AuditLogChain({ storagePath: file });
      expect(restarted.verifyChain().valid).toBe(true);
      restarted.close();
    } finally {
      a.close();
      b.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('does not expand a custom session TTL to one hour on validation', () => {
    const manager = new ClientSessionManager();
    const s = manager.createSession({ clientIdentity: 'a', serverId: 'local', ttlMs: 100 });
    const result = manager.validateSession(s.sessionId);
    expect(result.session!.expiresAt - Date.now()).toBeLessThanOrEqual(100);
  });
  it('rejects a live evaluation without the explicit paid flag before requiring a key', () => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/security-lab/live.ts'], {
      encoding: 'utf8',
      env: { PATH: process.env['PATH'] },
    });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('--allow-paid');
  });
});
