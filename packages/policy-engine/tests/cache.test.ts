import { describe, it, expect, beforeEach } from 'vitest';
import { InspectionCache } from '../src/cache/inspection-cache.js';
import type { SecurityInspectionResult } from '@veylith/core';

describe('InspectionCache Audit', () => {
  let cache: InspectionCache;

  beforeEach(() => {
    cache = new InspectionCache(3, 50); // max 3 entries, 50ms TTL
  });

  const createDummyResult = (action: 'allow' | 'block' | 'review'): SecurityInspectionResult => ({
    id: 'test-id',
    stage: 'call_arguments',
    action,
    threatCategory: action === 'block' ? 'destructive_command' : 'none',
    evidence: [],
    explanation: `Verdict: ${action}`,
    evaluationDurationMs: 1.0,
    origin: 'deterministic',
    isConfirmedViolation: action === 'block',
  });

  it('generates strictly scoped cache keys across all security boundaries', () => {
    const baseScope = {
      payload: 'rm -rf /',
      stage: 'call_arguments',
      policyVersion: 'v1.0.0',
      modelVersion: 'muse-spark-1.3',
      serverId: 'server-1',
      clientId: 'client-alice',
      toolName: 'shell',
    };

    const baseKey = cache.generateKey(baseScope);

    // 1. Changing policy version changes key
    expect(cache.generateKey({ ...baseScope, policyVersion: 'v1.0.1' })).not.toBe(baseKey);

    // 2. Changing model version changes key
    expect(cache.generateKey({ ...baseScope, modelVersion: 'muse-spark-2.0' })).not.toBe(baseKey);

    // 3. Changing client identity changes key (cross-client protection)
    expect(cache.generateKey({ ...baseScope, clientId: 'client-bob' })).not.toBe(baseKey);

    // 4. Changing server identity changes key (cross-server protection)
    expect(cache.generateKey({ ...baseScope, serverId: 'server-2' })).not.toBe(baseKey);

    // 5. Changing tool name changes key
    expect(cache.generateKey({ ...baseScope, toolName: 'echo' })).not.toBe(baseKey);

    // 6. Changing stage changes key
    expect(cache.generateKey({ ...baseScope, stage: 'call_response' })).not.toBe(baseKey);

    // 7. Changing payload changes key
    expect(cache.generateKey({ ...baseScope, payload: 'ls -la' })).not.toBe(baseKey);
  });

  it('never caches transient review or outage verdicts', () => {
    const key = cache.generateKey({
      payload: 'ambiguous input',
      stage: 'call_arguments',
      policyVersion: 'v1.0.0',
      modelVersion: 'muse-spark-1.3',
    });

    // Attempt to cache a review/outage verdict
    const reviewResult = createDummyResult('review');
    cache.set(key, reviewResult);

    expect(cache.get(key)).toBeNull();
    expect(cache.size()).toBe(0);

    // Caching allow or block succeeds
    const blockResult = createDummyResult('block');
    cache.set(key, blockResult);
    expect(cache.get(key)).not.toBeNull();
    expect(cache.get(key)?.action).toBe('block');
    expect(cache.get(key)?.origin).toBe('cache');
  });

  it('handles TTL expiration and purges expired entries correctly', async () => {
    const key = cache.generateKey({
      payload: 'echo test',
      stage: 'call_arguments',
      policyVersion: 'v1.0.0',
      modelVersion: 'muse-spark-1.3',
    });

    cache.set(key, createDummyResult('allow'));
    expect(cache.get(key)).not.toBeNull();

    // Wait for TTL (50ms) to expire
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(cache.get(key)).toBeNull();
  });

  it('enforces capacity limit and evicts LRU entries', () => {
    const k1 = 'k1';
    const k2 = 'k2';
    const k3 = 'k3';
    const k4 = 'k4';

    cache.set(k1, createDummyResult('allow'));
    cache.set(k2, createDummyResult('allow'));
    cache.set(k3, createDummyResult('allow'));
    expect(cache.size()).toBe(3);

    // Access k1 to make it recently used
    cache.get(k1);

    // Adding k4 should evict k2 (oldest unaccessed entry)
    cache.set(k4, createDummyResult('allow'));
    expect(cache.size()).toBe(3);
    expect(cache.get(k1)).not.toBeNull();
    expect(cache.get(k2)).toBeNull(); // evicted
    expect(cache.get(k3)).not.toBeNull();
    expect(cache.get(k4)).not.toBeNull();
  });
});
