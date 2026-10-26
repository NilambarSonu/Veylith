/**
 * In-memory LRU / TTL Inspection Cache.
 *
 * Caches semantic inspection decisions to eliminate duplicate inference latency.
 * Keys are scoped to: SHA-256(payload) + stage + policyVersion + modelVersion.
 * Ensures that changes in policy or model invalidate previous cache entries.
 */

import { createHash } from 'node:crypto';
import type { SecurityInspectionResult } from '@veylith/core';

export interface CacheEntry {
  readonly result: SecurityInspectionResult;
  readonly expiresAt: number;
}

export class InspectionCache {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    private readonly maxEntries = 500,
    private readonly ttlMs = 60000, // 1 minute default TTL
  ) {}

  /** Generate deterministic cache key. */
  generateKey(payload: string, stage: string, policyVersion: string, modelVersion: string): string {
    const hash = createHash('sha256').update(payload).digest('hex');
    return `${stage}:${policyVersion}:${modelVersion}:${hash}`;
  }

  get(key: string): SecurityInspectionResult | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Refresh position for LRU
    this.cache.delete(key);
    this.cache.set(key, entry);

    return {
      ...entry.result,
      origin: 'cache',
      evaluationDurationMs: 0.05,
    };
  }

  set(key: string, result: SecurityInspectionResult): void {
    if (this.cache.size >= this.maxEntries) {
      // Evict oldest entry (first key in iteration order)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }

    this.cache.set(key, {
      result,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}
