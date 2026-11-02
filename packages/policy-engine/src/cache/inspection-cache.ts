/**
 * In-memory LRU / TTL Inspection Cache.
 *
 * Caches semantic inspection decisions to eliminate duplicate inference latency.
 * Keys are strictly scoped to:
 *   - SHA-256(payload)
 *   - stage (discovery | call_arguments | call_response)
 *   - policyVersion (invalidated on policy update)
 *   - modelVersion (invalidated on model change)
 *   - serverId (prevents cross-server verdict confusion)
 *   - clientId (prevents cross-client / cross-tenant privilege confusion)
 *   - toolName (prevents cross-tool verdict reuse)
 *
 * Safety Invariants:
 *   - Never caches transient fallback/outage verdicts.
 *   - Evicts expired entries proactively.
 *   - Strictly prevents cross-boundary verdict reuse.
 */

import { createHash } from 'node:crypto';
import type { SecurityInspectionResult } from '@veylith/core';

export interface CacheKeyScope {
  readonly payload: string;
  readonly sessionId?: string;
  readonly baselineRevision?: number;
  readonly stage: string;
  readonly policyVersion: string;
  readonly modelVersion: string;
  readonly serverId?: string;
  readonly clientId?: string;
  readonly toolName?: string;
}

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

  /**
   * Generate deterministic, cryptographically bound cache key.
   * Incorporates all security boundaries: policy, model, server, client, stage, and tool.
   */
  generateKey(scope: CacheKeyScope): string {
    const serverScope = scope.serverId?.trim() || 'default_upstream';
    const clientScope = scope.clientId?.trim() || 'anonymous';
    const toolScope = scope.toolName?.trim() || '*';
    const payloadHash = createHash('sha256').update(scope.payload).digest('hex');

    return JSON.stringify([
      scope.stage,
      scope.policyVersion,
      scope.modelVersion,
      serverScope,
      clientScope,
      scope.sessionId ?? '',
      scope.baselineRevision ?? 0,
      toolScope,
      payloadHash,
    ]);
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
    // SECURITY INVARIANT: Never cache transient fallback verdicts or unverified review states
    if (result.action === 'review' || result.explanation.toLowerCase().includes('outage')) {
      return;
    }

    // Proactively purge expired entries before capacity eviction
    if (this.cache.size >= this.maxEntries) {
      this.purgeExpired();
    }

    // If still at capacity, evict oldest entry (LRU)
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }

    this.cache.set(key, {
      result,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /** Actively evicts any expired entries. Returns count of evicted entries. */
  purgeExpired(): number {
    const now = Date.now();
    let evicted = 0;
    for (const [k, v] of this.cache.entries()) {
      if (now > v.expiresAt) {
        this.cache.delete(k);
        evicted++;
      }
    }
    return evicted;
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}
