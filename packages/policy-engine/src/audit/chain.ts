/**
 * Tamper-Evident Local Audit Log Chain for Veylith Phase 2C.
 *
 * Implements:
 *   - Cryptographically linked audit records using SHA-256 hash chaining
 *   - Canonical deterministic serialization (sorted keys, stable JSON)
 *   - Zero credential / secret logging by default
 *   - Chain integrity verification & tamper detection (identifies exact modified record)
 *   - Documented limitation: Hash chaining guarantees local detection of alterations,
 *     insertions, and deletions; external anchoring is required to prevent full chain re-generation.
 */

import { createHash, randomUUID } from 'node:crypto';
import type { AuditRecord, InspectionStage, PolicyAction } from '@veylith/core';

export const GENESIS_HASH = '0'.repeat(64);

export interface CreateAuditRecordInput {
  readonly sessionId?: string;
  readonly serverId: string;
  readonly clientIdentity?: string;
  readonly mcpMethod: string;
  readonly targetName?: string;
  readonly stage: InspectionStage;
  readonly decision: PolicyAction;
  readonly reasonCode: string;
  readonly policyVersion: string;
  readonly modelId?: string;
  readonly latencyMs: number;
  readonly tokenUsage?: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
  };
}

export interface ChainVerificationResult {
  readonly valid: boolean;
  readonly totalRecords: number;
  readonly tamperedIndex?: number;
  readonly error?: string;
}

/**
 * Deterministically serializes an object with recursively sorted keys to guarantee
 * identical canonical JSON across platforms and Node versions.
 */
export function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return `[${obj.map(canonicalJson).join(',')}]`;
  }

  const entries = Object.entries(obj as Record<string, unknown>)
    .filter(([_, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/**
 * Computes the SHA-256 hash of an audit event given the previous hash and event payload.
 */
export function computeEventHash(
  previousHash: string,
  eventData: Omit<AuditRecord, 'currentEventHash'>,
): string {
  const serialized = canonicalJson(eventData);
  return createHash('sha256').update(`${previousHash}:${serialized}`).digest('hex');
}

export class AuditLogChain {
  private readonly records: AuditRecord[] = [];
  private lastHash: string = GENESIS_HASH;

  /**
   * Appends an event to the tamper-evident hash chain.
   */
  append(input: CreateAuditRecordInput): AuditRecord {
    const sequenceNumber = this.records.length;
    const eventId = `vyl-evt-${randomUUID()}`;
    const timestamp = new Date().toISOString();

    const recordData: Omit<AuditRecord, 'currentEventHash'> = {
      sequenceNumber,
      eventId,
      timestamp,
      sessionId: input.sessionId,
      serverId: input.serverId,
      clientIdentity: input.clientIdentity,
      mcpMethod: input.mcpMethod,
      targetName: input.targetName,
      stage: input.stage,
      decision: input.decision,
      reasonCode: input.reasonCode,
      policyVersion: input.policyVersion,
      modelId: input.modelId,
      latencyMs: input.latencyMs,
      tokenUsage: input.tokenUsage,
      previousEventHash: this.lastHash,
    };

    const currentEventHash = computeEventHash(this.lastHash, recordData);

    const fullRecord: AuditRecord = {
      ...recordData,
      currentEventHash,
    };

    this.records.push(fullRecord);
    this.lastHash = currentEventHash;

    return fullRecord;
  }

  /**
   * Returns a read-only snapshot of all records in the chain.
   */
  getRecords(): readonly AuditRecord[] {
    return [...this.records];
  }

  /**
   * Returns the latest hash in the chain.
   */
  getLatestHash(): string {
    return this.lastHash;
  }

  /**
   * Verifies the cryptographic integrity of the entire audit chain.
   */
  verifyChain(records: readonly AuditRecord[] = this.records): ChainVerificationResult {
    let expectedPreviousHash = GENESIS_HASH;

    for (let i = 0; i < records.length; i++) {
      const record = records[i]!;

      // 1. Check sequence number continuity
      if (record.sequenceNumber !== i) {
        return {
          valid: false,
          totalRecords: records.length,
          tamperedIndex: i,
          error: `Sequence number mismatch at index ${i}: expected ${i}, found ${record.sequenceNumber}`,
        };
      }

      // 2. Check previous hash continuity
      if (record.previousEventHash !== expectedPreviousHash) {
        return {
          valid: false,
          totalRecords: records.length,
          tamperedIndex: i,
          error: `Broken chain link at index ${i}: previousEventHash does not match expected hash`,
        };
      }

      // 3. Recompute and verify current hash
      const { currentEventHash, ...recordWithoutHash } = record;
      const recomputedHash = computeEventHash(expectedPreviousHash, recordWithoutHash);

      if (currentEventHash !== recomputedHash) {
        return {
          valid: false,
          totalRecords: records.length,
          tamperedIndex: i,
          error: `Hash mismatch at index ${i}: payload was modified after creation`,
        };
      }

      expectedPreviousHash = currentEventHash;
    }

    return {
      valid: true,
      totalRecords: records.length,
    };
  }

  /**
   * Resets the chain (for testing).
   */
  reset(): void {
    this.records.length = 0;
    this.lastHash = GENESIS_HASH;
  }
}
