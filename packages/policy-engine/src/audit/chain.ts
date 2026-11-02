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
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditRecord, InspectionStage, PolicyAction, RoutingTrace } from '@veylith/core';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditCheckpoint {
  readonly nextSequenceNumber: number;
  readonly previousEventHash: string;
}
export interface AuditLogChainOptions {
  /** Bounded in-memory tail; full persistent history is not silently deleted. */
  readonly maxRetainedRecords?: number;
  /** Fail closed at capacity; operator must archive/rotate and retain checkpoints. */
  readonly maxStorageBytes?: number;
  /** Optional file path for append-only JSONL persistence */
  readonly storagePath?: string;
  /** File mode permissions for local audit file (default: 0o600 - owner read/write only) */
  readonly fileMode?: number;
}

export interface CreateAuditRecordInput {
  readonly routing?: RoutingTrace;
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
  private totalRecords = 0;
  private retainedCheckpoint: AuditCheckpoint = {
    nextSequenceNumber: 0,
    previousEventHash: GENESIS_HASH,
  };
  private readonly maxRetainedRecords: number;
  private readonly maxStorageBytes: number;
  private lastHash: string = GENESIS_HASH;
  private readonly storagePath?: string;
  private readonly fileMode: number;
  private fileFd?: number;
  private persistedBytes = 0;
  private persistenceFailed = false;

  constructor(options?: AuditLogChainOptions) {
    this.maxRetainedRecords = options?.maxRetainedRecords ?? 2048;
    this.maxStorageBytes = options?.maxStorageBytes ?? 64 * 1024 * 1024;
    if (
      !Number.isInteger(this.maxRetainedRecords) ||
      this.maxRetainedRecords < 1 ||
      this.maxRetainedRecords > 100000
    )
      throw new Error('Invalid audit memory retention bound');
    if (!Number.isSafeInteger(this.maxStorageBytes) || this.maxStorageBytes < 1024)
      throw new Error('Invalid audit storage bound');
    this.storagePath = options?.storagePath;
    this.fileMode = options?.fileMode ?? 0o600;

    if (this.storagePath) {
      this.initPersistence();
    }
  }

  private initPersistence(): void {
    if (!this.storagePath) return;

    const dir = path.dirname(this.storagePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    if (fs.existsSync(this.storagePath)) {
      const fd = fs.openSync(this.storagePath, 'r');
      try {
        if (fs.fstatSync(fd).size > this.maxStorageBytes)
          throw new Error('Audit storage exceeds configured capacity');
        const buffer = Buffer.alloc(65536);
        let pending = Buffer.alloc(0);
        let lineNumber = 0;
        while (true) {
          const count = fs.readSync(fd, buffer, 0, buffer.length, null);
          if (!count) break;
          pending = Buffer.concat([pending, buffer.subarray(0, count)]);
          let end: number;
          while ((end = pending.indexOf(10)) >= 0) {
            if (end > 65536) throw new Error('Audit record exceeds bounded line length');
            const line = pending.subarray(0, end).toString('utf8');
            pending = pending.subarray(end + 1);
            lineNumber++;
            if (!line.trim()) continue;
            let record: AuditRecord;
            try {
              record = JSON.parse(line) as AuditRecord;
            } catch {
              throw new Error(`Audit log file corruption: invalid JSON at line ${lineNumber}`);
            }
            const check = this.verifyChain([record], {
              nextSequenceNumber: this.totalRecords,
              previousEventHash: this.lastHash,
            });
            if (!check.valid)
              throw new Error(
                `Audit log file integrity violation at record ${this.totalRecords}: ${check.error}`,
              );
            this.retain(record);
            this.lastHash = record.currentEventHash;
            this.totalRecords++;
          }
          if (pending.length > 65536) throw new Error('Audit record exceeds bounded line length');
        }
        if (pending.toString('utf8').trim())
          throw new Error('Audit log file corruption: incomplete final JSONL line');
      } finally {
        fs.closeSync(fd);
      }
    }

    this.fileFd = fs.openSync(this.storagePath, 'a', this.fileMode);
    this.persistedBytes = fs.fstatSync(this.fileFd).size;
  }

  /**
   * Appends an event to the tamper-evident hash chain and persists it if configured.
   */
  append(input: CreateAuditRecordInput): AuditRecord {
    const sequenceNumber = this.totalRecords;
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
      routing: input.routing,
      previousEventHash: this.lastHash,
    };

    const currentEventHash = computeEventHash(this.lastHash, recordData);

    const fullRecord: AuditRecord = {
      ...recordData,
      currentEventHash,
    };

    const bytes = Buffer.from(`${canonicalJson(fullRecord)}\n`);
    if (bytes.length > 65536) throw new Error('Audit record exceeds bounded line length');

    // A failed or closed persistent sink must never silently turn into memory-only audit.
    if (this.storagePath && (this.fileFd === undefined || this.persistenceFailed)) {
      throw new Error('Persistent audit unavailable; restart and verify the log before recovery');
    }
    if (this.fileFd !== undefined && this.storagePath) {
      let lockFd: number | undefined;
      const lockPath = `${this.storagePath}.append.lock`;
      try {
        // Cooperating processes serialize appends. A stale writer must reload the chain.
        lockFd = fs.openSync(lockPath, 'wx', 0o600);
        if (fs.fstatSync(this.fileFd).size !== this.persistedBytes) {
          throw new Error('Audit log changed by another writer or was truncated; reload required');
        }
        if (this.persistedBytes + bytes.length > this.maxStorageBytes)
          throw new Error('Audit storage capacity reached; archive and rotate before recovery');
        let offset = 0;
        while (offset < bytes.length) {
          const written = fs.writeSync(this.fileFd, bytes, offset, bytes.length - offset);
          if (written <= 0) throw new Error('Incomplete audit write');
          offset += written;
        }
        fs.fsyncSync(this.fileFd);
        this.persistedBytes += bytes.length;
      } catch (error) {
        this.persistenceFailed = true;
        throw error;
      } finally {
        if (lockFd !== undefined) {
          fs.closeSync(lockFd);
          fs.unlinkSync(lockPath);
        }
      }
    }

    this.retain(fullRecord);
    this.totalRecords++;
    this.lastHash = currentEventHash;

    return fullRecord;
  }

  private retain(record: AuditRecord): void {
    this.records.push(record);
    if (this.records.length > this.maxRetainedRecords) {
      const removed = this.records.shift()!;
      this.retainedCheckpoint = {
        nextSequenceNumber: removed.sequenceNumber + 1,
        previousEventHash: removed.currentEventHash,
      };
    }
  }
  getRetentionState() {
    return {
      retainedRecords: this.records.length,
      totalRecords: this.totalRecords,
      maxRetainedRecords: this.maxRetainedRecords,
      maxStorageBytes: this.maxStorageBytes,
      checkpoint: { ...this.retainedCheckpoint },
      scope: 'in-memory-tail' as const,
      externallyAnchored: false,
    };
  }
  /**
   * Returns a read-only snapshot of all records in the chain.
   */
  getRecords(): readonly AuditRecord[] {
    return structuredClone(this.records);
  }

  /**
   * Returns the latest hash in the chain.
   */
  getLatestHash(): string {
    return this.lastHash;
  }

  /**
   * Flushes in-flight persistent writes to disk.
   */
  flush(): void {
    if (this.fileFd !== undefined) {
      fs.fsyncSync(this.fileFd);
    }
  }

  /**
   * Closes the underlying file descriptor if open.
   */
  close(): void {
    if (this.fileFd !== undefined) {
      fs.closeSync(this.fileFd);
      this.fileFd = undefined;
    }
  }

  /**
   * Verifies the cryptographic integrity of the entire audit chain.
   */
  verifyChain(
    records?: readonly AuditRecord[],
    checkpoint?: AuditCheckpoint,
  ): ChainVerificationResult {
    const start =
      checkpoint ??
      (records === undefined
        ? this.retainedCheckpoint
        : { nextSequenceNumber: 0, previousEventHash: GENESIS_HASH });
    records = records ?? this.records;
    let expectedPreviousHash = start.previousEventHash;

    for (let i = 0; i < records.length; i++) {
      const record = records[i]!;

      // 1. Check sequence number continuity
      if (record.sequenceNumber !== i + start.nextSequenceNumber) {
        return {
          valid: false,
          totalRecords: records.length,
          tamperedIndex: i,
          error: `Sequence number mismatch at index ${i}: expected ${i + start.nextSequenceNumber}, found ${record.sequenceNumber}`,
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
    this.persistenceFailed = false;
    this.persistedBytes = 0;
    this.records.length = 0;
    this.totalRecords = 0;
    this.retainedCheckpoint = { nextSequenceNumber: 0, previousEventHash: GENESIS_HASH };
    this.lastHash = GENESIS_HASH;
    if (this.fileFd !== undefined) {
      fs.closeSync(this.fileFd);
      this.fileFd = undefined;
    }
    if (this.storagePath && fs.existsSync(this.storagePath)) {
      fs.truncateSync(this.storagePath, 0);
      this.fileFd = fs.openSync(this.storagePath, 'a', this.fileMode);
    }
  }
}
