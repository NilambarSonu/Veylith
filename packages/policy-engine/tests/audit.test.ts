import { describe, it, expect, beforeEach } from 'vitest';
import { AuditLogChain, GENESIS_HASH, canonicalJson } from '../src/audit/chain.js';

describe('AuditLogChain (Phase 2C)', () => {
  let auditChain: AuditLogChain;

  beforeEach(() => {
    auditChain = new AuditLogChain();
  });

  it('serializes canonical JSON with recursively sorted keys', () => {
    const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
    const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };

    expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    expect(canonicalJson(obj1)).toBe('{"a":2,"m":{"a":4,"b":3},"z":1}');
  });

  it('initializes with genesis hash and starts appending from sequence 0', () => {
    expect(auditChain.getLatestHash()).toBe(GENESIS_HASH);

    const record = auditChain.append({
      serverId: 'mcp-server-1',
      mcpMethod: 'tools/call',
      targetName: 'echo',
      stage: 'call_arguments',
      decision: 'allow',
      reasonCode: 'clean',
      policyVersion: 'v1.0.0',
      latencyMs: 1.2,
    });

    expect(record.sequenceNumber).toBe(0);
    expect(record.previousEventHash).toBe(GENESIS_HASH);
    expect(record.currentEventHash).toMatch(/^[0-9a-f]{64}$/);
    expect(auditChain.getLatestHash()).toBe(record.currentEventHash);
  });

  it('cryptographically links consecutive records in a hash chain', () => {
    const r1 = auditChain.append({
      serverId: 'server-1',
      mcpMethod: 'tools/list',
      stage: 'discovery',
      decision: 'allow',
      reasonCode: 'clean',
      policyVersion: 'v1.0.0',
      latencyMs: 0.5,
    });

    const r2 = auditChain.append({
      serverId: 'server-1',
      mcpMethod: 'tools/call',
      targetName: 'add',
      stage: 'call_arguments',
      decision: 'allow',
      reasonCode: 'clean',
      policyVersion: 'v1.0.0',
      latencyMs: 0.8,
    });

    expect(r2.previousEventHash).toBe(r1.currentEventHash);
    expect(r2.sequenceNumber).toBe(1);

    const verification = auditChain.verifyChain();
    expect(verification.valid).toBe(true);
    expect(verification.totalRecords).toBe(2);
  });

  it('detects tampering when an adversary modifies an audit payload (Criterion K)', () => {
    auditChain.append({
      serverId: 'server-1',
      mcpMethod: 'tools/call',
      targetName: 'rm_tool',
      stage: 'call_arguments',
      decision: 'block',
      reasonCode: 'destructive_command',
      policyVersion: 'v1.0.0',
      latencyMs: 0.4,
    });

    auditChain.append({
      serverId: 'server-1',
      mcpMethod: 'tools/call',
      targetName: 'echo',
      stage: 'call_arguments',
      decision: 'allow',
      reasonCode: 'clean',
      policyVersion: 'v1.0.0',
      latencyMs: 0.2,
    });

    const records = [...auditChain.getRecords()];
    // Adversary attempts to alter the block decision to allow at index 0
    (records[0] as unknown as { decision: string }).decision = 'allow';

    const verification = auditChain.verifyChain(records);
    expect(verification.valid).toBe(false);
    expect(verification.tamperedIndex).toBe(0);
    expect(verification.error).toContain('Hash mismatch at index 0');
  });

  it('detects sequence gap or dropped audit records', () => {
    for (let i = 0; i < 3; i++) {
      auditChain.append({
        serverId: 'server-1',
        mcpMethod: 'tools/call',
        targetName: `tool-${i}`,
        stage: 'call_arguments',
        decision: 'allow',
        reasonCode: 'clean',
        policyVersion: 'v1.0.0',
        latencyMs: 0.5,
      });
    }

    const records = [...auditChain.getRecords()];
    // Delete record 1
    records.splice(1, 1);

    const verification = auditChain.verifyChain(records);
    expect(verification.valid).toBe(false);
    expect(verification.tamperedIndex).toBe(1);
  });

  it('never stores raw secrets or API credentials in audit logs (Criterion L)', () => {
    const rawSecret = 'sk-live-secret-meta-api-token-xyz';
    auditChain.append({
      serverId: 'server-1',
      mcpMethod: 'tools/call',
      targetName: 'echo',
      stage: 'call_arguments',
      decision: 'block',
      reasonCode: 'credential_leak',
      policyVersion: 'v1.0.0',
      latencyMs: 1.0,
    });

    const serialized = JSON.stringify(auditChain.getRecords());
    expect(serialized).not.toContain(rawSecret);
  });
});
