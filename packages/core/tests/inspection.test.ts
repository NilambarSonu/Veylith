import { describe, it, expect } from 'vitest';
import type { SecurityInspectionResult, InspectionContext } from '../src/index.js';

describe('Core Inspection Types', () => {
  it('constructs a valid SecurityInspectionResult', () => {
    const ctx: InspectionContext = {
      requestId: 'test-req-123',
      stage: 'call_arguments',
      method: 'tools/call',
      toolName: 'execute_query',
      timestamp: new Date().toISOString(),
    };

    const result: SecurityInspectionResult = {
      id: 'insp-001',
      stage: ctx.stage,
      action: 'block',
      threatCategory: 'destructive_command',
      evidence: [
        {
          type: 'deterministic_rule',
          matchedPattern: 'DROP TABLE',
          snippet: 'DROP TABLE users;',
          location: 'args.query',
        },
      ],
      explanation: 'Destructive SQL command detected in arguments',
      ruleId: 'rule-sql-destructive',
      evaluationDurationMs: 0.45,
      origin: 'deterministic',
      isConfirmedViolation: true,
    };

    expect(result.id).toBe('insp-001');
    expect(result.action).toBe('block');
    expect(result.threatCategory).toBe('destructive_command');
    expect(result.evidence).toHaveLength(1);
    expect(result.isConfirmedViolation).toBe(true);
  });
});
