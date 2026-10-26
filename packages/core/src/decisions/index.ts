/**
 * Security decision types for the Veylith policy engine.
 *
 * A PolicyVerdict is the outcome of evaluating a request against all active
 * policy rules. The gateway uses this to decide whether to forward, block,
 * or flag a request for human review.
 */

/** The three possible policy outcomes. */
export type SecurityDecision = 'allow' | 'block' | 'review';

/** A single rule in the policy configuration. */
export interface PolicyRule {
  /** Unique identifier for this rule. */
  readonly id: string;
  /** Human-readable description. */
  readonly description: string;
  /** The MCP method this rule applies to, or '*' for all methods. */
  readonly method: string;
  /** Optional: specific tool name to match for tools/call requests. */
  readonly toolName?: string;
  /** The decision to apply when the rule matches. */
  readonly decision: SecurityDecision;
  /** Whether this rule is currently active. */
  readonly enabled: boolean;
}

/** The result of evaluating the policy engine against a single request. */
export interface PolicyEvaluationResult {
  /** The final decision. */
  readonly decision: SecurityDecision;
  /** The rule that produced the decision, or null if default-allow. */
  readonly matchedRule: PolicyRule | null;
  /** Human-readable reason for the decision. */
  readonly reason: string;
  /** Duration of policy evaluation in milliseconds. */
  readonly evaluationDurationMs: number;
}

/** Legacy alias — kept for downstream compatibility. */
export type PolicyVerdict = PolicyEvaluationResult;
