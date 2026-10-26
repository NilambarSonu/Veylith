/**
 * Security inspection interfaces and types for Veylith Phase 1.
 *
 * Defines the core vocabulary for the multi-tier security inspection pipeline:
 * - Discovery inspection (tool metadata & schemas)
 * - Argument inspection (tools/call parameters)
 * - Response inspection (tools/call returned data)
 */

/** The operational stage of an MCP interaction. */
export type InspectionStage = 'discovery' | 'call_arguments' | 'call_response';

/** Classified threat categories detected by deterministic or semantic analysis. */
export type ThreatCategory =
  | 'tool_poisoning' // Hidden instructions or adversarial descriptions in tool metadata
  | 'suspicious_arguments' // Parameter tampering, unauthorized paths, destructive intents
  | 'malicious_response' // Indirect prompt injection in tool outputs
  | 'credential_leak' // Exposure of API keys, bearer tokens, or private secrets
  | 'destructive_command' // Shell execution, filesystem wipes, privilege escalation
  | 'none'; // Clean interaction

/** Enforcement action decided by the security engine. */
export type PolicyAction = 'allow' | 'block' | 'review';

/** Evidence supporting a threat detection. */
export interface RiskEvidence {
  /** Classifier or rule type that produced this evidence. */
  readonly type: string;
  /** Exact regex pattern or rule identifier matched, if applicable. */
  readonly matchedPattern?: string;
  /** Sanitized snippet of the offending content (never raw secret material). */
  readonly snippet: string;
  /** Field or location where the anomaly was found (e.g. 'description', 'args.command', 'content[0].text'). */
  readonly location: string;
}

/** Operational context for an inspection event. */
export interface InspectionContext {
  /** Gateway request/event correlation ID. */
  readonly requestId: string;
  /** Inspection stage. */
  readonly stage: InspectionStage;
  /** MCP method name (e.g. 'tools/list', 'tools/call'). */
  readonly method: string;
  /** Tool name involved, if applicable. */
  readonly toolName?: string;
  /** Client identity or IP, if available. */
  readonly clientIdentity?: string;
  /** Timestamp when the event entered inspection (ISO-8601). */
  readonly timestamp: string;
}

/** Input passed into the security inspection engine. */
export interface SecurityInspectionInput {
  readonly context: InspectionContext;
  readonly target: {
    readonly type: 'tool_metadata' | 'arguments' | 'response';
    readonly data: unknown;
  };
}

/** Complete outcome of a security inspection. */
export interface SecurityInspectionResult {
  /** Unique inspection result identifier. */
  readonly id: string;
  /** The stage evaluated. */
  readonly stage: InspectionStage;
  /** Policy decision: allow, block, or review. */
  readonly action: PolicyAction;
  /** Detected threat category. */
  readonly threatCategory: ThreatCategory;
  /** Sanitized evidence references. */
  readonly evidence: readonly RiskEvidence[];
  /** Human-readable explanation of the verdict. */
  readonly explanation: string;
  /** Deterministic rule ID, if matched. */
  readonly ruleId?: string;
  /** Model ID, if semantic inference was consulted. */
  readonly modelId?: string;
  /** Duration of the inspection in milliseconds. */
  readonly evaluationDurationMs: number;
  /** Token usage metadata if model inference was performed. */
  readonly tokenUsage?: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
  };
  /** Source of the verdict. */
  readonly origin: 'deterministic' | 'mock' | 'live' | 'cache';
  /**
   * Raw risk or confidence score (0.0 to 1.0) if applicable.
   * NOTE: LLM confidence is not a calibrated probability.
   */
  readonly confidence?: number;
  /** Whether this is a confirmed hard security violation (e.g., deterministic rule). */
  readonly isConfirmedViolation: boolean;
}
