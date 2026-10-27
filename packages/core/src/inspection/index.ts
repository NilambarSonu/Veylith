/**
 * Security inspection interfaces and types for Veylith Phase 1.
 *
 * Defines the core vocabulary for the multi-tier security inspection pipeline:
 * - Discovery inspection (tool metadata & schemas)
 * - Argument inspection (tools/call parameters)
 * - Response inspection (tools/call returned data)
 */

/** The operational stage of an MCP interaction. */
export type InspectionStage =
  | 'discovery'
  | 'call_arguments'
  | 'call_response'
  | 'resource_discovery'
  | 'resource_content'
  | 'prompt_discovery'
  | 'prompt_messages';

/** Classified threat categories detected by deterministic or semantic analysis. */
export type ThreatCategory =
  | 'tool_poisoning' // Hidden instructions or adversarial descriptions in tool metadata
  | 'suspicious_arguments' // Parameter tampering, unauthorized paths, destructive intents
  | 'malicious_response' // Indirect prompt injection in tool outputs
  | 'credential_leak' // Exposure of API keys, bearer tokens, or private secrets
  | 'destructive_command' // Shell execution, filesystem wipes, privilege escalation
  | 'resource_poisoning' // Malicious content, prompt injection, or tampered metadata in resources
  | 'prompt_poisoning' // Adversarial instructions in prompt templates or prompt arguments
  | 'unauthorized_access' // Session violation, forbidden tool/resource/prompt invocation
  | 'uninspected_binary' // Uninspected binary payload requiring explicit policy clearance
  | 'none'; // Clean interaction

/** Explicit capability classifications for upstream MCP tools. */
export type ToolCapability =
  | 'PURE_OR_READ' // Pure functions, text transforms, read-only queries (e.g. echo, add, search_codebase)
  | 'SHELL_EXEC' // Operating system shell / terminal command execution (e.g. bash, exec_command)
  | 'FS_MUTATION' // Destructive or mutating filesystem operations (e.g. delete_file, write_file)
  | 'SQL_EXEC' // Database query and DDL/DML execution (e.g. execute_sql, query_db)
  | 'NETWORK_OUT' // Arbitrary outbound network or HTTP transmission (e.g. curl, fetch_url, webhook)
  | 'UNKNOWN'; // Unverified or untrusted tool capability (defaults to conservative enforcement)

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
  /** Trusted adapter-derived string leaves for exact read-only echo provenance; never from headers. */
  readonly clientArgumentText?: readonly string[];
  /** Gateway request/event correlation ID. */
  readonly requestId: string;
  /** Inspection stage. */
  readonly stage: InspectionStage;
  /** MCP method name (e.g. 'tools/list', 'tools/call', 'resources/read', 'prompts/get'). */
  readonly method: string;
  /** Session identifier, if established. */
  readonly sessionId?: string;
  /** Tool name involved, if applicable. */
  readonly toolName?: string;
  /** Resource URI involved, if applicable. */
  readonly resourceUri?: string;
  /** Prompt name involved, if applicable. */
  readonly promptName?: string;
  /** Client identity or IP, if available. */
  readonly clientIdentity?: string;
  /** Upstream server identity or URL, if available. */
  readonly serverId?: string;
  /** Verified capability classification for the tool, if known. */
  readonly capability?: ToolCapability;
  /** Timestamp when the event entered inspection (ISO-8601). */
  readonly timestamp: string;
}

/** Input passed into the security inspection engine. */
export interface SecurityInspectionInput {
  readonly context: InspectionContext;
  readonly target: {
    readonly type:
      | 'tool_metadata'
      | 'arguments'
      | 'response'
      | 'resource_metadata'
      | 'resource_content'
      | 'prompt_metadata'
      | 'prompt_messages';
    readonly data: unknown;
  };
}

/** Routing is provenance/coverage evidence, not an attack probability. */
export interface RoutingTrace {
  readonly decision:
    | 'verified_safe_fast_path'
    | 'needs_semantic_review'
    | 'deterministically_blocked'
    | 'unknown_or_uninspectable';
  readonly reason: string;
  readonly origin: 'client' | 'upstream' | 'trusted-local';
  readonly capability: ToolCapability;
  readonly inputBytes: number;
  readonly contextIncluded: boolean;
}

/** Complete outcome of a security inspection. */
export interface SecurityInspectionResult {
  readonly routing?: RoutingTrace;
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

/** Resource definition metadata input during resources/list. */
export interface ResourceMetadataInput {
  readonly uri: string;
  readonly name: string;
  readonly description?: string;
  readonly mimeType?: string;
}

/** Resource template metadata input during resources/templates/list. */
export interface ResourceTemplateInput {
  readonly uriTemplate: string;
  readonly name: string;
  readonly description?: string;
  readonly mimeType?: string;
}

/** Resource content item returned from resources/read. */
export interface ResourceContentItem {
  readonly uri: string;
  readonly mimeType?: string;
  readonly text?: string;
  readonly blob?: string;
}

/** Prompt definition metadata input during prompts/list. */
export interface PromptMetadataInput {
  readonly name: string;
  readonly description?: string;
  readonly arguments?: readonly {
    readonly name: string;
    readonly description?: string;
    readonly required?: boolean;
  }[];
}

/** Prompt message item returned from prompts/get. */
export interface PromptMessageItem {
  readonly role: 'user' | 'assistant';
  readonly content: {
    readonly type: string;
    readonly text?: string;
    readonly data?: string;
    readonly mimeType?: string;
  };
}

/** Client session representing authenticated/authorized local access state. */
export interface ClientSession {
  readonly sessionId: string;
  readonly clientIdentity: string;
  readonly serverId: string;
  readonly createdAt: number;
  readonly lastAccessedAt: number;
  readonly expiresAt: number;
  readonly permittedTools: readonly string[] | '*';
  readonly permittedResources: readonly string[] | '*';
  readonly permittedPrompts: readonly string[] | '*';
  readonly metadata?: Record<string, unknown>;
}

/** Tamper-evident local audit log record with hash chaining. */
export interface AuditRecord {
  readonly routing?: RoutingTrace;
  readonly sequenceNumber: number;
  readonly eventId: string;
  readonly timestamp: string;
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
  readonly previousEventHash: string;
  readonly currentEventHash: string;
}
