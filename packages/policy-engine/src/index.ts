/**
 * @veylith/policy-engine — Policy evaluation and security inspection engine.
 */

export { PolicyEvaluator, type EvaluationContext } from './evaluator/index.js';
export { DeterministicRuleSet, type RuleMatch, type ScanOptions } from './rules/deterministic.js';
export { HeuristicRiskScreener, type ScreenerVerdict } from './screener/heuristic.js';
export { InspectionCache } from './cache/inspection-cache.js';
export {
  ToolCapabilityRegistry,
  computeToolDefinitionHash,
  type TrustedToolBinding,
  type ToolDefinitionSnapshot,
  type ToolDefinitionInput,
  type DefinitionTrackingResult,
} from './capabilities/registry.js';
export {
  ClientSessionManager,
  DEFAULT_SESSION_TTL_MS,
  type CreateSessionOptions,
  type SessionRejectionReason,
  type SessionValidationResult,
} from './sessions/manager.js';
export {
  AuditLogChain,
  GENESIS_HASH,
  canonicalJson,
  computeEventHash,
  type CreateAuditRecordInput,
  type ChainVerificationResult,
} from './audit/chain.js';
export {
  SecurityInspectionEngine,
  type SecurityEngineOptions,
  type ToolMetadataInput,
  type DiscoveryInspectionOutcome,
  type ResponseInspectionOutcome,
  type ResourceDiscoveryOutcome,
  type ResourceContentOutcome,
  type PromptDiscoveryOutcome,
  type PromptMessagesOutcome,
} from './engine/index.js';
