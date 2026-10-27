/**
 * @veylith/core — Shared types for Veylith security decisions and gateway operations.
 *
 * This module is protocol-independent: it defines the vocabulary used across
 * the policy engine, gateway, and observability layers without importing the
 * MCP SDK directly.
 */

export type {
  SecurityDecision,
  PolicyVerdict,
  PolicyRule,
  PolicyEvaluationResult,
} from './decisions/index.js';
export type { GatewayRequest, GatewayResponse, RequestMeta } from './types/index.js';
export { VeylithError, PolicyBlockedError, UpstreamError, ConfigError } from './errors/index.js';
export type {
  InspectionStage,
  ThreatCategory,
  ToolCapability,
  PolicyAction,
  RiskEvidence,
  InspectionContext,
  SecurityInspectionInput,
  SecurityInspectionResult,
} from './inspection/index.js';
