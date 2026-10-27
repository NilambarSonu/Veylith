/**
 * Meta Muse security adapter types and validation schemas.
 */

import * as z from 'zod/v4';
import type { ThreatCategory, PolicyAction } from '@veylith/core';

/** Supported operating modes for semantic analysis. */
export type MetaAiMode = 'mock' | 'live' | 'disabled';

/** Raw classification schema returned by the model or mock classifier. */
export const ModelClassificationSchema = z.object({
  flagged: z.boolean(),
  threatCategory: z.enum([
    'tool_poisoning',
    'suspicious_arguments',
    'malicious_response',
    'credential_leak',
    'destructive_command',
    'none',
  ]),
  action: z.enum(['allow', 'block', 'review']),
  confidence: z.number().min(0).max(1),
  explanation: z.string().min(1),
  evidence: z.array(z.string()).default([]),
});

export type ModelClassification = z.infer<typeof ModelClassificationSchema>;

/** Token usage breakdown. */
export interface TokenUsage {
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly cachedPromptTokens?: number;
  readonly reasoningTokens?: number;
}

/** Result of semantic inspection. */
export interface SemanticInspectionResult {
  readonly flagged: boolean;
  readonly threatCategory: ThreatCategory;
  readonly action: PolicyAction;
  readonly explanation: string;
  readonly confidence: number;
  readonly evidence: readonly string[];
  readonly rawScore?: number;
  readonly tokenUsage?: TokenUsage;
  readonly durationMs: number;
  readonly mode: MetaAiMode;
  readonly model: string;
}

/** Interface for Meta Muse Security Adapter. */
export interface MetaAdapter {
  readonly mode: MetaAiMode;
  readonly model: string;
  inspect(
    content: string,
    stage: 'discovery' | 'call_arguments' | 'call_response',
    metadata?: Record<string, unknown>,
  ): Promise<SemanticInspectionResult>;
}
