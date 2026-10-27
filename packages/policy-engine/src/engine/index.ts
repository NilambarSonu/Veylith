/**
 * Veylith Hybrid Security Inspection Engine (Phase 1).
 *
 * Coordinates:
 *   - Tier 1: Deterministic rules (hard invariants, sub-millisecond, unoverrideable)
 *   - Tier 2: Heuristic risk screener (triages clean vs ambiguous content)
 *   - Tier 3: Meta Muse semantic model (evaluates complex ambiguous prompts)
 *
 * Enforces policy decisions across:
 *   1. Discovery (tool descriptions & schemas in tools/list)
 *   2. Invocation arguments (tools/call parameters)
 *   3. Tool responses (tools/call returned data)
 */

import { randomUUID } from 'node:crypto';
import type {
  SecurityInspectionResult,
  InspectionContext,
  PolicyRule,
  ThreatCategory,
  PolicyAction,
} from '@veylith/core';
import type { MetaAdapter } from '@veylith/meta-adapter';
import { DeterministicRuleSet } from '../rules/deterministic.js';
import { HeuristicRiskScreener } from '../screener/heuristic.js';
import { InspectionCache } from '../cache/inspection-cache.js';
import { ToolCapabilityRegistry, type TrustedToolBinding } from '../capabilities/registry.js';

export interface SecurityEngineOptions {
  readonly policyVersion?: string;
  readonly failClosed?: boolean;
  readonly useCache?: boolean;
  readonly defaultDecision?: PolicyAction;
  readonly capabilityRegistry?: ToolCapabilityRegistry;
  readonly capabilityBindings?: readonly TrustedToolBinding[];
}

export interface ToolMetadataInput {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
}

export interface DiscoveryInspectionOutcome {
  readonly cleanTools: readonly ToolMetadataInput[];
  readonly blockedTools: readonly {
    readonly name: string;
    readonly reason: string;
    readonly threatCategory: ThreatCategory;
  }[];
  readonly results: readonly SecurityInspectionResult[];
}

export interface ResponseInspectionOutcome {
  readonly result: SecurityInspectionResult;
  readonly sanitizedContent: readonly { readonly type: string; readonly text?: string }[];
  readonly isRedacted: boolean;
}

export class SecurityInspectionEngine {
  private readonly deterministicRules = new DeterministicRuleSet();
  private readonly screener = new HeuristicRiskScreener();
  private readonly cache: InspectionCache;
  private readonly policyRules: readonly PolicyRule[];
  private readonly metaAdapter: MetaAdapter;
  private readonly policyVersion: string;
  private readonly failClosed: boolean;
  private readonly defaultDecision: PolicyAction;
  public readonly capabilityRegistry: ToolCapabilityRegistry;

  constructor(
    policyRules: readonly PolicyRule[] = [],
    metaAdapter: MetaAdapter,
    options?: SecurityEngineOptions,
  ) {
    this.policyRules = policyRules;
    this.metaAdapter = metaAdapter;
    this.policyVersion = options?.policyVersion ?? 'v1.0.0';
    this.failClosed = options?.failClosed ?? false;
    this.defaultDecision = options?.defaultDecision ?? 'allow';
    this.cache = new InspectionCache(500, 60000);
    this.capabilityRegistry =
      options?.capabilityRegistry ?? new ToolCapabilityRegistry(options?.capabilityBindings ?? []);
  }

  /**
   * 1. Inspect tool metadata during tools/list discovery.
   * Identifies tool-description poisoning, dynamic schema mutations, and static blocks.
   */
  async inspectDiscovery(
    tools: readonly ToolMetadataInput[],
    clientOrContext?: string | { readonly serverId?: string; readonly clientIdentity?: string },
  ): Promise<DiscoveryInspectionOutcome> {
    const serverId = typeof clientOrContext === 'object' ? clientOrContext.serverId : undefined;
    const clientIdentity =
      typeof clientOrContext === 'string' ? clientOrContext : clientOrContext?.clientIdentity;
    const cleanTools: ToolMetadataInput[] = [];
    const blockedTools: { name: string; reason: string; threatCategory: ThreatCategory }[] = [];
    const results: SecurityInspectionResult[] = [];

    for (const tool of tools) {
      // Check if tool name is explicitly blocked by configured deterministic rules
      const staticRule = this.policyRules.find(
        (r) =>
          r.enabled &&
          (r.method === '*' || r.method === 'tools/list') &&
          (r.toolName === tool.name || r.toolName === '*') &&
          r.decision === 'block',
      );

      if (staticRule) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'none',
          evidence: [{ type: 'static_rule', snippet: tool.name, location: 'toolName' }],
          explanation: `Tool '${tool.name}' blocked by static policy rule '${staticRule.id}'`,
          ruleId: staticRule.id,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({ name: tool.name, reason: res.explanation, threatCategory: 'none' });
        continue;
      }

      // Check for dynamic definition mutations (schema/description tampering after registration)
      const trackResult = this.capabilityRegistry.trackDefinition(serverId, tool);
      if (trackResult.mutated) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'tool_poisoning',
          evidence: [
            {
              type: 'definition_mutation',
              snippet: `Hash changed from ${trackResult.previousHash?.slice(0, 12)} to ${trackResult.currentHash.slice(0, 12)}`,
              location: 'tool_metadata',
            },
          ],
          explanation: `Tool definition mutated: Description or schema for tool '${tool.name}' was modified after initial registration. Quarantined to prevent dynamic prompt injection or unauthorized capability expansion.`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: 'tool_poisoning',
        });
        continue;
      }

      // Tier 1 & 2: Screen description and schema
      const inspectTarget = `${tool.name} ${tool.description ?? ''} ${JSON.stringify(tool.inputSchema ?? {})}`;
      const screenVerdict = this.screener.screen(inspectTarget, 'discovery');

      if (screenVerdict.type === 'hard_violation') {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: screenVerdict.match.location || 'description',
            },
          ],
          explanation: `Tool description poisoning detected: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: 0.2,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: res.threatCategory,
        });
        continue;
      }

      if (screenVerdict.type === 'clean') {
        // Fast path: clean
        cleanTools.push(tool);
        results.push({
          id: randomUUID(),
          stage: 'discovery',
          action: 'allow',
          threatCategory: 'none',
          evidence: [],
          explanation: 'Tool metadata verified clean by deterministic screener',
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: false,
        });
        continue;
      }

      // Ambiguous -> Tier 3: Meta Muse Semantic Inspection
      const cacheKey = this.cache.generateKey({
        payload: inspectTarget,
        stage: 'discovery',
        policyVersion: this.policyVersion,
        modelVersion: this.metaAdapter.model,
        clientId: clientIdentity,
        toolName: tool.name,
      });
      const cached = this.cache.get(cacheKey);

      if (cached) {
        results.push(cached);
        if (cached.action === 'block') {
          blockedTools.push({
            name: tool.name,
            reason: cached.explanation,
            threatCategory: cached.threatCategory,
          });
        } else {
          cleanTools.push(tool);
        }
        continue;
      }

      const modelResult = await this.metaAdapter.inspect(inspectTarget, 'discovery', {
        toolName: tool.name,
      });

      let finalAction: PolicyAction = modelResult.flagged
        ? modelResult.action
        : this.defaultDecision;
      let finalExplanation = modelResult.explanation;

      // Fail-open security audit: High-risk unverified operations MUST NOT pass when AI provider fails
      if (
        modelResult.action === 'review' &&
        screenVerdict.type === 'ambiguous' &&
        screenVerdict.riskLevel === 'high'
      ) {
        finalAction = 'block';
        finalExplanation = `High-risk tool discovery quarantined: Security classifier unavailable while metadata exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
      }

      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'discovery',
        action: finalAction,
        threatCategory:
          finalAction === 'block' && modelResult.threatCategory === 'none'
            ? 'tool_poisoning'
            : modelResult.threatCategory,
        evidence: modelResult.evidence.map((ev) => ({
          type: 'semantic_inference',
          snippet: ev,
          location: 'tool_metadata',
        })),
        explanation: finalExplanation,
        modelId: this.metaAdapter.model,
        evaluationDurationMs: modelResult.durationMs,
        tokenUsage: modelResult.tokenUsage,
        origin: modelResult.mode === 'mock' ? 'mock' : 'live',
        confidence: modelResult.confidence,
        isConfirmedViolation: modelResult.flagged && modelResult.action === 'block',
      };

      this.cache.set(cacheKey, res);
      results.push(res);

      if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: res.threatCategory,
        });
      } else {
        cleanTools.push(tool);
      }
    }

    return { cleanTools, blockedTools, results };
  }

  /**
   * 2. Inspect invocation arguments during tools/call.
   */
  async inspectArguments(
    ctx: InspectionContext,
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<SecurityInspectionResult> {
    const start = performance.now();

    // Check static policy rules (e.g. BLOCKED_TOOLS)
    const staticRule = this.policyRules.find(
      (r) => r.enabled && (r.toolName === toolName || r.toolName === '*') && r.decision === 'block',
    );

    if (staticRule) {
      return {
        id: randomUUID(),
        stage: 'call_arguments',
        action: 'block',
        threatCategory: 'none',
        evidence: [{ type: 'static_rule', snippet: toolName, location: 'toolName' }],
        explanation: `Veylith policy blocked this call: Matched rule '${staticRule.id}': ${staticRule.description}`,
        ruleId: staticRule.id,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };
    }

    // Resolve tool capability from context or trusted registry
    const capability =
      ctx.capability ?? this.capabilityRegistry.resolveCapability(ctx.serverId, toolName);

    // Tier 1 & 2: Screen arguments (capability-aware)
    const screenVerdict = this.screener.screen(args, {
      stage: 'call_arguments',
      capability,
      toolName,
      serverId: ctx.serverId,
    });

    if (screenVerdict.type === 'hard_violation') {
      return {
        id: randomUUID(),
        stage: 'call_arguments',
        action: 'block',
        threatCategory: screenVerdict.match.threatCategory,
        evidence: [
          {
            type: 'deterministic_rule',
            matchedPattern: screenVerdict.match.matchedPattern,
            snippet: screenVerdict.match.snippet,
            location: screenVerdict.match.location,
          },
        ],
        explanation: `Dangerous arguments blocked: ${screenVerdict.match.description}`,
        ruleId: screenVerdict.match.ruleId,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };
    }

    if (screenVerdict.type === 'clean') {
      return {
        id: randomUUID(),
        stage: 'call_arguments',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Arguments screened clean by deterministic rules',
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
    }

    // Tier 3: Ambiguous arguments -> Semantic model check
    const serializedArgs = JSON.stringify(args);
    const cacheKey = this.cache.generateKey({
      payload: serializedArgs,
      stage: 'call_arguments',
      policyVersion: this.policyVersion,
      modelVersion: this.metaAdapter.model,
      clientId: ctx.clientIdentity,
      toolName,
    });
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const modelResult = await this.metaAdapter.inspect(serializedArgs, 'call_arguments', {
      toolName,
    });

    let finalAction: PolicyAction = modelResult.flagged ? modelResult.action : this.defaultDecision;
    let finalExplanation = modelResult.explanation;

    // Fail-open security audit: High-risk unverified operations MUST NOT pass when AI provider fails
    if (
      modelResult.action === 'review' &&
      screenVerdict.type === 'ambiguous' &&
      screenVerdict.riskLevel === 'high'
    ) {
      finalAction = 'block';
      finalExplanation = `High-risk arguments quarantined: Security classifier unavailable while arguments exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
    }

    const res: SecurityInspectionResult = {
      id: randomUUID(),
      stage: 'call_arguments',
      action: finalAction,
      threatCategory:
        finalAction === 'block' && modelResult.threatCategory === 'none'
          ? 'suspicious_arguments'
          : modelResult.threatCategory,
      evidence: modelResult.evidence.map((ev) => ({
        type: 'semantic_inference',
        snippet: ev,
        location: 'args',
      })),
      explanation: finalExplanation,
      modelId: this.metaAdapter.model,
      evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
      tokenUsage: modelResult.tokenUsage,
      origin: modelResult.mode === 'mock' ? 'mock' : 'live',
      confidence: modelResult.confidence,
      isConfirmedViolation: modelResult.flagged && modelResult.action === 'block',
    };

    this.cache.set(cacheKey, res);
    return res;
  }

  /**
   * 3. Inspect tool response before returning downstream.
   * Intercepts indirect prompt injection in tool outputs and redacts if dangerous.
   */
  async inspectResponse(
    _ctx: InspectionContext,
    toolName: string,
    content: readonly { readonly type: string; readonly text?: string }[],
  ): Promise<ResponseInspectionOutcome> {
    const start = performance.now();

    const textPayload = content
      .filter((c) => c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text!)
      .join('\n');

    // Tier 1 & 2: Screen response
    const screenVerdict = this.screener.screen(textPayload, 'call_response');

    if (screenVerdict.type === 'hard_violation') {
      const result: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'call_response',
        action: 'block',
        threatCategory: screenVerdict.match.threatCategory,
        evidence: [
          {
            type: 'deterministic_rule',
            matchedPattern: screenVerdict.match.matchedPattern,
            snippet: screenVerdict.match.snippet,
            location: screenVerdict.match.location || 'response_body',
          },
        ],
        explanation: `Malicious response intercepted: ${screenVerdict.match.description}`,
        ruleId: screenVerdict.match.ruleId,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };

      // Sanitize the content to prevent agent hijacking
      const sanitizedContent = [
        {
          type: 'text',
          text: `[Veylith Security Notice]: Tool response from '${toolName}' contained potential prompt injection instructions and was redacted to protect the agent reasoning loop. Reason: ${screenVerdict.match.description}`,
        },
      ];

      return { result, sanitizedContent, isRedacted: true };
    }

    if (screenVerdict.type === 'clean') {
      const result: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'call_response',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Response content screened clean by deterministic rules',
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
      return { result, sanitizedContent: content, isRedacted: false };
    }

    // Tier 3: Ambiguous response -> Semantic model check
    const cacheKey = this.cache.generateKey({
      payload: textPayload,
      stage: 'call_response',
      policyVersion: this.policyVersion,
      modelVersion: this.metaAdapter.model,
      clientId: _ctx.clientIdentity,
      toolName,
    });
    const cached = this.cache.get(cacheKey);

    if (cached) {
      if (cached.action === 'block') {
        return {
          result: cached,
          sanitizedContent: [
            {
              type: 'text',
              text: `[Veylith Security Notice]: Tool response from '${toolName}' contained potential prompt injection instructions and was redacted. Reason: ${cached.explanation}`,
            },
          ],
          isRedacted: true,
        };
      }
      return { result: cached, sanitizedContent: content, isRedacted: false };
    }

    const modelResult = await this.metaAdapter.inspect(textPayload, 'call_response', {
      toolName,
    });

    let finalAction: PolicyAction = modelResult.flagged ? modelResult.action : this.defaultDecision;
    let finalExplanation = modelResult.explanation;

    // Fail-open security audit: High-risk unverified operations MUST NOT pass when AI provider fails
    if (
      modelResult.action === 'review' &&
      screenVerdict.type === 'ambiguous' &&
      screenVerdict.riskLevel === 'high'
    ) {
      finalAction = 'block';
      finalExplanation = `High-risk response quarantined: Security classifier unavailable while response exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
    }

    const result: SecurityInspectionResult = {
      id: randomUUID(),
      stage: 'call_response',
      action: finalAction,
      threatCategory:
        finalAction === 'block' && modelResult.threatCategory === 'none'
          ? 'malicious_response'
          : modelResult.threatCategory,
      evidence: modelResult.evidence.map((ev) => ({
        type: 'semantic_inference',
        snippet: ev,
        location: 'response_body',
      })),
      explanation: finalExplanation,
      modelId: this.metaAdapter.model,
      evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
      tokenUsage: modelResult.tokenUsage,
      origin: modelResult.mode === 'mock' ? 'mock' : 'live',
      confidence: modelResult.confidence,
      isConfirmedViolation: modelResult.flagged && modelResult.action === 'block',
    };

    this.cache.set(cacheKey, result);

    if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
      return {
        result,
        sanitizedContent: [
          {
            type: 'text',
            text: `[Veylith Security Notice]: Tool response from '${toolName}' was intercepted and redacted. Reason: ${finalExplanation}`,
          },
        ],
        isRedacted: true,
      };
    }

    return { result, sanitizedContent: content, isRedacted: false };
  }
}
